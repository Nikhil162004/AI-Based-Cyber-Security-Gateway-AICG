"""Tests for Flask API endpoints, static assets, runtime lifecycle, and simulation controls."""

from pathlib import Path
import pytest
from aegis_gateway.api import create_app
from aegis_gateway.config import Settings
from aegis_gateway.runtime import GatewayRuntime
from aegis_gateway.scenarios import generate_window


@pytest.fixture
def runtime_app(tmp_path: Path):
    settings = Settings(
        database_path=tmp_path / "test_api.sqlite3",
        report_dir=tmp_path / "reports",
        dataset_dir=tmp_path / "datasets",
    )
    runtime = GatewayRuntime(settings)
    app = create_app(runtime)
    return runtime, app


def test_api_health_and_status(runtime_app):
    runtime, app = runtime_app
    with app.test_client() as client:
        res = client.get("/api/health")
        assert res.status_code == 200
        data = res.get_json()
        assert data["ok"] is True
        assert data["status"] == "ONLINE"
        assert data["host_enforcement"] is False

        res_status = client.get("/api/status")
        assert res_status.status_code == 200
        status_data = res_status.get_json()
        assert "summary" in status_data
        assert "pipeline" in status_data


def test_api_static_assets_and_pages(runtime_app):
    runtime, app = runtime_app
    with app.test_client() as client:
        # Dashboard HTML
        res_root = client.get("/")
        assert res_root.status_code == 200
        assert b"AI EDGE SECURITY GATEWAY" in res_root.data

        # Attacker Page HTML
        res_atk = client.get("/attacker")
        assert res_atk.status_code == 200
        assert b"AEGIS-OT ATTACK SIMULATOR" in res_atk.data

        # Static CSS and JS
        res_css = client.get("/static/css/dashboard.css")
        assert res_css.status_code == 200
        assert len(res_css.data) > 1000

        res_js = client.get("/static/js/dashboard.js")
        assert res_js.status_code == 200
        assert len(res_js.data) > 1000


def test_api_telemetry_and_events(runtime_app):
    runtime, app = runtime_app
    # Ingest one normal and one attack window
    runtime.ingest(generate_window("normal", 1, 0))
    runtime.ingest(generate_window("udp_flood", 3, 0))

    with app.test_client() as client:
        res = client.get("/api/telemetry")
        assert res.status_code == 200
        data = res.get_json()
        assert len(data["rows"]) == 2
        first = data["rows"][0]
        assert "window_start" in first
        assert "packets_per_second" in first
        assert "identity_context" in first
        assert "lifecycle_context" in first
        assert "explainability_context" in first

        res_events = client.get("/api/events")
        assert res_events.status_code == 200
        events_data = res_events.get_json()
        assert events_data["count"] == 1
        assert events_data["events"][0]["prediction"] == "ATTACK"


def test_api_incidents_lifecycle(runtime_app):
    runtime, app = runtime_app
    runtime.ingest(generate_window("syn_flood", 3, 0))

    with app.test_client() as client:
        res = client.get("/api/incidents")
        assert res.status_code == 200
        data = res.get_json()
        assert data["count"] >= 1
        inc = data["incidents"][0]
        inc_id = inc["incident_id"]

        # Detail endpoint
        res_det = client.get(f"/api/incidents/{inc_id}")
        assert res_det.status_code == 200
        assert res_det.get_json()["incident_id"] == inc_id

        # Transition endpoint
        res_trans = client.post(f"/api/incidents/{inc_id}/transition", json={
            "state": "RECOVERING",
            "actor": "operator",
            "note": "Operator initiated recovery"
        })
        assert res_trans.status_code == 200
        assert res_trans.get_json()["lifecycle_state"] == "RECOVERING"

        # Action endpoint
        res_act = client.post(f"/api/incidents/{inc_id}/action", json={
            "action": "BLOCK",
            "actor": "operator"
        })
        assert res_act.status_code == 200
        assert res_act.get_json()["action"]["action"] == "BLOCK"


def test_api_manual_action_and_mode(runtime_app):
    runtime, app = runtime_app
    with app.test_client() as client:
        # Toggle mode to MANUAL
        res_mode = client.post("/api/settings/mode", json={"mode": "MANUAL", "auto": False})
        assert res_mode.status_code == 200
        assert res_mode.get_json()["auto"] is False

        # Execute manual action
        res_act = client.post("/api/manual/action", json={"action": "RATE_LIMIT", "actor": "operator"})
        assert res_act.status_code == 200
        assert res_act.get_json()["action"]["action"] == "RATE_LIMIT"


def test_api_demo_data_endpoint(runtime_app):
    runtime, app = runtime_app
    with app.test_client() as client:
        res = client.post("/api/demo-data")
        assert res.status_code == 200
        data = res.get_json()
        assert data["controlled"] is True
        assert data["offline_only"] is True
        assert data["prediction"] == "ATTACK"
        assert data["security_action"] in ("BLOCK", "RATE_LIMIT", "ISOLATE")


def test_api_scenarios_and_simulations(runtime_app):
    runtime, app = runtime_app
    with app.test_client() as client:
        res_sc = client.get("/api/scenarios")
        assert res_sc.status_code == 200
        assert len(res_sc.get_json()["scenarios"]) >= 10

        # Start simulation
        res_start = client.post("/api/simulations/start", json={
            "scenario_id": "normal",
            "intensity": 1,
            "duration": 5.0
        })
        assert res_start.status_code == 202
        assert res_start.get_json()["state"] == "RUNNING"

        # Stop simulation
        res_stop = client.post("/api/simulations/stop", json={"scenario_id": "normal"})
        assert res_stop.status_code == 200
        assert "normal" in res_stop.get_json()["stopped"]


def test_api_export_endpoints(runtime_app):
    runtime, app = runtime_app
    runtime.ingest(generate_window("normal", 1, 0))

    with app.test_client() as client:
        res_csv = client.get("/api/export/telemetry.csv")
        assert res_csv.status_code == 200
        assert res_csv.mimetype == "text/csv"

        res_json = client.get("/api/export/telemetry.json")
        assert res_json.status_code == 200
        assert res_json.mimetype == "application/json"


def test_controlled_demo_frontend_and_api_integration_regression(runtime_app):
    runtime, app = runtime_app
    js_path = Path(__file__).resolve().parent.parent / "dashboard" / "static" / "js" / "dashboard.js"
    html_path = Path(__file__).resolve().parent.parent / "dashboard" / "templates" / "index.html"

    js_content = js_path.read_text(encoding="utf-8")
    html_content = html_path.read_text(encoding="utf-8")

    # 1. Verify no stale /api/demo-data references remain in active frontend code
    assert "/api/demo-data" not in js_content, "Found stale /api/demo-data reference in dashboard.js"
    assert "/api/demo-data" not in html_content, "Found stale /api/demo-data reference in index.html"

    # 2. Verify controlled demo uses canonical POST /api/simulations/start endpoint
    assert 'fetch("/api/simulations/start"' in js_content or "fetch('/api/simulations/start'" in js_content
    assert '"udp_flood"' in js_content or "'udp_flood'" in js_content

    # 3. Verify backend flow: GET /api/demo-data is not reintroduced (returns 405)
    with app.test_client() as client:
        res_legacy = client.get("/api/demo-data")
        assert res_legacy.status_code == 405

        # 4. Canonical controlled demo simulation start accepted with 202
        res_start = client.post("/api/simulations/start", json={
            "scenario_id": "udp_flood",
            "intensity": 3,
            "duration": 5.0
        })
        assert res_start.status_code == 202
        data = res_start.get_json()
        assert data["scenario_id"] == "udp_flood"
        assert data["state"] == "RUNNING"
        assert data["network_transmission"] is False

        # Clean up simulation
        client.post("/api/simulations/stop", json={"scenario_id": "udp_flood"})


def test_api_events_sse_endpoint(runtime_app):
    runtime, app = runtime_app
    with app.test_client() as client:
        res = client.get("/events")
        assert res.status_code == 200
        assert res.mimetype == "text/event-stream"

        # The first event yielded upon subscription is the initial status event
        first_chunk = next(res.response)
        assert b"data: " in first_chunk

        # Publish an event to the bus and verify subsequent SSE stream formatting
        runtime.publish("telemetry", {"type": "test_event", "val": 42})
        chunk = next(res.response)
        assert b"data: " in chunk
        assert b"test_event" in chunk
        res.close()


def test_api_status_trust_score(runtime_app):
    runtime, app = runtime_app
    with app.test_client() as client:
        res = client.get("/api/status")
        assert res.status_code == 200
        data = res.get_json()
        assert "summary" in data
        assert "trust_score" in data["summary"]
        assert isinstance(data["summary"]["trust_score"], (int, float))
        assert 0.0 <= data["summary"]["trust_score"] <= 100.0


def test_api_model_assurance_endpoint(tmp_path):
    reports_dir = Path(__file__).resolve().parent.parent / "reports"
    settings = Settings(
        database_path=tmp_path / "test_assurance.sqlite3",
        report_dir=reports_dir,
        dataset_dir=tmp_path / "datasets",
    )
    runtime = GatewayRuntime(settings)
    app = create_app(runtime)
    with app.test_client() as client:
        res = client.get("/api/model-assurance")
        assert res.status_code == 200
        data = res.get_json()
        assert data["status"] == "READY"
        metrics = data["metrics"]
        assert metrics["f1"] == 1.0
        assert metrics["precision"] == 1.0
        assert metrics["recall"] == 1.0
        assert metrics["false_positive_rate"] == 0.0
        assert metrics["roc_auc"] == 1.0
        assert metrics["pr_auc"] == 1.0
        assert metrics["brier_score_calibrated"] < 0.01
        assert metrics["scenario_held_out_f1"] == 1.0
        cm = data["confusion_matrix"]
        assert cm["true_negative"] == 80
        assert cm["false_positive"] == 0
        assert cm["false_negative"] == 0
        assert cm["true_positive"] == 240
        assert cm["matrix"] == [[80, 0], [0, 240]]


def test_api_iam_endpoint(runtime_app):
    runtime, app = runtime_app
    with app.test_client() as client:
        res = client.get("/api/iam")
        assert res.status_code == 200
        data = res.get_json()
        identities = data.get("identities") or data.get("devices")
        assert identities is not None
        assert len(identities) > 0
        first_dev = identities[0]
        assert "identity" in first_dev
        assert "trust_score" in first_dev
        assert "authenticated" in first_dev
        assert "role" in first_dev

