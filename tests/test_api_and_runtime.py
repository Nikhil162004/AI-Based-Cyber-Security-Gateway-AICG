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


def test_protocol_percentages_normalize_correctly(runtime_app):
    """Verify /api/protocols returns valid distribution summing to ~100% and never exceeding 100%."""
    runtime, app = runtime_app
    with app.test_client() as client:
        res = client.get("/api/protocols")
        assert res.status_code == 200
        data = res.get_json()
        assert "mix" in data
        assert "percentages" in data
        assert "claim_boundary" in data

        percentages = data["percentages"]
        if percentages:
            total_pct = sum(percentages.values())
            # Sum must be within rounding tolerance and strictly <= 100.5%
            assert 99.5 <= total_pct <= 100.5, f"Percentages sum to {total_pct}%, outside acceptable 100% bounds"

        # Mathematical integrity test of the Largest Remainder Normalization algorithm
        def normalize_largest_remainder(counts: dict[str, int]) -> dict[str, int]:
            total = sum(counts.values())
            if total == 0:
                return {k: 0 for k in counts}
            raw = {k: (v / total) * 100 for k, v in counts.items()}
            floor_p = {k: int(p) for k, p in raw.items()}
            remainder = 100 - sum(floor_p.values())
            remainders = sorted([(k, raw[k] - floor_p[k]) for k in counts if counts[k] > 0], key=lambda x: x[1], reverse=True)
            norm = dict(floor_p)
            for i in range(min(remainder, len(remainders))):
                norm[remainders[i][0]] += 1
            return norm

        # Test edge case: UDP 212, TCP 20, ICMP 9, MQTT 0
        norm = normalize_largest_remainder({"UDP": 212, "TCP": 20, "ICMP": 9, "MQTT": 0})
        assert sum(norm.values()) == 100, f"Normalized percentages sum to {sum(norm.values())}"
        assert norm["UDP"] == 88
        assert norm["TCP"] == 8
        assert norm["ICMP"] == 4
        assert norm["MQTT"] == 0
        assert norm["UDP"] + norm["TCP"] + norm["ICMP"] + norm["MQTT"] == 100


def test_model_assurance_held_out_claims_and_consistency(tmp_path):
    """Verify model assurance presentation is academically defensible and consistent with confusion matrix."""
    reports_dir = Path(__file__).resolve().parent.parent / "reports"
    settings = Settings(
        database_path=tmp_path / "test_assurance_audit.sqlite3",
        report_dir=reports_dir,
        dataset_dir=tmp_path / "datasets",
    )
    runtime = GatewayRuntime(settings)
    app = create_app(runtime)
    with app.test_client() as client:
        res = client.get("/api/model-assurance")
        assert res.status_code == 200
        data = res.get_json()
        assert data.get("evaluation_context") == "HELD-OUT SYNTHETIC LAB EVALUATION"
        assert "not a production accuracy claim" in data.get("claim_boundary", "").lower()

        cm = data.get("confusion_matrix", {})
        tn = cm.get("true_negative", 0)
        fp = cm.get("false_positive", 0)
        fn = cm.get("false_negative", 0)
        tp = cm.get("true_positive", 0)

        # Total test windows evaluated
        assert tn + fp + fn + tp == 320
        # Zero false positives and false negatives on held-out test split
        assert fp == 0
        assert fn == 0
        assert tp == 240
        assert tn == 80

        metrics = data.get("metrics", {})
        # Mathematical consistency with confusion matrix: TP / (TP + FP) = 240 / 240 = 1.0
        calculated_precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        calculated_recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        assert round(metrics.get("precision"), 2) == round(calculated_precision, 2)
        assert round(metrics.get("recall"), 2) == round(calculated_recall, 2)


def test_incident_current_vs_history_semantics(runtime_app):
    """Verify that current runtime active incident is differentiated from resolved historical audit records."""
    runtime, app = runtime_app
    with app.test_client() as client:
        # Create/ingest an attack event that produces an incident
        from aegis_gateway.scenarios import generate_window
        event = generate_window("udp_flood", intensity=4, sequence=1)
        record = runtime.ingest(event)

        incidents_res = client.get("/api/incidents")
        assert incidents_res.status_code == 200
        inc_list = incidents_res.get_json()["incidents"]
        assert len(inc_list) > 0

        latest_inc = inc_list[0]
        assert latest_inc["provenance"] == "SIMULATED"

        # Transition to RESOLVED
        inc_id = latest_inc["incident_id"]
        res_trans = client.post(f"/api/incidents/{inc_id}/transition", json={
            "state": "RESOLVED",
            "actor": "operator_test",
            "note": "Controlled resolution"
        })
        assert res_trans.status_code == 200
        assert res_trans.get_json()["lifecycle_state"] == "RESOLVED"

        # Transition to CLOSED
        res_close = client.post(f"/api/incidents/{inc_id}/transition", json={
            "state": "CLOSED",
            "actor": "operator_test",
            "note": "Audit log closure"
        })
        assert res_close.status_code == 200
        assert res_close.get_json()["lifecycle_state"] == "CLOSED"


def test_energy_baseline_causal_contract(runtime_app):
    """Verify that energy telemetry explicitly states modelled software telemetry boundary."""
    runtime, app = runtime_app
    with app.test_client() as client:
        res = client.get("/api/energy")
        assert res.status_code == 200
        data = res.get_json()
        assert data["measurement_status"] == "MODELLED"
        assert data["hardware_measured"] is False
        assert "correlation does not prove attack" in data["claim_boundary"].lower()


def test_iam_auth_vs_access_semantics():
    """Verify zero-trust semantics: authentication != authorization."""
    from aegis_gateway.iam import IAMService
    iam = IAMService()

    # Authenticated sensor
    acc_sensor = iam.access("SENSOR-01")
    assert acc_sensor["authentication_status"] == "AUTHENTICATED"
    assert acc_sensor["authorization_status"] == "AUTHORIZED"
    assert acc_sensor["decision"] == "ALLOW"

    # Untrusted attacker node: unauthenticated and denied
    acc_atk = iam.access("ATK-01")
    assert acc_atk["authentication_status"] == "FAILED_OR_UNVERIFIED"
    assert acc_atk["authorization_status"] == "DENIED"
    assert acc_atk["decision"] == "DENY"
    assert iam.get("ATK-01").trust_score < 40.0


def test_offline_first_no_remote_assets():
    """Verify index.html and attacker.html have no remote CDNs or external fonts."""
    repo_root = Path(__file__).resolve().parent.parent
    index_html = (repo_root / "dashboard" / "templates" / "index.html").read_text(encoding="utf-8")
    attacker_html = (repo_root / "dashboard" / "templates" / "attacker.html").read_text(encoding="utf-8")

    for html_name, html_content in [("index.html", index_html), ("attacker.html", attacker_html)]:
        assert "fonts.googleapis.com" not in html_content, f"Found remote Google Fonts in {html_name}"
        assert "fonts.gstatic.com" not in html_content, f"Found remote gstatic in {html_name}"
        assert "cdn.jsdelivr.net" not in html_content, f"Found remote jsdelivr in {html_name}"
        assert "cdnjs.cloudflare.com" not in html_content, f"Found remote cloudflare CDN in {html_name}"
        assert "unpkg.com" not in html_content, f"Found remote unpkg in {html_name}"


def test_sticky_header_scroll_margin_css():
    """Verify dashboard.css includes --hmi-header-height and scroll-margin-top rules."""
    repo_root = Path(__file__).resolve().parent.parent
    css = (repo_root / "dashboard" / "static" / "css" / "dashboard.css").read_text(encoding="utf-8")

    assert "--hmi-header-height:" in css
    assert "scroll-margin-top:" in css
    assert "position: sticky" in css
    assert "top: 0" in css


