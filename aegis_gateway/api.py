"""Flask API and SSE transport for the unified laboratory gateway runtime."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from flask import Flask, Response, jsonify, render_template, request

from .adapters import ns3_csv_events
from .runtime import GatewayRuntime
from .scenarios import catalogue


def _number(value: Any, default: int = 3) -> int:
    try: return int(value)
    except (TypeError, ValueError): return default


def create_app(runtime: GatewayRuntime) -> Flask:
    template_folder = str(Path(__file__).resolve().parent.parent / "dashboard" / "templates")
    app = Flask(__name__, template_folder=template_folder)
    app.config["runtime"] = runtime

    @app.get("/")
    def dashboard(): return render_template("index.html")

    @app.get("/attacker")
    def attacker(): return render_template("attacker.html")

    @app.get("/api/health")
    def health(): return jsonify({"ok": True, **runtime.status(), "safety": "All simulator response actions are non-enforcing."})

    @app.get("/api/status")
    def status(): return jsonify(runtime.status())

    @app.get("/api/telemetry")
    def telemetry(): return jsonify({"rows": runtime.store.telemetry(limit=_number(request.args.get("limit"), 100)), "provenance_note": "Each row carries its own source provenance."})

    @app.get("/api/events")
    def events():
        rows = [row for row in runtime.store.telemetry(limit=_number(request.args.get("limit"), 200)) if row.get("label") == "ATTACK"]
        return jsonify({"events": rows, "count": len(rows)})

    @app.get("/api/incidents")
    def incidents(): return jsonify({"incidents": runtime.store.incidents(limit=_number(request.args.get("limit"), 100), severity=request.args.get("severity"), state=request.args.get("state"))})

    @app.get("/api/incidents/<incident_id>")
    def incident(incident_id: str):
        item = runtime.store.incident(incident_id)
        return (jsonify(item), 200) if item else (jsonify({"error": "not found"}), 404)

    @app.post("/api/incidents/<incident_id>/transition")
    def transition_incident(incident_id: str):
        body = request.get_json(silent=True) or {}
        try:
            item = runtime.store.transition_incident(incident_id, str(body.get("state", "")), str(body.get("actor", "operator")), str(body.get("note", "operator transition")))
            runtime.publish("incident", item); return jsonify(item)
        except (KeyError, ValueError) as error: return jsonify({"error": str(error)}), 400

    @app.post("/api/incidents/<incident_id>/action")
    def incident_action(incident_id: str):
        body = request.get_json(silent=True) or {}
        try: return jsonify(runtime.manual_action(incident_id, str(body.get("action", "")), str(body.get("actor", "operator"))))
        except (KeyError, ValueError) as error: return jsonify({"error": str(error)}), 400

    @app.get("/api/actions")
    def actions(): return jsonify({"actions": runtime.store.actions(limit=_number(request.args.get("limit"), 100)), "enforcement": "SIMULATED / DRY-RUN only"})

    @app.get("/api/export/<kind>.<fmt>")
    def export(kind: str, fmt: str):
        try:
            content = runtime.store.export(kind, fmt)
            mimetype = "text/csv" if fmt == "csv" else "application/json"
            return Response(content, mimetype=mimetype, headers={"Content-Disposition": f'attachment; filename="aegis-{kind}.{fmt}"'})
        except ValueError as error: return jsonify({"error": str(error)}), 400

    @app.get("/api/scenarios")
    def scenarios(): return jsonify({"scenarios": catalogue(), "safety": "These are in-process profiles. They transmit no packets and do not target any device."})

    @app.post("/api/simulations/start")
    def start_simulation():
        body = request.get_json(silent=True) or {}
        try: return jsonify(runtime.start_simulation(str(body.get("scenario_id", "")), _number(body.get("intensity"), 3), body.get("duration"))), 202
        except (KeyError, ValueError) as error: return jsonify({"error": str(error)}), 400

    @app.post("/api/simulations/stop")
    def stop_simulation():
        body = request.get_json(silent=True) or {}
        return jsonify({"stopped": runtime.stop_simulation(body.get("scenario_id")), "network_transmission": False})

    @app.post("/api/iam/access")
    def iam_access():
        body = request.get_json(silent=True) or {}
        decision = runtime.iam.access(body.get("identity"), str(body.get("resource", "gateway:telemetry")))
        runtime.store.record_iam(decision); runtime.publish("iam", decision); return jsonify(decision)

    @app.get("/api/iam")
    def iam(): return jsonify({"identities": [identity.__dict__ for identity in runtime.iam.identities.values()], "policy": "authenticated role plus trust >= 40"})

    @app.get("/api/trust")
    def trust(): return jsonify({"history": runtime.store.trust(request.args.get("identity")), "calculation": "-20 suspicious detection; -15 authentication failure; +3 per normal recovery observation; bounded 0..100."})

    @app.get("/api/energy")
    def energy():
        rows = runtime.store.telemetry(limit=_number(request.args.get("limit"), 100))
        return jsonify({"rows": [{key: row.get(key) for key in ("timestamp", "packet_rate", "cpu_activity", "memory_activity", "radio_tx", "radio_rx", "energy_rate", "energy_baseline", "energy_deviation", "energy_cause", "provenance")} for row in rows], "measurement_status": "MODELLED", "claim_boundary": "Not a physical energy measurement; correlation does not prove attack."})

    @app.get("/api/protocols")
    def protocols():
        rows = runtime.store.telemetry(limit=1000); counts: dict[str, int] = {}
        for row in rows: counts[str(row.get("protocol") or "UNKNOWN")] = counts.get(str(row.get("protocol") or "UNKNOWN"), 0) + 1
        return jsonify({"mix": counts, "claim_boundary": "MQTT, CoAP, RPL, and Modbus scenario labels are simulated profiles unless a parsed source explicitly says otherwise."})

    @app.get("/api/topology")
    def topology(): return jsonify({"provenance": "SIMULATED", "discovery": False, "nodes": [
        {"id": "SENSOR-01", "type": "sensor", "trust": runtime.iam.get("SENSOR-01").trust_score},
        {"id": "GATEWAY-01", "type": "gateway", "trust": 100}, {"id": "PLC-SINK", "type": "plc", "trust": 100},
        {"id": "ATK-01", "type": "authorized-test-source", "trust": runtime.iam.get("ATK-01").trust_score},
    ], "links": [["SENSOR-01", "GATEWAY-01"], ["ATK-01", "GATEWAY-01"], ["GATEWAY-01", "PLC-SINK"]]})

    @app.get("/api/metrics")
    def metrics():
        path = runtime.settings.report_dir / "evaluation.json"
        return jsonify(json.loads(path.read_text(encoding="utf-8")) if path.exists() else {"status": "NOT_TRAINED", "instruction": "Run `make train` to create synthetic grouped-evaluation evidence."})

    @app.get("/api/ns3")
    def ns3_status():
        root = runtime.settings.root / "ns-allinone-3.48" / "ns-3.48"
        return jsonify({"available": root.exists(), "provenance": "SIMULATED", "adapter": "POST /api/ns3/import accepts existing CSV paths inside repository only", "existing_scenarios": [str(path.relative_to(runtime.settings.root)) for path in (root / "scratch").glob("ddos_udp*_v1.cc")] if root.exists() else []})

    @app.post("/api/ns3/import")
    def import_ns3():
        body = request.get_json(silent=True) or {}; candidate = (runtime.settings.root / str(body.get("path", ""))).resolve()
        if runtime.settings.root not in candidate.parents or not candidate.is_file(): return jsonify({"error": "path must name a repository-local CSV"}), 400
        try:
            count = sum(1 for event in ns3_csv_events(candidate, body.get("scenario_id")) for _ in [runtime.ingest(event)])
            return jsonify({"imported": count, "source": str(candidate.relative_to(runtime.settings.root)), "provenance": "SIMULATED"})
        except Exception as error: return jsonify({"error": str(error)}), 400

    @app.get("/api/cooja")
    def cooja(): return jsonify({"status": "NOT_IMPLEMENTED", "adapter_status": "NOT_IMPLEMENTED", "reason": "No Contiki-NG/Cooja project or runnable installation was found in this repository. The gateway schema can accept source_type=COOJA when a verified adapter is added.", "provenance": "UNKNOWN"})

    @app.get("/events")
    def sse():
        def stream():
            for message in runtime.subscribe(): yield f"event: {message['type']}\ndata: {json.dumps(message['data'], default=str)}\n\n"
        return Response(stream(), mimetype="text/event-stream", headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

    return app
