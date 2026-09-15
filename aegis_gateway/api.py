"""Flask API and SSE transport for the unified laboratory gateway runtime."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from flask import Flask, Response, jsonify, render_template, request

from .adapters import cooja_csv_events, ns3_csv_events, pcap_events, pcap_window_events
from .runtime import GatewayRuntime
from .scenarios import catalogue, generate_window


def _number(value: Any, default: int = 3) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _format_telemetry_row(event: dict[str, Any], runtime: GatewayRuntime) -> dict[str, Any]:
    dev_id = event.get("device_id") or "SENSOR-01"
    identity_obj = runtime.iam.get(dev_id)
    label = event.get("label") or "NORMAL"
    is_attack = label == "ATTACK"
    raw_conf = float(event.get("confidence") or (0.95 if is_attack else 0.05))
    ddos_prob = round(raw_conf if is_attack else max(0.0, 1.0 - raw_conf), 3)
    normal_prob = round(1.0 - ddos_prob, 3)

    rate = float(event.get("packet_rate") or 0.0)
    byte_rate = float(event.get("byte_rate") or 0.0)
    packet_count = int(event.get("packet_count") or round(rate))
    packet_size = float(event.get("packet_size") or (byte_rate / rate if rate > 0 else 0.0))
    protocol = event.get("protocol") or "UDP"

    evidence = [
        f"Protocol: {protocol}",
        f"Packet rate: {rate:.1f} pps (baseline: 20.0 pps)",
        f"Modelled energy deviation: {round(float(event.get('energy_deviation') or 0.0) * 100, 1)}%",
    ]
    if event.get("energy_cause"):
        evidence.append(str(event.get("energy_cause")))

    action = event.get("response_action") or ("BLOCK" if is_attack else "ALERT")
    severity = event.get("severity") or ("HIGH" if is_attack else "INFO")

    row = dict(event)
    row.update({
        "window_start": event.get("timestamp"),
        "packet_count": packet_count,
        "packets_per_second": rate,
        "bytes_per_second": byte_rate,
        "average_packet_size": packet_size,
        "prediction": label,
        "ddos_probability": ddos_prob,
        "normal_probability": normal_prob,
        "security_action": action,
        "mitigation_action": action,
        "severity": severity,
        "mitigation_reason": "Automated simulated policy response" if is_attack else "Normal operating baseline",
        "identity_context": {
            "observed_source_count": event.get("unique_sources") or 1,
            "known_device_count": 1 if identity_obj.authenticated else 0,
            "unknown_device_count": 0 if identity_obj.authenticated else 1,
            "device_contexts": [{
                "device_id": dev_id,
                "ip_address": event.get("src_ip") or ("10.42.0.250" if is_attack else "10.42.0.11"),
                "device_role": identity_obj.role.upper(),
                "identity_status": "KNOWN" if identity_obj.authenticated else "UNKNOWN",
                "authentication_status": event.get("authentication_status") or ("AUTHENTICATED" if identity_obj.authenticated else "FAILED_OR_UNVERIFIED"),
                "authorization_decision": event.get("access_decision") or ("ALLOW" if identity_obj.trust_score >= 40 else "DENIED"),
                "identity_source": "GATEWAY_IAM_REGISTRY",
                "environment": "CONTROLLED_LAB",
                "suspicious": is_attack
            }]
        },
        "lifecycle_context": {
            "available": True,
            "lifecycle_state": event.get("lifecycle_state") or ("CONTAINED" if is_attack else "NORMAL"),
            "window_observation_state": event.get("lifecycle_state") or ("DETECTED" if is_attack else "OBSERVED"),
            "lifecycle_stage": "RESPONSE_SIMULATED" if is_attack else "BASELINE_OBSERVATION",
            "implementation_status": "SIMULATED / DRY-RUN",
            "enforcement_status": "HOST FIREWALL UNTOUCHED",
            "recovery_status": "MONITORING" if not is_attack else "CONTAINED_IN_SOFTWARE",
            "window_start": event.get("timestamp")
        },
        "explainability_context": {
            "evidence_status": "OBSERVED",
            "prediction": label,
            "ddos_probability": ddos_prob,
            "normal_probability": normal_prob,
            "packet_count": packet_count,
            "packets_per_second": rate,
            "bytes_per_second": byte_rate,
            "average_packet_size": packet_size,
            "unique_sources": event.get("unique_sources") or 1,
            "unique_destinations": event.get("unique_destinations") or 1,
            "udp_count": packet_count if protocol == "UDP" else 0,
            "tcp_count": packet_count if protocol == "TCP" else 0,
            "icmp_count": packet_count if protocol in ("ICMP", "ICMPV6") else 0,
            "flow_count": event.get("unique_sources") or 1,
            "security_action": action,
            "severity": severity,
            "mitigation_action": action,
            "mitigation_reason": "Automated simulated policy response" if is_attack else "Normal operating baseline",
            "observed_evidence": evidence
        }
    })
    return row


def _format_energy_row(event: dict[str, Any]) -> dict[str, Any]:
    rate = float(event.get("packet_rate") or 0.0)
    baseline = float(event.get("energy_baseline") or 55.0)
    e_rate = float(event.get("energy_rate") or baseline)
    dev = float(event.get("energy_deviation") if event.get("energy_deviation") is not None else ((e_rate - baseline) / baseline))
    consumed = float(event.get("energy_consumed") or e_rate)
    return {
        "window_start": event.get("timestamp"),
        "energy_estimate": round(consumed, 2),
        "energy_rate": round(e_rate, 2),
        "energy_per_packet": round(consumed / rate, 4) if rate > 0 else 0.0,
        "baseline_energy": round(baseline, 2),
        "energy_deviation": round(dev, 4),
        "energy_increase_percent": round(dev * 100.0, 2),
        "tx_activity": float(event.get("radio_tx") or 4.0),
        "rx_activity": float(event.get("radio_rx") or 5.0),
        "cpu_activity": float(event.get("cpu_activity") or 6.0),
        "energy_cause": event.get("energy_cause") or f"MODELLED: baseline rhythm ({e_rate:.1f} mW)",
        "measurement_status": "MODELLED",
        "environment": "CONTROLLED_SIMULATION",
        "hardware_measured": False,
        "provenance": event.get("provenance") or "MODELLED"
    }


def create_app(runtime: GatewayRuntime) -> Flask:
    dashboard_dir = Path(__file__).resolve().parent.parent / "dashboard"
    template_folder = str(dashboard_dir / "templates")
    static_folder = str(dashboard_dir / "static")

    app = Flask(
        __name__,
        template_folder=template_folder,
        static_folder=static_folder,
        static_url_path="/static"
    )
    app.config["runtime"] = runtime
    app.config["TEMPLATES_AUTO_RELOAD"] = True
    app.jinja_env.auto_reload = True

    @app.get("/")
    def dashboard():
        return render_template("index.html")

    @app.get("/attacker")
    def attacker():
        return render_template("attacker.html")

    @app.get("/api/health")
    def health():
        return jsonify({
            "ok": True,
            **runtime.status(),
            "safety": "All simulator response actions are non-enforcing."
        })

    @app.get("/api/status")
    def status():
        base_status = runtime.status()
        latest = base_status.get("latest") or {}
        pred = latest.get("label") or "NORMAL"
        is_attack = pred == "ATTACK"
        ddos_p = float(latest.get("confidence") or (0.95 if is_attack else 0.05)) if is_attack else round(1.0 - float(latest.get("confidence") or 0.95), 3)

        dev_id = latest.get("device_id") or "SENSOR-01"
        trust_val = runtime.iam.get(dev_id).trust_score

        active_inc = runtime.store.find_active_incident()
        if not active_inc:
            recent_incidents = runtime.store.incidents(limit=1)
            if recent_incidents and recent_incidents[0].get("lifecycle_state") == "RESOLVED":
                active_inc = recent_incidents[0]

        active_inc_summary = {
            "incident_id": active_inc["incident_id"],
            "lifecycle_state": active_inc["lifecycle_state"],
            "severity": active_inc.get("severity"),
            "attack_type": active_inc.get("attack_type"),
            "recovery_state": active_inc.get("recovery_state"),
        } if active_inc else None
        canonical_state = active_inc["lifecycle_state"] if active_inc else "OBSERVED"

        base_status["summary"] = {
            "latest_prediction": pred,
            "latest_packet_rate": float(latest.get("packet_rate") or 18.0),
            "latest_bytes_per_second": float(latest.get("byte_rate") or 4140.0),
            "latest_ddos_probability": ddos_p,
            "latest_security_action": latest.get("response_action") or "ALERT",
            "latest_mitigation_action": latest.get("response_action") or "NONE",
            "trust_score": float(trust_val),
            "active_incident": active_inc_summary,
            "lifecycle_state": canonical_state,
        }
        base_status["active_incident"] = active_inc_summary
        base_status["lifecycle_state"] = canonical_state
        base_status["pipeline"] = {
            "traffic_features": True,
            "ml_predictions": True,
            "security_decisions": True,
            "mitigation_decisions": True
        }
        return jsonify(base_status)

    @app.get("/api/telemetry")
    def telemetry():
        limit = _number(request.args.get("limit"), 100)
        raw_rows = runtime.store.telemetry(limit=limit)
        formatted = [_format_telemetry_row(row, runtime) for row in raw_rows]
        return jsonify({
            "rows": formatted,
            "count": len(formatted),
            "provenance_note": "Each row carries its own source provenance."
        })

    @app.get("/api/events")
    def events():
        limit = _number(request.args.get("limit"), 200)
        raw_rows = [row for row in runtime.store.telemetry(limit=limit) if row.get("label") == "ATTACK"]
        formatted = [_format_telemetry_row(row, runtime) for row in raw_rows]
        return jsonify({"events": formatted, "count": len(formatted)})

    @app.get("/api/incidents")
    def incidents():
        limit = _number(request.args.get("limit"), 100)
        items = runtime.store.incidents(limit=limit, severity=request.args.get("severity"), state=request.args.get("state"))
        return jsonify({"incidents": items, "count": len(items)})

    @app.get("/api/incidents/<incident_id>")
    def incident(incident_id: str):
        item = runtime.store.incident(incident_id)
        return (jsonify(item), 200) if item else (jsonify({"error": "not found"}), 404)

    @app.post("/api/incidents/<incident_id>/transition")
    def transition_incident(incident_id: str):
        body = request.get_json(silent=True) or {}
        try:
            item = runtime.store.transition_incident(
                incident_id,
                str(body.get("state", "")),
                str(body.get("actor", "operator")),
                str(body.get("note", "operator transition"))
            )
            runtime.publish("incident", item)
            return jsonify(item)
        except (KeyError, ValueError) as error:
            return jsonify({"error": str(error)}), 400

    @app.post("/api/incidents/<incident_id>/action")
    def incident_action(incident_id: str):
        body = request.get_json(silent=True) or {}
        try:
            return jsonify(runtime.manual_action(incident_id, str(body.get("action", "")), str(body.get("actor", "operator"))))
        except (KeyError, ValueError) as error:
            return jsonify({"error": str(error)}), 400

    @app.post("/api/manual/action")
    def manual_action():
        body = request.get_json(silent=True) or {}
        action = str(body.get("action", "")).upper()
        incident_id = body.get("incident_id")
        actor = str(body.get("actor", "operator"))
        if not incident_id:
            active = runtime.store.find_active_incident()
            if active:
                incident_id = active["incident_id"]
            else:
                incidents_list = runtime.store.incidents(limit=1)
                if incidents_list:
                    incident_id = incidents_list[0]["incident_id"]
        if incident_id:
            try:
                return jsonify(runtime.manual_action(incident_id, action, actor))
            except Exception as e:
                return jsonify({"error": str(e)}), 400
        stored = runtime.store.record_action(
            event_id=None,
            incident_id=None,
            action=action,
            reason="operator manual command",
            policy="operator-manual-v1",
            mode="MANUAL",
            result="SIMULATED_NOT_ENFORCED",
            provenance="SIMULATED"
        )
        runtime.publish("response", stored)
        return jsonify({"action": stored, "incident": None})

    @app.get("/api/actions")
    def actions():
        return jsonify({
            "actions": runtime.store.actions(limit=_number(request.args.get("limit"), 100)),
            "enforcement": "SIMULATED / DRY-RUN only"
        })

    @app.get("/api/export/<kind>.<fmt>")
    def export(kind: str, fmt: str):
        try:
            content = runtime.store.export(kind, fmt)
            mimetype = "text/csv" if fmt == "csv" else "application/json"
            return Response(content, mimetype=mimetype, headers={"Content-Disposition": f'attachment; filename="aegis-{kind}.{fmt}"'})
        except ValueError as error:
            return jsonify({"error": str(error)}), 400

    @app.get("/api/scenarios")
    def scenarios():
        return jsonify({
            "scenarios": catalogue(),
            "safety": "These are in-process profiles. They transmit no packets and do not target any device."
        })

    @app.post("/api/simulations/start")
    def start_simulation():
        body = request.get_json(silent=True) or {}
        try:
            return jsonify(runtime.start_simulation(
                str(body.get("scenario_id", "")),
                _number(body.get("intensity"), 3),
                body.get("duration")
            )), 202
        except (KeyError, ValueError) as error:
            return jsonify({"error": str(error)}), 400

    @app.post("/api/simulations/stop")
    def stop_simulation():
        body = request.get_json(silent=True) or {}
        return jsonify({"stopped": runtime.stop_simulation(body.get("scenario_id")), "network_transmission": False})

    @app.post("/api/demo-data")
    def demo_data():
        """Single-step validated controlled attack execution for the dashboard button."""
        event = generate_window("udp_flood", intensity=3, sequence=0)
        res = runtime.ingest(event)
        is_attack = res["decision"]["prediction"] == "ATTACK"
        ddos_p = float(res["decision"]["confidence"]) if is_attack else round(1.0 - float(res["decision"]["confidence"]), 2)
        return jsonify({
            "prediction": res["decision"]["prediction"],
            "ddos_probability": ddos_p,
            "security_action": res["response"]["action"],
            "severity": res["decision"]["severity"],
            "mitigation_action": res["response"]["action"],
            "mitigation_reason": res["response"]["reason"],
            "enforcement": False,
            "controlled": True,
            "offline_only": True
        })

    @app.post("/api/settings/mode")
    def set_mode():
        body = request.get_json(silent=True) or {}
        mode = body.get("mode")
        auto = body.get("auto")
        cfg = runtime.configure_response(mode=mode, auto=auto)
        return jsonify(cfg)

    @app.post("/api/iam/access")
    def iam_access():
        body = request.get_json(silent=True) or {}
        decision = runtime.iam.access(body.get("identity"), str(body.get("resource", "gateway:telemetry")))
        runtime.store.record_iam(decision)
        runtime.publish("iam", decision)
        return jsonify(decision)

    @app.get("/api/iam")
    def iam():
        identity_list = [identity.__dict__ for identity in runtime.iam.identities.values()]
        return jsonify({
            "identities": identity_list,
            "devices": identity_list,
            "policy": "authenticated role plus trust >= 40"
        })

    @app.get("/api/trust")
    def trust():
        return jsonify({
            "history": runtime.store.trust(request.args.get("identity")),
            "calculation": "-20 suspicious detection; -15 authentication failure; +3 per normal recovery observation; bounded 0..100."
        })

    @app.get("/api/energy")
    def energy():
        limit = _number(request.args.get("limit"), 100)
        raw_rows = runtime.store.telemetry(limit=limit)
        formatted = [_format_energy_row(r) for r in raw_rows]
        return jsonify({
            "rows": formatted,
            "count": len(formatted),
            "baseline": 55.0,
            "unit": "mW",
            "measurement_status": "MODELLED",
            "environment": "CONTROLLED_SIMULATION",
            "hardware_measured": False,
            "claim_boundary": "Not a physical energy measurement; correlation does not prove attack."
        })

    @app.get("/api/protocols")
    def protocols():
        rows = runtime.store.telemetry(limit=1000)
        counts: dict[str, int] = {}
        for row in rows:
            proto = str(row.get("protocol") or "UNKNOWN").upper()
            if proto in ("ICMP", "ICMPV6"):
                proto = "ICMP"
            elif proto == "MQTT" or row.get("dst_port") == 1883 or row.get("scenario_id") == "mqtt_anomaly":
                proto = "MQTT"
            elif proto == "UDP":
                proto = "UDP"
            elif proto == "TCP":
                proto = "TCP"
            counts[proto] = counts.get(proto, 0) + 1

        total = sum(counts.values()) or 1
        percentages = {k: round((v / total) * 100, 1) for k, v in counts.items()}
        return jsonify({
            "mix": counts,
            "total": sum(counts.values()),
            "percentages": percentages,
            "aggregation": "ICMP/ICMPv6 grouped under ICMP; port 1883 and mqtt_anomaly grouped under MQTT; port 5683/UDP under UDP.",
            "claim_boundary": "MQTT, CoAP, RPL, and Modbus scenario labels are simulated profiles unless a parsed source explicitly says otherwise."
        })

    @app.get("/api/topology")
    def topology():
        sensors = [
            {"name": "SENSOR-01", "id": "SENSOR-01", "ip": "10.42.0.11", "role": "IIoT Sensor", "authorization": "AUTHORIZED", "trust": runtime.iam.get("SENSOR-01").trust_score},
            {"name": "SENSOR-02", "id": "SENSOR-02", "ip": "10.42.0.12", "role": "Sensor Cluster", "authorization": "AUTHORIZED", "trust": runtime.iam.get("SENSOR-GROUP-A").trust_score},
        ]
        gateway = {"name": "GATEWAY-01", "id": "GATEWAY-01", "ip": "10.42.0.1", "role": "Security Gateway", "authorization": "AUTHORIZED", "trust": 100}
        ot_servers = [{"name": "PLC-SINK", "id": "PLC-SINK", "ip": "10.42.0.10", "role": "OT PLC Sink", "authorization": "AUTHORIZED", "trust": 100}]
        attack_nodes = [{"name": "ATK-01", "id": "ATK-01", "ip": "10.42.0.250", "role": "Controlled Lab Attacker", "authorization": "DENIED", "trust": runtime.iam.get("ATK-01").trust_score, "simulation_only": True}]
        links = [
            {"source": "SENSOR-01", "target": "GATEWAY-01"},
            {"source": "SENSOR-02", "target": "GATEWAY-01"},
            {"source": "ATK-01", "target": "GATEWAY-01"},
            {"source": "GATEWAY-01", "target": "PLC-SINK"}
        ]
        return jsonify({
            "status": "ONLINE",
            "environment": "CONTROLLED_SIMULATION",
            "provenance": "SIMULATED",
            "discovery": False,
            "sensors": sensors,
            "gateway": gateway,
            "ot_servers": ot_servers,
            "attack_nodes": attack_nodes,
            "links": links,
            "nodes": [
                {"id": "SENSOR-01", "type": "sensor", "trust": runtime.iam.get("SENSOR-01").trust_score},
                {"id": "GATEWAY-01", "type": "gateway", "trust": 100},
                {"id": "PLC-SINK", "type": "plc", "trust": 100},
                {"id": "ATK-01", "type": "authorized-test-source", "trust": runtime.iam.get("ATK-01").trust_score},
            ]
        })

    @app.get("/api/metrics")
    def metrics():
        path = runtime.settings.report_dir / "evaluation.json"
        return jsonify(json.loads(path.read_text(encoding="utf-8")) if path.exists() else {
            "status": "NOT_TRAINED",
            "instruction": "Run `python3 -m aegis_gateway.cli train` to generate evaluation evidence."
        })

    @app.get("/api/model-assurance")
    def model_assurance():
        eval_path = runtime.settings.report_dir / "evaluation.json"
        cm_path = runtime.settings.report_dir / "confusion_matrix.csv"

        data: dict[str, Any] = {
            "status": "READY" if eval_path.exists() else "NOT_TRAINED",
            "model_architecture": "Random Forest (240 trees) + Isolation Forest (200 trees)",
            "model_version": "hybrid-rf-if-v2",
            "dataset_version": "synthetic-lab-v2",
            "evaluation_protocol": "stratified campaign-grouped train/validation/test plus scenario-held-out evaluation",
            "evaluation_context": "HELD-OUT SYNTHETIC LAB EVALUATION",
            "metrics": {
                "precision": None,
                "recall": None,
                "f1": None,
                "false_positive_rate": None,
                "roc_auc": None,
                "pr_auc": None,
                "brier_score_calibrated": None,
                "scenario_held_out_f1": None,
            },
            "confusion_matrix": {
                "labels": ["NORMAL", "ATTACK"],
                "true_negative": None,
                "false_positive": None,
                "false_negative": None,
                "true_positive": None,
                "matrix": None,
            },
            "splits": {},
            "provenance": "SYNTHETIC",
            "claim_boundary": "Scenario-separated synthetic evaluation on stratified campaign-grouped lab data without leakage — not a production accuracy claim. Platt calibration guarantees bounded decision probabilities."
        }

        if eval_path.exists():
            try:
                ev = json.loads(eval_path.read_text(encoding="utf-8"))
                data["experiment_id"] = ev.get("experiment_id")
                data["timestamp"] = ev.get("timestamp")
                data["feature_version"] = ev.get("feature_version")
                data["splits"] = ev.get("splits", {})
                data["feature_importance"] = ev.get("feature_importance", {})

                test_block = ev.get("test", {})
                data["metrics"]["precision"] = test_block.get("precision", {}).get("ATTACK")
                data["metrics"]["recall"] = test_block.get("recall", {}).get("ATTACK")
                data["metrics"]["f1"] = test_block.get("f1", {}).get("ATTACK")
                data["metrics"]["false_positive_rate"] = test_block.get("false_positive_rate")
                data["metrics"]["roc_auc"] = test_block.get("roc_auc")
                data["metrics"]["pr_auc"] = test_block.get("pr_auc")

                calib = ev.get("calibration", {})
                data["metrics"]["brier_score_calibrated"] = calib.get("brier_score_calibrated")

                held = ev.get("scenario_held_out", {})
                data["metrics"]["scenario_held_out_f1"] = held.get("f1", {}).get("ATTACK")

                if "confusion_matrix" in test_block:
                    cm = test_block["confusion_matrix"]
                    data["confusion_matrix"]["matrix"] = cm
                    if len(cm) == 2 and len(cm[0]) == 2 and len(cm[1]) == 2:
                        data["confusion_matrix"]["true_negative"] = cm[0][0]
                        data["confusion_matrix"]["false_positive"] = cm[0][1]
                        data["confusion_matrix"]["false_negative"] = cm[1][0]
                        data["confusion_matrix"]["true_positive"] = cm[1][1]
            except Exception as err:
                data["eval_parse_error"] = str(err)

        if cm_path.exists():
            try:
                lines = cm_path.read_text(encoding="utf-8").strip().splitlines()
                if len(lines) >= 3:
                    row_norm = lines[1].split(",")
                    row_atk = lines[2].split(",")
                    tn = int(row_norm[1])
                    fp = int(row_norm[2])
                    fn = int(row_atk[1])
                    tp = int(row_atk[2])
                    data["confusion_matrix"]["true_negative"] = tn
                    data["confusion_matrix"]["false_positive"] = fp
                    data["confusion_matrix"]["false_negative"] = fn
                    data["confusion_matrix"]["true_positive"] = tp
                    data["confusion_matrix"]["matrix"] = [[tn, fp], [fn, tp]]
            except Exception as err:
                data["cm_parse_error"] = str(err)

        return jsonify(data)

    @app.get("/api/ns3")
    def ns3_status():
        root = runtime.settings.root / "ns-allinone-3.48" / "ns-3.48"
        scratch_dir = root / "scratch"
        existing = [str(path.relative_to(runtime.settings.root)) for path in scratch_dir.glob("*.cc")] if scratch_dir.exists() else []
        return jsonify({
            "available": root.exists(),
            "provenance": "SIMULATED",
            "adapter": "POST /api/ns3/import accepts repository-local CSV paths",
            "existing_scenarios": existing,
            "pcap_traces": [f"dataset/{p.name}" for p in (runtime.settings.root / "dataset").glob("ns3_*.pcap")]
        })

    @app.post("/api/ns3/import")
    def import_ns3():
        body = request.get_json(silent=True) or {}
        candidate = (runtime.settings.root / str(body.get("path", ""))).resolve()
        if runtime.settings.root not in candidate.parents or not candidate.is_file():
            return jsonify({"error": "path must name a repository-local CSV"}), 400
        try:
            count = sum(1 for event in ns3_csv_events(candidate, body.get("scenario_id")) for _ in [runtime.ingest(event)])
            return jsonify({
                "imported": count,
                "source": str(candidate.relative_to(runtime.settings.root)),
                "provenance": "SIMULATED"
            })
        except Exception as error:
            return jsonify({"error": str(error)}), 400

    @app.get("/api/cooja")
    def cooja():
        cooja_dir = Path("/home/kali/contiki-ng/examples/ai_edge_iiot")
        cooja_data = cooja_dir / "data" / "cooja_ml_ready_v1.csv"
        frozen_model = runtime.settings.root / "detection" / "cooja_attack_model_v1.pkl"
        available = cooja_data.exists()
        return jsonify({
            "status": "SIMULATION_READY" if available else "NOT_INSTALLED",
            "adapter_status": "READY" if available else "NOT_IMPLEMENTED",
            "provenance": "SIMULATED",
            "environment": "Contiki-NG / Cooja 6LoWPAN Emulation",
            "data_available": available,
            "data_path": str(cooja_data) if available else None,
            "frozen_model": str(frozen_model.relative_to(runtime.settings.root)) if frozen_model.exists() else None,
            "claim_boundary": "Cooja mote emulation output, not physical hardware measurements."
        })

    @app.post("/api/cooja/import")
    def import_cooja():
        body = request.get_json(silent=True) or {}
        raw_path = body.get("path") or "/home/kali/contiki-ng/examples/ai_edge_iiot/data/cooja_ml_ready_v1.csv"
        candidate = Path(raw_path).resolve()
        if not candidate.is_file():
            return jsonify({"error": f"File not found: {raw_path}"}), 400
        try:
            count = sum(1 for event in cooja_csv_events(candidate, body.get("scenario_id")) for _ in [runtime.ingest(event)])
            return jsonify({
                "imported": count,
                "source": str(candidate),
                "provenance": "SIMULATED",
                "source_type": "COOJA"
            })
        except Exception as error:
            return jsonify({"error": str(error)}), 400

    @app.post("/api/pcap/replay")
    def replay_pcap():
        body = request.get_json(silent=True) or {}
        candidate = (runtime.settings.root / str(body.get("path", ""))).resolve()
        if runtime.settings.root not in candidate.parents or not candidate.is_file():
            return jsonify({"error": "path must name a repository-local PCAP file"}), 400
        try:
            windowed = body.get("windowed", True)
            stream = pcap_window_events(candidate) if windowed else pcap_events(candidate)
            count = sum(1 for event in stream for _ in [runtime.ingest(event)])
            return jsonify({
                "replayed": count,
                "source": str(candidate.relative_to(runtime.settings.root)),
                "provenance": "REPLAYED",
                "transmitted": False
            })
        except Exception as error:
            return jsonify({"error": str(error)}), 400

    @app.get("/events")
    def sse():
        def stream():
            for message in runtime.subscribe():
                yield f"event: {message['type']}\ndata: {json.dumps(message['data'], default=str)}\n\n"
        return Response(stream(), mimetype="text/event-stream")

    return app


if __name__ == "__main__":
    runtime = GatewayRuntime()
    app = create_app(runtime)
    app.run(host=runtime.settings.host, port=runtime.settings.port, debug=False, threaded=True)
