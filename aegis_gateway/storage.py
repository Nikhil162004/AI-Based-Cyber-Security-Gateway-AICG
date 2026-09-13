"""Durable local SQLite historian with append-only telemetry/event records."""

from __future__ import annotations

import csv
import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from io import StringIO
from pathlib import Path
from typing import Any, Iterator
from uuid import uuid4

from .schema import CANONICAL_FIELDS, TelemetryEvent, utc_now


class GatewayStore:
    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.initialize()

    @contextmanager
    def connection(self) -> Iterator[sqlite3.Connection]:
        con = sqlite3.connect(self.path, timeout=10)
        con.row_factory = sqlite3.Row
        try:
            yield con
            con.commit()
        finally:
            con.close()

    def initialize(self) -> None:
        canonical_columns = ",\n".join(f"{field} TEXT" for field in CANONICAL_FIELDS)
        with self.connection() as con:
            con.executescript(
                f"""
                CREATE TABLE IF NOT EXISTS telemetry (
                    {canonical_columns}, raw_json TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS telemetry_timestamp_idx ON telemetry(timestamp DESC);
                CREATE INDEX IF NOT EXISTS telemetry_scenario_idx ON telemetry(scenario_id);
                CREATE INDEX IF NOT EXISTS telemetry_source_idx ON telemetry(source_type, source_id);
                CREATE TABLE IF NOT EXISTS incidents (
                    incident_id TEXT PRIMARY KEY, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
                    event_id TEXT NOT NULL, device_id TEXT, source_id TEXT, attack_type TEXT,
                    severity TEXT, confidence REAL, evidence_json TEXT NOT NULL, affected_resources TEXT,
                    energy_impact TEXT, iam_impact TEXT, trust_impact TEXT, response_action TEXT,
                    response_mode TEXT, operator TEXT, lifecycle_state TEXT NOT NULL,
                    recovery_state TEXT NOT NULL, resolved_at TEXT, provenance TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS incidents_state_idx ON incidents(lifecycle_state, severity);
                CREATE TABLE IF NOT EXISTS incident_history (
                    history_id TEXT PRIMARY KEY, incident_id TEXT NOT NULL, timestamp TEXT NOT NULL,
                    previous_state TEXT, state TEXT NOT NULL, actor TEXT, note TEXT, evidence_json TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS incident_history_incident_idx ON incident_history(incident_id, timestamp);
                CREATE TABLE IF NOT EXISTS actions (
                    action_id TEXT PRIMARY KEY, timestamp TEXT NOT NULL, event_id TEXT, incident_id TEXT,
                    action TEXT NOT NULL, reason TEXT NOT NULL, policy TEXT NOT NULL, mode TEXT NOT NULL,
                    result TEXT NOT NULL, provenance TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS iam_events (
                    iam_event_id TEXT PRIMARY KEY, timestamp TEXT NOT NULL, identity TEXT, role TEXT,
                    authentication_status TEXT, authorization_status TEXT, access_request TEXT,
                    decision TEXT, reason TEXT, provenance TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS trust_history (
                    trust_event_id TEXT PRIMARY KEY, timestamp TEXT NOT NULL, identity TEXT NOT NULL,
                    score REAL NOT NULL, delta REAL NOT NULL, reason TEXT NOT NULL, provenance TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS trust_identity_idx ON trust_history(identity, timestamp DESC);
                CREATE TABLE IF NOT EXISTS metadata (
                    metadata_id TEXT PRIMARY KEY, kind TEXT NOT NULL, version TEXT NOT NULL,
                    created_at TEXT NOT NULL, payload_json TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS metadata_kind_idx ON metadata(kind, created_at DESC);
                """
            )

    def append_telemetry(self, event: TelemetryEvent) -> None:
        event.normalize()
        values = event.to_dict()
        columns = CANONICAL_FIELDS + ["raw_json"]
        stored = [None if values[name] is None else str(values[name]) for name in CANONICAL_FIELDS]
        stored.append(json.dumps(values, sort_keys=True))
        placeholders = ",".join("?" for _ in columns)
        with self.connection() as con:
            con.execute(f"INSERT INTO telemetry ({','.join(columns)}) VALUES ({placeholders})", stored)

    def telemetry(self, limit: int = 100, source_type: str | None = None) -> list[dict[str, Any]]:
        query = "SELECT raw_json FROM telemetry"
        params: list[Any] = []
        if source_type:
            query += " WHERE source_type = ?"
            params.append(source_type.upper())
        query += " ORDER BY timestamp DESC, rowid DESC LIMIT ?"
        params.append(max(1, min(limit, 5000)))
        with self.connection() as con:
            rows = con.execute(query, params).fetchall()
        return [json.loads(row["raw_json"]) for row in reversed(rows)]

    def create_incident(self, event: TelemetryEvent, evidence: list[str], affected_resources: str) -> dict[str, Any]:
        incident_id = f"INC-{datetime.now(timezone.utc):%Y%m%d}-{uuid4().hex[:8].upper()}"
        now = utc_now()
        values = {
            "incident_id": incident_id, "created_at": now, "updated_at": now, "event_id": event.event_id,
            "device_id": event.device_id, "source_id": event.source_id, "attack_type": event.attack_type,
            "severity": event.severity, "confidence": event.confidence, "evidence_json": json.dumps(evidence),
            "affected_resources": affected_resources, "energy_impact": event.energy_cause,
            "iam_impact": event.access_decision, "trust_impact": str(event.trust_score),
            "response_action": event.response_action, "response_mode": event.response_mode, "operator": "system",
            "lifecycle_state": "DETECTED", "recovery_state": "PENDING", "resolved_at": None,
            "provenance": event.provenance,
        }
        with self.connection() as con:
            con.execute(
                "INSERT INTO incidents VALUES (:incident_id,:created_at,:updated_at,:event_id,:device_id,:source_id,"
                ":attack_type,:severity,:confidence,:evidence_json,:affected_resources,:energy_impact,:iam_impact,"
                ":trust_impact,:response_action,:response_mode,:operator,:lifecycle_state,:recovery_state,:resolved_at,:provenance)", values)
            con.execute("INSERT INTO incident_history VALUES (?,?,?,?,?,?,?,?)", (
                str(uuid4()), incident_id, now, None, "DETECTED", "system", "Detection opened incident", json.dumps(evidence)))
        return self.incident(incident_id) or values

    def incidents(self, limit: int = 100, severity: str | None = None, state: str | None = None) -> list[dict[str, Any]]:
        clauses, params = [], []
        if severity:
            clauses.append("severity = ?"); params.append(severity.upper())
        if state:
            clauses.append("lifecycle_state = ?"); params.append(state.upper())
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        params.append(max(1, min(limit, 1000)))
        with self.connection() as con:
            rows = con.execute(f"SELECT * FROM incidents{where} ORDER BY created_at DESC LIMIT ?", params).fetchall()
        return [self._incident_row(row) for row in rows]

    def incident(self, incident_id: str) -> dict[str, Any] | None:
        with self.connection() as con:
            row = con.execute("SELECT * FROM incidents WHERE incident_id = ?", (incident_id,)).fetchone()
            history = con.execute("SELECT * FROM incident_history WHERE incident_id = ? ORDER BY timestamp", (incident_id,)).fetchall()
        if not row:
            return None
        result = self._incident_row(row)
        result["history"] = [{**dict(item), "evidence": json.loads(item["evidence_json"])} for item in history]
        return result

    @staticmethod
    def _incident_row(row: sqlite3.Row) -> dict[str, Any]:
        item = dict(row)
        item["evidence"] = json.loads(item.pop("evidence_json"))
        return item

    def find_active_incident(self, device_id: str | None = None, attack_type: str | None = None) -> dict[str, Any] | None:
        """Find an unclosed, unresolved incident matching device_id or attack_type."""
        clauses = ["lifecycle_state NOT IN ('RESOLVED', 'CLOSED')"]
        params: list[Any] = []
        if device_id and attack_type:
            clauses.append("device_id = ? AND attack_type = ?")
            params.extend([device_id, attack_type])
        elif device_id:
            clauses.append("device_id = ?")
            params.append(device_id)
        elif attack_type:
            clauses.append("attack_type = ?")
            params.append(attack_type)
        where = f"WHERE {' AND '.join(clauses)}"
        with self.connection() as con:
            row = con.execute(f"SELECT * FROM incidents {where} ORDER BY updated_at DESC LIMIT 1", params).fetchone()
        return self._incident_row(row) if row else None

    def correlate_incident(self, incident_id: str, event: TelemetryEvent, new_evidence: list[str], note: str = "Correlated ongoing campaign activity") -> dict[str, Any]:
        """Correlate a subsequent telemetry window into an active incident."""
        current = self.incident(incident_id)
        if not current:
            raise KeyError(f"Unknown incident: {incident_id}")
        now = utc_now()
        merged_evidence = list(dict.fromkeys(current.get("evidence", []) + new_evidence))
        severity_rank = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        curr_sev = current.get("severity") or "MEDIUM"
        new_sev = event.severity or "MEDIUM"
        effective_sev = new_sev if severity_rank.get(new_sev, 2) > severity_rank.get(curr_sev, 2) else curr_sev
        effective_conf = max(float(current.get("confidence") or 0.0), float(event.confidence or 0.0))
        with self.connection() as con:
            con.execute(
                "UPDATE incidents SET updated_at=?, event_id=?, severity=?, confidence=?, evidence_json=?, "
                "energy_impact=?, iam_impact=?, trust_impact=?, response_action=? WHERE incident_id=?",
                (now, event.event_id, effective_sev, round(effective_conf, 3), json.dumps(merged_evidence),
                 event.energy_cause or current.get("energy_impact"),
                 event.access_decision or current.get("iam_impact"),
                 str(event.trust_score) if event.trust_score is not None else current.get("trust_impact"),
                 event.response_action or current.get("response_action"),
                 incident_id)
            )
            con.execute(
                "INSERT INTO incident_history VALUES (?,?,?,?,?,?,?,?)",
                (str(uuid4()), incident_id, now, current["lifecycle_state"], current["lifecycle_state"],
                 "system", note, json.dumps(new_evidence))
            )
        return self.incident(incident_id)  # type: ignore[return-value]

    def transition_incident(self, incident_id: str, state: str, actor: str, note: str, evidence: list[str] | None = None) -> dict[str, Any]:
        allowed = {
            "DETECTED": {"TRIAGED", "RESPONDING", "CONTAINED"},
            "TRIAGED": {"RESPONDING", "CONTAINED", "CLOSED"},
            "RESPONDING": {"CONTAINED", "RECOVERING"},
            "CONTAINED": {"RECOVERING", "RESPONDING", "RESOLVED"},
            "RECOVERING": {"RESOLVED", "RESPONDING", "CONTAINED"},
            "RESOLVED": {"CLOSED", "RESPONDING"},
            "CLOSED": {"RESPONDING", "DETECTED"},
        }
        current = self.incident(incident_id)
        if not current:
            raise KeyError(f"Unknown incident: {incident_id}")
        state = state.upper()
        if state == current["lifecycle_state"]:
            return current
        if state not in allowed.get(current["lifecycle_state"], set()):
            raise ValueError(f"Invalid transition {current['lifecycle_state']} -> {state}")
        now = utc_now()
        recovery = "VERIFIED" if state in {"RESOLVED", "CLOSED"} else current["recovery_state"]
        with self.connection() as con:
            con.execute("UPDATE incidents SET lifecycle_state=?, recovery_state=?, updated_at=?, resolved_at=? WHERE incident_id=?", (
                state, recovery, now, now if state == "RESOLVED" else current["resolved_at"], incident_id))
            con.execute("INSERT INTO incident_history VALUES (?,?,?,?,?,?,?,?)", (
                str(uuid4()), incident_id, now, current["lifecycle_state"], state, actor, note, json.dumps(evidence or [])))
        return self.incident(incident_id)  # type: ignore[return-value]

    def record_action(self, *, event_id: str | None, incident_id: str | None, action: str, reason: str, policy: str, mode: str, result: str, provenance: str = "SIMULATED") -> dict[str, Any]:
        item = {"action_id": str(uuid4()), "timestamp": utc_now(), "event_id": event_id, "incident_id": incident_id,
                "action": action, "reason": reason, "policy": policy, "mode": mode, "result": result, "provenance": provenance}
        with self.connection() as con:
            con.execute("INSERT INTO actions VALUES (:action_id,:timestamp,:event_id,:incident_id,:action,:reason,:policy,:mode,:result,:provenance)", item)
        return item

    def actions(self, limit: int = 100) -> list[dict[str, Any]]:
        with self.connection() as con:
            rows = con.execute("SELECT * FROM actions ORDER BY timestamp DESC LIMIT ?", (max(1, min(limit, 1000)),)).fetchall()
        return [dict(row) for row in rows]

    def record_iam(self, item: dict[str, Any]) -> None:
        defaults = {
            "iam_event_id": str(uuid4()),
            "timestamp": utc_now(),
            "identity": None,
            "role": None,
            "authentication_status": "AUTHENTICATED",
            "authorization_status": "AUTHORIZED",
            "access_request": "TELEMETRY_INGEST",
            "decision": "ALLOW",
            "reason": "Normal operational access",
            "provenance": "DERIVED",
        }
        item = {**defaults, **item}
        with self.connection() as con:
            con.execute("INSERT INTO iam_events VALUES (:iam_event_id,:timestamp,:identity,:role,:authentication_status,:authorization_status,:access_request,:decision,:reason,:provenance)", item)

    def record_trust(self, identity: str, score: float, delta: float, reason: str) -> None:
        with self.connection() as con:
            con.execute("INSERT INTO trust_history VALUES (?,?,?,?,?,?,?)", (str(uuid4()), utc_now(), identity, score, delta, reason, "DERIVED"))

    def trust(self, identity: str | None = None, limit: int = 300) -> list[dict[str, Any]]:
        query, params = "SELECT * FROM trust_history", []
        if identity:
            query += " WHERE identity=?"; params.append(identity)
        query += " ORDER BY timestamp DESC LIMIT ?"; params.append(max(1, min(limit, 5000)))
        with self.connection() as con:
            rows = con.execute(query, params).fetchall()
        return [dict(row) for row in reversed(rows)]

    def put_metadata(self, kind: str, version: str, payload: dict[str, Any]) -> None:
        with self.connection() as con:
            con.execute("INSERT INTO metadata VALUES (?,?,?,?,?)", (str(uuid4()), kind, version, utc_now(), json.dumps(payload, sort_keys=True)))

    def latest_metadata(self, kind: str) -> dict[str, Any] | None:
        with self.connection() as con:
            row = con.execute("SELECT * FROM metadata WHERE kind=? ORDER BY created_at DESC LIMIT 1", (kind,)).fetchone()
        if not row:
            return None
        item = dict(row); item["payload"] = json.loads(item.pop("payload_json")); return item

    def prune(self, days: int) -> int:
        cutoff = (datetime.now(timezone.utc) - timedelta(days=max(days, 1))).isoformat()
        with self.connection() as con:
            result = con.execute("DELETE FROM telemetry WHERE timestamp < ?", (cutoff,))
        return result.rowcount

    def export(self, kind: str, fmt: str) -> str:
        if kind == "incidents": rows = self.incidents(limit=1000)
        elif kind in ("telemetry", "events"):
            rows = self.telemetry(limit=5000)
            if kind == "events":
                rows = [r for r in rows if r.get("label") == "ATTACK"]
        elif kind == "actions": rows = self.actions(limit=1000)
        else: raise ValueError("Export kind must be incidents, telemetry, events, or actions")
        if fmt == "json": return json.dumps(rows, indent=2, sort_keys=True)
        if fmt != "csv": raise ValueError("Export format must be csv or json")
        flattened = [{key: json.dumps(value) if isinstance(value, (list, dict)) else value for key, value in row.items()} for row in rows]
        if not flattened: return ""
        result = StringIO(); writer = csv.DictWriter(result, fieldnames=sorted({key for row in flattened for key in row}), extrasaction="ignore")
        writer.writeheader(); writer.writerows(flattened); return result.getvalue()
