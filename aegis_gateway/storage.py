"""Durable local SQLite historian with append-only telemetry/event records."""

from __future__ import annotations

import csv
import hashlib
import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from io import StringIO
from pathlib import Path
from typing import Any, Iterator
from uuid import uuid4

from .schema import CANONICAL_FIELDS, TelemetryEvent, utc_now

GENESIS_HASH = "0" * 64


class GatewayStore:
    def __init__(self, path: Path, master_key: str | None = None):
        self.path = path
        self.master_key = master_key
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.initialize()

    @contextmanager
    def connection(self) -> Iterator[sqlite3.Connection]:
        con = sqlite3.connect(self.path, timeout=10)
        con.row_factory = sqlite3.Row
        # Phase 20 Concurrency and Integrity Pragmas
        con.execute("PRAGMA journal_mode = WAL;")
        con.execute("PRAGMA foreign_keys = ON;")
        con.execute("PRAGMA busy_timeout = 5000;")
        con.execute("PRAGMA synchronous = NORMAL;")
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
                    previous_state TEXT, state TEXT NOT NULL, actor TEXT, note TEXT, evidence_json TEXT NOT NULL,
                    FOREIGN KEY (incident_id) REFERENCES incidents(incident_id) ON DELETE CASCADE
                );
                CREATE INDEX IF NOT EXISTS incident_history_incident_idx ON incident_history(incident_id, timestamp);
                CREATE TABLE IF NOT EXISTS actions (
                    action_id TEXT PRIMARY KEY, timestamp TEXT NOT NULL, event_id TEXT, incident_id TEXT,
                    action TEXT NOT NULL, reason TEXT NOT NULL, policy TEXT NOT NULL, mode TEXT NOT NULL,
                    result TEXT NOT NULL, provenance TEXT NOT NULL,
                    FOREIGN KEY (incident_id) REFERENCES incidents(incident_id) ON DELETE SET NULL
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
                CREATE TABLE IF NOT EXISTS admin_users (
                    user_id TEXT PRIMARY KEY, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL,
                    role TEXT NOT NULL, status TEXT NOT NULL, mfa_enabled INTEGER NOT NULL DEFAULT 1,
                    mfa_status TEXT NOT NULL DEFAULT 'SIMULATED_VERIFIED', created_at TEXT NOT NULL, last_login TEXT
                );
                CREATE INDEX IF NOT EXISTS admin_users_username_idx ON admin_users(username);
                CREATE TABLE IF NOT EXISTS admin_alerts (
                    alert_id TEXT PRIMARY KEY, incident_id TEXT NOT NULL UNIQUE, timestamp TEXT NOT NULL,
                    severity TEXT NOT NULL, attack_type TEXT NOT NULL, device_id TEXT, source_id TEXT,
                    target TEXT NOT NULL, confidence REAL NOT NULL, detection_reason TEXT NOT NULL,
                    lifecycle_state TEXT NOT NULL, recommended_action TEXT NOT NULL, current_action TEXT NOT NULL,
                    acknowledgement_state TEXT NOT NULL DEFAULT 'UNACKNOWLEDGED', acknowledged_by TEXT,
                    acknowledged_at TEXT, status TEXT NOT NULL DEFAULT 'ACTIVE', evidence_json TEXT NOT NULL DEFAULT '[]',
                    FOREIGN KEY (incident_id) REFERENCES incidents(incident_id) ON DELETE CASCADE
                );
                CREATE INDEX IF NOT EXISTS admin_alerts_incident_idx ON admin_alerts(incident_id);
                CREATE INDEX IF NOT EXISTS admin_alerts_status_idx ON admin_alerts(status, acknowledgement_state);
                CREATE TABLE IF NOT EXISTS admin_audit_log (
                    event_id TEXT PRIMARY KEY, timestamp TEXT NOT NULL, username TEXT NOT NULL,
                    role TEXT NOT NULL, action TEXT NOT NULL, resource TEXT NOT NULL, resource_id TEXT,
                    result TEXT NOT NULL, source_ip TEXT, details TEXT NOT NULL,
                    prev_hash TEXT NOT NULL DEFAULT '0000000000000000000000000000000000000000000000000000000000000000',
                    record_hash TEXT NOT NULL DEFAULT ''
                );
                CREATE INDEX IF NOT EXISTS admin_audit_timestamp_idx ON admin_audit_log(timestamp DESC);
                CREATE INDEX IF NOT EXISTS admin_audit_action_idx ON admin_audit_log(action);
                CREATE TABLE IF NOT EXISTS device_identities (
                    device_id TEXT PRIMARY KEY, role TEXT NOT NULL DEFAULT 'sensor',
                    status TEXT NOT NULL DEFAULT 'ENROLLED', auth_key_hash TEXT NOT NULL,
                    trust_score REAL NOT NULL DEFAULT 100.0, failures INTEGER NOT NULL DEFAULT 0,
                    mfa_status TEXT NOT NULL DEFAULT 'NOT_REQUIRED', created_at TEXT NOT NULL,
                    last_seen TEXT
                );
                CREATE INDEX IF NOT EXISTS device_identities_status_idx ON device_identities(status);
                """
            )
            self._migrate_schema(con)
            self._seed_default_users(con)
            self._seed_default_device_identities(con)

    def _migrate_schema(self, con: sqlite3.Connection) -> None:
        """Backward-compatible schema migration for existing databases."""
        audit_cols = [r["name"] for r in con.execute("PRAGMA table_info(admin_audit_log)").fetchall()]
        if "prev_hash" not in audit_cols:
            con.execute(f"ALTER TABLE admin_audit_log ADD COLUMN prev_hash TEXT DEFAULT '{GENESIS_HASH}'")
        if "record_hash" not in audit_cols:
            con.execute("ALTER TABLE admin_audit_log ADD COLUMN record_hash TEXT DEFAULT ''")

        # Migrate unhashed records if present
        unhashed = con.execute("SELECT rowid, * FROM admin_audit_log WHERE record_hash IS NULL OR record_hash = '' ORDER BY rowid ASC").fetchall()
        if unhashed:
            first_rowid = unhashed[0]["rowid"]
            prev_row = con.execute("SELECT record_hash FROM admin_audit_log WHERE rowid < ? AND record_hash != '' ORDER BY rowid DESC LIMIT 1", (first_rowid,)).fetchone()
            curr_prev = str(prev_row["record_hash"]) if prev_row else GENESIS_HASH
            for row in unhashed:
                h = self._compute_audit_hash(
                    prev_hash=curr_prev,
                    event_id=row["event_id"],
                    timestamp=row["timestamp"],
                    username=row["username"],
                    role=row["role"],
                    action=row["action"],
                    resource=row["resource"],
                    resource_id=row["resource_id"],
                    result=row["result"],
                    source_ip=row["source_ip"],
                    details=row["details"],
                )
                con.execute("UPDATE admin_audit_log SET prev_hash = ?, record_hash = ? WHERE rowid = ?", (curr_prev, h, row["rowid"]))
                curr_prev = h

        # Reconcile historical alerts whose parent incidents are already resolved or closed
        con.execute(
            "UPDATE admin_alerts SET status = 'CLOSED', lifecycle_state = 'CLOSED' "
            "WHERE incident_id IN (SELECT incident_id FROM incidents WHERE lifecycle_state = 'CLOSED') AND status != 'CLOSED'"
        )
        con.execute(
            "UPDATE admin_alerts SET status = 'RESOLVED', lifecycle_state = 'RESOLVED' "
            "WHERE incident_id IN (SELECT incident_id FROM incidents WHERE lifecycle_state = 'RESOLVED') AND status NOT IN ('RESOLVED', 'CLOSED')"
        )

    def _seed_default_users(self, con: sqlite3.Connection) -> None:
        from .security import hash_password
        now = utc_now()
        defaults = [
            ("USR-ADMIN-01", "admin", hash_password("Admin@AICG2026!"), "ADMIN", "ACTIVE", 1, "SIMULATED_VERIFIED", now, None),
            ("USR-OPERATOR-01", "operator", hash_password("Operator@AICG2026!"), "OPERATOR", "ACTIVE", 1, "SIMULATED_VERIFIED", now, None),
        ]
        for row in defaults:
            con.execute(
                "INSERT OR IGNORE INTO admin_users (user_id, username, password_hash, role, status, mfa_enabled, mfa_status, created_at, last_login) VALUES (?,?,?,?,?,?,?,?,?)",
                row
            )

    def _seed_default_device_identities(self, con: sqlite3.Connection) -> None:
        from .iam import DEFAULT_MASTER_KEY, derive_device_key, hash_device_key
        now = utc_now()
        devices = [
            ("SENSOR-01", "sensor", "ENROLLED", 100.0, 0, "NOT_REQUIRED"),
            ("SENSOR-02", "sensor", "ENROLLED", 100.0, 0, "NOT_REQUIRED"),
            ("SENSOR-03", "sensor", "ENROLLED", 100.0, 0, "NOT_REQUIRED"),
            ("SENSOR-GROUP-A", "sensor", "ENROLLED", 100.0, 0, "NOT_REQUIRED"),
            ("ATK-01", "untrusted", "REVOKED", 35.0, 0, "FAILED"),
            ("operator", "operator", "ENROLLED", 100.0, 0, "VERIFIED"),
        ]
        eff_key = getattr(self, "master_key", None) or DEFAULT_MASTER_KEY
        for dev_id, role, status, trust, fails, mfa in devices:
            if role == "untrusted":
                h = hash_device_key(f"untrusted-key-{dev_id}")
            else:
                psk = derive_device_key(dev_id, eff_key)
                h = hash_device_key(psk)
            con.execute(
                """
                INSERT OR IGNORE INTO device_identities
                (device_id, role, status, auth_key_hash, trust_score, failures, mfa_status, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (dev_id, role, status, h, trust, fails, mfa, now),
            )

    def append_telemetry(self, event: TelemetryEvent) -> None:
        event.normalize()
        values = event.to_dict()
        values.pop("auth_token", None)
        columns = CANONICAL_FIELDS + ["raw_json"]
        stored = [None if values.get(name) is None else str(values[name]) for name in CANONICAL_FIELDS]
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

        prev_state = current["lifecycle_state"]
        if prev_state == "RECOVERING":
            effective_state = "CONTAINED"
            history_note = "Attack activity resumed during recovery verification; state regressed from RECOVERING to CONTAINED."
        else:
            effective_state = prev_state
            history_note = note

        with self.connection() as con:
            con.execute(
                "UPDATE incidents SET updated_at=?, event_id=?, severity=?, confidence=?, evidence_json=?, "
                "energy_impact=?, iam_impact=?, trust_impact=?, response_action=?, lifecycle_state=? WHERE incident_id=?",
                (now, event.event_id, effective_sev, round(effective_conf, 3), json.dumps(merged_evidence),
                 event.energy_cause or current.get("energy_impact"),
                 event.access_decision or current.get("iam_impact"),
                 str(event.trust_score) if event.trust_score is not None else current.get("trust_impact"),
                 event.response_action or current.get("response_action"),
                 effective_state,
                 incident_id)
            )
            con.execute(
                "INSERT INTO incident_history (history_id, incident_id, timestamp, previous_state, state, actor, note, evidence_json) "
                "VALUES (?,?,?,?,?,?,?,?)",
                (str(uuid4()), incident_id, now, prev_state, effective_state,
                 "system", history_note, json.dumps(new_evidence))
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
            alert_status = "RESOLVED" if state == "RESOLVED" else ("CLOSED" if state == "CLOSED" else "ACTIVE")
            con.execute(
                "UPDATE admin_alerts SET lifecycle_state = ?, status = ?, timestamp = ? WHERE incident_id = ?",
                (state, alert_status, now, incident_id)
            )
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
        item.pop("auth_token", None)
        with self.connection() as con:
            con.execute("INSERT INTO iam_events VALUES (:iam_event_id,:timestamp,:identity,:role,:authentication_status,:authorization_status,:access_request,:decision,:reason,:provenance)", item)

    def record_trust(self, identity: str, score: float, delta: float, reason: str) -> None:
        with self.connection() as con:
            con.execute("INSERT INTO trust_history VALUES (?,?,?,?,?,?,?)", (str(uuid4()), utc_now(), identity, score, delta, reason, "DERIVED"))

    def trust(self, identity: str | None = None, limit: int = 300) -> list[dict[str, Any]]:
        query, params = "SELECT * FROM trust_history", []
        if identity:
            query += " WHERE identity=?"; params.append(identity)
        query += " ORDER BY timestamp DESC, rowid DESC LIMIT ?"; params.append(max(1, min(limit, 5000)))
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
        if kind == "incidents":
            rows = self.incidents(limit=1000)
        elif kind in ("telemetry", "events"):
            rows = self.telemetry(limit=5000)
            if kind == "events":
                rows = [r for r in rows if r.get("label") == "ATTACK"]
        elif kind == "actions":
            rows = self.actions(limit=1000)
        elif kind == "audit":
            rows = self.list_audit_logs(limit=1000)
        elif kind == "alerts":
            raw_alerts = self.list_alerts(limit=1000)
            rows = []
            for alert in raw_alerts:
                item = dict(alert)
                if "evidence" in item and "evidence_json" not in item:
                    item["evidence_json"] = json.dumps(item["evidence"]) if isinstance(item["evidence"], (list, dict)) else str(item["evidence"])
                rows.append(item)
        else:
            raise ValueError("Export kind must be incidents, telemetry, events, actions, audit, or alerts")

        if fmt == "json":
            return json.dumps(rows, indent=2, sort_keys=True)
        if fmt != "csv":
            raise ValueError("Export format must be csv or json")
        flattened = [{key: json.dumps(value) if isinstance(value, (list, dict)) else value for key, value in row.items()} for row in rows]
        if not flattened:
            return ""
        result = StringIO()
        writer = csv.DictWriter(result, fieldnames=sorted({key for row in flattened for key in row}), extrasaction="ignore")
        writer.writeheader()
        writer.writerows(flattened)
        return result.getvalue()

    # =========================================================================
    # ADMINISTRATIVE USER IDENTITY REGISTRY (LOCAL LAB)
    # =========================================================================

    def get_admin_user(self, username: str) -> dict[str, Any] | None:
        with self.connection() as con:
            row = con.execute("SELECT * FROM admin_users WHERE username = ?", (username,)).fetchone()
        return dict(row) if row else None

    def get_admin_user_by_id(self, user_id: str) -> dict[str, Any] | None:
        with self.connection() as con:
            row = con.execute("SELECT * FROM admin_users WHERE user_id = ?", (user_id,)).fetchone()
        return dict(row) if row else None

    def list_admin_users(self) -> list[dict[str, Any]]:
        with self.connection() as con:
            rows = con.execute("SELECT user_id, username, role, status, mfa_enabled, mfa_status, created_at, last_login FROM admin_users ORDER BY created_at ASC").fetchall()
        return [dict(row) for row in rows]

    def create_admin_user(self, username: str, password_hash: str, role: str, status: str = "ACTIVE", mfa_enabled: int = 1) -> dict[str, Any]:
        user_id = f"USR-{uuid4().hex[:8].upper()}"
        now = utc_now()
        with self.connection() as con:
            con.execute(
                "INSERT INTO admin_users (user_id, username, password_hash, role, status, mfa_enabled, mfa_status, created_at, last_login) VALUES (?,?,?,?,?,?,?,?,?)",
                (user_id, username, password_hash, role.upper(), status.upper(), mfa_enabled, "SIMULATED_VERIFIED", now, None)
            )
        return {
            "user_id": user_id,
            "username": username,
            "role": role.upper(),
            "status": status.upper(),
            "mfa_enabled": mfa_enabled,
            "mfa_status": "SIMULATED_VERIFIED",
            "created_at": now,
            "last_login": None,
        }

    def update_admin_user_status(self, user_id: str, status: str) -> dict[str, Any]:
        status = status.upper()
        if status not in {"ACTIVE", "DISABLED"}:
            raise ValueError(f"Invalid status: {status}")
        with self.connection() as con:
            con.execute("UPDATE admin_users SET status = ? WHERE user_id = ?", (status, user_id))
        user = self.get_admin_user_by_id(user_id)
        if not user:
            raise KeyError(f"User not found: {user_id}")
        user.pop("password_hash", None)
        return user

    def update_admin_user_role(self, user_id: str, role: str) -> dict[str, Any]:
        role = role.upper()
        if role not in {"ADMIN", "OPERATOR"}:
            raise ValueError(f"Invalid role: {role}")
        with self.connection() as con:
            con.execute("UPDATE admin_users SET role = ? WHERE user_id = ?", (role, user_id))
        user = self.get_admin_user_by_id(user_id)
        if not user:
            raise KeyError(f"User not found: {user_id}")
        user.pop("password_hash", None)
        return user

    def record_admin_login(self, username: str) -> None:
        now = utc_now()
        with self.connection() as con:
            con.execute("UPDATE admin_users SET last_login = ? WHERE username = ?", (now, username))

    # =========================================================================
    # ADMINISTRATIVE SECURITY ALERTS & ALERT CENTER
    # =========================================================================

    def _alert_row(self, row: sqlite3.Row) -> dict[str, Any]:
        item = dict(row)
        try:
            item["evidence"] = json.loads(item.pop("evidence_json", "[]"))
        except Exception:
            item["evidence"] = []
        return item

    def get_alert(self, alert_id: str) -> dict[str, Any] | None:
        with self.connection() as con:
            row = con.execute("SELECT * FROM admin_alerts WHERE alert_id = ?", (alert_id,)).fetchone()
        return self._alert_row(row) if row else None

    def get_alert_by_incident(self, incident_id: str) -> dict[str, Any] | None:
        with self.connection() as con:
            row = con.execute("SELECT * FROM admin_alerts WHERE incident_id = ?", (incident_id,)).fetchone()
        return self._alert_row(row) if row else None

    def create_or_update_alert(
        self,
        incident: dict[str, Any],
        event: TelemetryEvent | dict[str, Any] | None = None,
        decision: Any = None,
        plan: Any = None
    ) -> dict[str, Any]:
        incident_id = incident["incident_id"]
        existing = self.get_alert_by_incident(incident_id)

        severity_rank = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        now = utc_now()

        # Evidence
        new_evidence = []
        if decision and hasattr(decision, "evidence") and decision.evidence:
            new_evidence = list(decision.evidence)
        elif incident.get("evidence"):
            new_evidence = list(incident["evidence"])

        # Determine severity
        inc_sev = (incident.get("severity") or "MEDIUM").upper()
        evt_sev = (getattr(event, "severity", None) or (event.get("severity") if isinstance(event, dict) else None) or "MEDIUM").upper()
        effective_sev = inc_sev if severity_rank.get(inc_sev, 2) >= severity_rank.get(evt_sev, 2) else evt_sev

        conf = float(incident.get("confidence") or (getattr(decision, "confidence", None) or 0.95))
        act = (getattr(plan, "action", None) or incident.get("response_action") or "ISOLATE")

        if existing:
            # Update existing alert (NO duplicates!)
            prev_sev = existing.get("severity", "MEDIUM")
            is_escalation = (
                severity_rank.get(effective_sev, 2) > severity_rank.get(prev_sev, 2)
                or (existing.get("lifecycle_state") == "RECOVERING" and severity_rank.get(effective_sev, 2) >= 2)
            )
            if severity_rank.get(effective_sev, 2) < severity_rank.get(prev_sev, 2):
                effective_sev = prev_sev
            effective_conf = max(float(existing.get("confidence") or 0.0), conf)
            merged_evidence = list(dict.fromkeys(existing.get("evidence", []) + new_evidence))
            new_state = incident.get("lifecycle_state") or existing.get("lifecycle_state", "DETECTED")
            new_status = "RESOLVED" if new_state == "RESOLVED" else ("CLOSED" if new_state == "CLOSED" else existing.get("status", "ACTIVE"))

            # Alert Re-escalation: If previously acknowledged and severity escalated, shift to RE_ESCALATED
            ack_state = existing.get("acknowledgement_state", "UNACKNOWLEDGED")
            if is_escalation and ack_state == "ACKNOWLEDGED":
                ack_state = "RE_ESCALATED"
                self.record_audit(
                    username="system",
                    role="SYSTEM",
                    action="ALERT_RE_ESCALATED",
                    resource="alert",
                    resource_id=existing["alert_id"],
                    result="SUCCESS",
                    details=f"Alert {existing['alert_id']} re-escalated from {prev_sev} to {effective_sev} due to intensified attack activity",
                    source_ip="127.0.0.1",
                )

            with self.connection() as con:
                con.execute(
                    "UPDATE admin_alerts SET timestamp = ?, severity = ?, confidence = ?, lifecycle_state = ?, "
                    "current_action = ?, status = ?, acknowledgement_state = ?, evidence_json = ? WHERE alert_id = ?",
                    (
                        now,
                        effective_sev,
                        round(effective_conf, 3),
                        new_state,
                        f"{act} (DRY_RUN)",
                        new_status,
                        ack_state,
                        json.dumps(merged_evidence),
                        existing["alert_id"],
                    )
                )
            return self.get_alert(existing["alert_id"])  # type: ignore[return-value]

        # Generate new alert for this incident
        alert_id = f"ALT-{datetime.now(timezone.utc):%Y%m%d}-{uuid4().hex[:6].upper()}"
        attack_type = incident.get("attack_type") or (getattr(event, "attack_type", None) if event else "ANOMALY") or "ANOMALY"
        dev_id = incident.get("device_id") or (getattr(event, "device_id", None) if event else None) or "SENSOR-01"
        src_id = incident.get("source_id") or (getattr(event, "source_id", None) if event else None)
        reason = new_evidence[0] if new_evidence else f"Automated detection of {attack_type} campaign"
        state = incident.get("lifecycle_state") or "DETECTED"
        status = "RESOLVED" if state == "RESOLVED" else ("CLOSED" if state == "CLOSED" else "ACTIVE")

        with self.connection() as con:
            con.execute(
                "INSERT INTO admin_alerts (alert_id, incident_id, timestamp, severity, attack_type, device_id, "
                "source_id, target, confidence, detection_reason, lifecycle_state, recommended_action, "
                "current_action, acknowledgement_state, acknowledged_by, acknowledged_at, status, evidence_json) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    alert_id,
                    incident_id,
                    now,
                    effective_sev,
                    attack_type,
                    dev_id,
                    src_id,
                    "AICG-GW-01 / OT Cell",
                    round(conf, 3),
                    reason,
                    state,
                    f"{act} (DRY_RUN)",
                    f"{act} (DRY_RUN)",
                    "UNACKNOWLEDGED",
                    None,
                    None,
                    status,
                    json.dumps(new_evidence),
                )
            )
        return self.get_alert(alert_id)  # type: ignore[return-value]

    def sync_alert_with_incident(self, incident: dict[str, Any]) -> dict[str, Any] | None:
        existing = self.get_alert_by_incident(incident["incident_id"])
        if not existing:
            return None
        new_state = incident.get("lifecycle_state") or existing["lifecycle_state"]
        new_status = "RESOLVED" if new_state == "RESOLVED" else ("CLOSED" if new_state == "CLOSED" else "ACTIVE")
        now = utc_now()
        with self.connection() as con:
            con.execute(
                "UPDATE admin_alerts SET lifecycle_state = ?, status = ?, timestamp = ? WHERE alert_id = ?",
                (new_state, new_status, now, existing["alert_id"])
            )
        return self.get_alert(existing["alert_id"])

    def acknowledge_alert(self, alert_id: str, username: str) -> dict[str, Any]:
        existing = self.get_alert(alert_id)
        if not existing:
            raise KeyError(f"Unknown alert: {alert_id}")
        now = utc_now()
        with self.connection() as con:
            con.execute(
                "UPDATE admin_alerts SET acknowledgement_state = 'ACKNOWLEDGED', acknowledged_by = ?, acknowledged_at = ? WHERE alert_id = ?",
                (username, now, alert_id)
            )
        return self.get_alert(alert_id)  # type: ignore[return-value]

    def list_alerts(
        self,
        limit: int = 100,
        status: str | None = None,
        ack_state: str | None = None,
        severity: str | None = None
    ) -> list[dict[str, Any]]:
        clauses, params = [], []
        if status:
            clauses.append("status = ?")
            params.append(status.upper())
        if ack_state:
            clauses.append("acknowledgement_state = ?")
            params.append(ack_state.upper())
        if severity:
            clauses.append("severity = ?")
            params.append(severity.upper())
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        params.append(max(1, min(limit, 1000)))
        with self.connection() as con:
            rows = con.execute(f"SELECT * FROM admin_alerts{where} ORDER BY timestamp DESC LIMIT ?", params).fetchall()
        return [self._alert_row(row) for row in rows]

    # =========================================================================
    # ADMINISTRATIVE AUDIT LOG
    # =========================================================================

    def record_audit(
        self,
        username: str,
        role: str,
        action: str,
        resource: str,
        resource_id: str | None = None,
        result: str = "SUCCESS",
        details: str = "",
        source_ip: str | None = None
    ) -> dict[str, Any]:
        event_id = f"AUD-{datetime.now(timezone.utc):%Y%m%d}-{uuid4().hex[:8].upper()}"
        now = utc_now()
        # Security sanitization: never store passwords or authorization tokens
        safe_details = str(details)
        for keyword in ["password", "token", "hash", "secret"]:
            if keyword in safe_details.lower() and "=" in safe_details:
                import re
                safe_details = re.sub(rf"{keyword}\s*=\s*[^\s,]+", f"{keyword}=[REDACTED]", safe_details, flags=re.IGNORECASE)

        item = {
            "event_id": event_id,
            "timestamp": now,
            "username": username or "system",
            "role": (role or "UNKNOWN").upper(),
            "action": action.upper(),
            "resource": resource,
            "resource_id": resource_id,
            "result": result.upper(),
            "source_ip": source_ip or "127.0.0.1",
            "details": safe_details,
        }
        with self.connection() as con:
            last_row = con.execute("SELECT record_hash FROM admin_audit_log ORDER BY rowid DESC LIMIT 1").fetchone()
            prev_hash = str(last_row["record_hash"]) if (last_row and last_row["record_hash"]) else GENESIS_HASH
            record_hash = self._compute_audit_hash(
                prev_hash=prev_hash,
                event_id=event_id,
                timestamp=now,
                username=username or "system",
                role=(role or "UNKNOWN").upper(),
                action=action.upper(),
                resource=resource,
                resource_id=resource_id,
                result=result.upper(),
                source_ip=source_ip or "127.0.0.1",
                details=safe_details,
            )
            item["prev_hash"] = prev_hash
            item["record_hash"] = record_hash
            con.execute(
                "INSERT INTO admin_audit_log (event_id, timestamp, username, role, action, resource, resource_id, result, source_ip, details, prev_hash, record_hash) "
                "VALUES (:event_id, :timestamp, :username, :role, :action, :resource, :resource_id, :result, :source_ip, :details, :prev_hash, :record_hash)",
                item
            )
        return item

    def _compute_audit_hash(
        self,
        prev_hash: str,
        event_id: str,
        timestamp: str,
        username: str,
        role: str,
        action: str,
        resource: str,
        resource_id: str | None,
        result: str,
        source_ip: str | None,
        details: str,
    ) -> str:
        """Deterministic canonical string serialization for cryptographic hash chaining."""
        canonical_repr = (
            f"{prev_hash}|{event_id}|{timestamp}|{username}|{role}|{action}|"
            f"{resource}|{resource_id or ''}|{result}|{source_ip or ''}|{details}"
        )
        return hashlib.sha256(canonical_repr.encode("utf-8")).hexdigest()

    def verify_audit_log_integrity(self) -> dict[str, Any]:
        """Verify the cryptographic forward integrity of the audit log hash chain."""
        with self.connection() as con:
            rows = con.execute("SELECT rowid, * FROM admin_audit_log ORDER BY rowid ASC").fetchall()

        if not rows:
            return {"valid": True, "count": 0, "first_corrupted_id": None, "reason": None}

        expected_prev = GENESIS_HASH
        for idx, row in enumerate(rows):
            event_id = row["event_id"]
            prev_hash = row["prev_hash"]
            record_hash = row["record_hash"]

            if prev_hash != expected_prev:
                return {
                    "valid": False,
                    "count": len(rows),
                    "corrupted_index": idx,
                    "first_corrupted_id": event_id,
                    "reason": f"Broken chain at record {event_id}: expected prev_hash {expected_prev}, got {prev_hash}",
                }

            computed = self._compute_audit_hash(
                prev_hash=prev_hash,
                event_id=event_id,
                timestamp=row["timestamp"],
                username=row["username"],
                role=row["role"],
                action=row["action"],
                resource=row["resource"],
                resource_id=row["resource_id"],
                result=row["result"],
                source_ip=row["source_ip"],
                details=row["details"],
            )
            if computed != record_hash:
                return {
                    "valid": False,
                    "count": len(rows),
                    "corrupted_index": idx,
                    "first_corrupted_id": event_id,
                    "reason": f"Hash mismatch at record {event_id}: expected {computed}, got {record_hash}",
                }
            expected_prev = record_hash

        return {"valid": True, "count": len(rows), "first_corrupted_id": None, "reason": None}

    def list_audit_logs(
        self,
        limit: int = 100,
        action: str | None = None,
        username: str | None = None
    ) -> list[dict[str, Any]]:
        clauses, params = [], []
        if action:
            clauses.append("action = ?")
            params.append(action.upper())
        if username:
            clauses.append("username = ?")
            params.append(username)
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        params.append(max(1, min(limit, 1000)))
        with self.connection() as con:
            rows = con.execute(f"SELECT * FROM admin_audit_log{where} ORDER BY timestamp DESC LIMIT ?", params).fetchall()
        return [dict(row) for row in rows]

    # =========================================================================
    # PERSISTENT ZERO-TRUST DEVICE IDENTITY REGISTRY
    # =========================================================================

    def get_device_identity(self, device_id: str) -> dict[str, Any] | None:
        with self.connection() as con:
            row = con.execute("SELECT * FROM device_identities WHERE device_id = ?", (device_id,)).fetchone()
        return dict(row) if row else None

    def list_device_identities(self, status: str | None = None) -> list[dict[str, Any]]:
        query = "SELECT * FROM device_identities"
        params: list[Any] = []
        if status:
            query += " WHERE status = ?"
            params.append(status.upper())
        query += " ORDER BY device_id ASC"
        with self.connection() as con:
            rows = con.execute(query, params).fetchall()
        return [dict(row) for row in rows]

    def upsert_device_identity(
        self,
        device_id: str,
        role: str = "sensor",
        auth_key_hash: str = "",
        status: str = "ENROLLED",
        trust_score: float = 100.0,
        failures: int = 0,
        mfa_status: str = "NOT_REQUIRED",
    ) -> dict[str, Any]:
        now = utc_now()
        with self.connection() as con:
            con.execute(
                """
                INSERT INTO device_identities (device_id, role, status, auth_key_hash, trust_score, failures, mfa_status, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(device_id) DO UPDATE SET
                    role = excluded.role,
                    status = excluded.status,
                    auth_key_hash = CASE WHEN excluded.auth_key_hash != '' THEN excluded.auth_key_hash ELSE device_identities.auth_key_hash END,
                    trust_score = excluded.trust_score,
                    failures = excluded.failures,
                    mfa_status = excluded.mfa_status
                """,
                (device_id, role.lower(), status.upper(), auth_key_hash, trust_score, failures, mfa_status, now),
            )
        return self.get_device_identity(device_id) or {}

    def update_device_trust(self, device_id: str, score: float, failures: int | None = None) -> None:
        with self.connection() as con:
            if failures is not None:
                con.execute("UPDATE device_identities SET trust_score = ?, failures = ? WHERE device_id = ?", (score, failures, device_id))
            else:
                con.execute("UPDATE device_identities SET trust_score = ? WHERE device_id = ?", (score, device_id))

    def update_device_last_seen(self, device_id: str, timestamp: str | None = None) -> None:
        ts = timestamp or utc_now()
        with self.connection() as con:
            con.execute("UPDATE device_identities SET last_seen = ? WHERE device_id = ?", (ts, device_id))

    def set_device_status(self, device_id: str, status: str) -> dict[str, Any] | None:
        with self.connection() as con:
            con.execute("UPDATE device_identities SET status = ? WHERE device_id = ?", (status.upper(), device_id))
        return self.get_device_identity(device_id)


StorageHistorian = GatewayStore
