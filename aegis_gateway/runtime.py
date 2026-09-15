"""Single source→ingest→detect→incident→response gateway runtime."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
import queue
import threading
import time
from typing import Any, Iterator

from .config import Settings
from .detection import HybridDetector
from .energy import EnergyModel
from .iam import IAMService
from .policy import ResponseEngine
from .scenarios import CATALOGUE, generate_window
from .schema import TelemetryEvent
from .storage import GatewayStore


@dataclass
class SimulationState:
    scenario_id: str
    intensity: int
    started_at: float
    stop: threading.Event
    thread: threading.Thread
    windows: int = 0


class GatewayRuntime:
    """Thread-safe runtime; no code path configures firewall/routing/NIC policy."""

    def __init__(self, settings: Settings | None = None):
        self.settings = settings or Settings()
        self.settings.ensure_directories()
        self.store = GatewayStore(self.settings.database_path)
        self.detector = HybridDetector(self.settings.model_path)
        self.energy = EnergyModel()
        self.iam = IAMService()
        self.response = ResponseEngine(self.settings.response_mode, self.settings.auto_response)
        self._subscribers: set[queue.Queue[dict[str, Any]]] = set()
        self._lock = threading.RLock()
        self._simulations: dict[str, SimulationState] = {}
        self._recent: deque[dict[str, Any]] = deque(maxlen=120)
        self._normal_streak = 0

    def publish(self, kind: str, data: dict[str, Any]) -> None:
        message = {"type": kind, "data": data}
        self._recent.append(message)
        with self._lock:
            stale: list[queue.Queue[dict[str, Any]]] = []
            for subscriber in self._subscribers:
                try: subscriber.put_nowait(message)
                except queue.Full: stale.append(subscriber)
            for subscriber in stale: self._subscribers.discard(subscriber)

    def subscribe(self) -> Iterator[dict[str, Any]]:
        subscriber: queue.Queue[dict[str, Any]] = queue.Queue(maxsize=100)
        with self._lock: self._subscribers.add(subscriber)
        try:
            yield {"type": "status", "data": self.status()}
            while True:
                try: yield subscriber.get(timeout=15)
                except queue.Empty: yield {"type": "keepalive", "data": {}}
        finally:
            with self._lock: self._subscribers.discard(subscriber)

    def configure_response(self, mode: str | None = None, auto: bool | None = None) -> dict[str, Any]:
        if mode is not None:
            self.response.mode = mode.upper()
        if auto is not None:
            self.response.auto = bool(auto)
        return {"mode": self.response.mode, "auto": self.response.auto}

    def ingest(self, event: TelemetryEvent | dict[str, Any]) -> dict[str, Any]:
        """Normalize and retain a source observation, returning evidence-backed result."""
        item = event if isinstance(event, TelemetryEvent) else TelemetryEvent.from_mapping(event)
        item.normalize()
        self.energy.correlate(item)
        decision = self.detector.analyze(item)
        identity, delta, trust_reason = self.iam.adjust_trust(item.device_id or item.source_id, attack=decision.prediction == "ATTACK", recovered=decision.prediction == "NORMAL")
        access = self.iam.access(identity.identity)
        item.label = decision.prediction
        item.confidence = decision.confidence
        item.model_version = decision.model_version
        item.feature_version = decision.feature_version
        item.severity = decision.severity
        item.iam_identity, item.role = identity.identity, identity.role
        item.authentication_status, item.authorization_status = access["authentication_status"], access["authorization_status"]
        item.access_request, item.access_decision, item.trust_score = access["access_request"], access["decision"], identity.trust_score
        plan = self.response.plan(item, decision)
        item.response_action, item.response_mode = plan.action, plan.mode
        item.lifecycle_state = "DETECTED" if plan.requires_incident else "OBSERVED"
        self.store.append_telemetry(item)
        self.store.record_iam(access)
        if delta:
            self.store.record_trust(identity.identity, identity.trust_score, delta, trust_reason)
            self.publish("trust", {"identity": identity.identity, "score": identity.trust_score, "delta": delta, "reason": trust_reason, "provenance": "DERIVED"})

        incident = None
        if plan.requires_incident:
            active = self.store.find_active_incident(device_id=item.device_id, attack_type=item.attack_type)
            if active:
                incident = self.store.correlate_incident(
                    active["incident_id"],
                    item,
                    decision.evidence,
                    "Ongoing campaign correlated across observation windows"
                )
            else:
                incident = self.store.create_incident(item, decision.evidence, "CPU/RAM/radio/energy are model-correlated")
                if plan.mode != "MANUAL":
                    self.response.apply_simulation(plan, item.device_id)
                    incident = self.store.transition_incident(incident["incident_id"], "RESPONDING", "system", "Simulated response planned; no host enforcement.", decision.evidence)
                    incident = self.store.transition_incident(incident["incident_id"], "CONTAINED", "system", "Containment state is simulated within the laboratory runtime.", decision.evidence)
            self.store.record_action(event_id=item.event_id, incident_id=incident["incident_id"], action=plan.action, reason=plan.reason, policy="hybrid-response-v1", mode=plan.mode, result=plan.result)
            self.publish("incident", incident)
            self.publish("response", {"incident_id": incident["incident_id"], **plan.__dict__, "provenance": "SIMULATED"})
            self._normal_streak = 0
        else:
            self._normal_streak += 1
            self._verify_recovery()
        result = {"event": item.to_dict(), "decision": decision.as_dict(), "response": plan.__dict__, "incident": incident}
        self.publish("telemetry", result)
        return result

    def _verify_recovery(self) -> None:
        """Advance recovery only after actual consecutive normal runtime observations."""
        if self._normal_streak < 3:
            return
        for incident in self.store.incidents(limit=100):
            state = incident["lifecycle_state"]
            try:
                if state in {"CONTAINED", "RESPONDING", "DETECTED"}:
                    updated = self.store.transition_incident(
                        incident["incident_id"],
                        "RECOVERING",
                        "system",
                        f"Consecutive normal observations (streak={self._normal_streak}) verified traffic/resource recovery.",
                        ["traffic returned toward modeled baseline"]
                    )
                    self.publish("incident", updated)
                elif state == "RECOVERING" and self._normal_streak >= 5:
                    updated = self.store.transition_incident(
                        incident["incident_id"],
                        "RESOLVED",
                        "system",
                        f"Recovery verified from sustained normal baseline ({self._normal_streak} normal windows).",
                        ["sustained normal observations verified"]
                    )
                    self.publish("incident", updated)
            except (ValueError, KeyError):
                continue

    def start_simulation(self, scenario_id: str, intensity: int = 3, duration: float | None = None) -> dict[str, Any]:
        """Start a bounded in-process profile; it sends no network traffic."""
        if scenario_id not in CATALOGUE:
            raise KeyError(f"Unknown scenario: {scenario_id}")
        if scenario_id in self._simulations:
            raise ValueError(f"Simulation already running: {scenario_id}")
        stop = threading.Event()
        state_ref: list[SimulationState] = []

        def run() -> None:
            sequence = 0
            started = time.monotonic()
            try:
                while not stop.is_set() and (duration is None or time.monotonic() - started < duration):
                    result = self.ingest(generate_window(scenario_id, intensity, sequence))
                    state_ref[0].windows += 1
                    sequence += 1
                    stop.wait(self.settings.demo_tick_seconds)
            finally:
                with self._lock: self._simulations.pop(scenario_id, None)
                self.publish("simulation", {"scenario_id": scenario_id, "state": "STOPPED", "windows": sequence, "provenance": "SIMULATED"})

        thread = threading.Thread(target=run, name=f"aegis-{scenario_id}", daemon=True)
        state = SimulationState(scenario_id, max(1, min(intensity, 6)), time.time(), stop, thread)
        state_ref.append(state)
        with self._lock: self._simulations[scenario_id] = state
        thread.start()
        payload = {"scenario_id": scenario_id, "intensity": state.intensity, "duration": duration, "state": "RUNNING", "provenance": "SIMULATED", "network_transmission": False}
        self.publish("simulation", payload)
        return payload

    def stop_simulation(self, scenario_id: str | None = None) -> list[str]:
        with self._lock:
            targets = [scenario_id] if scenario_id else list(self._simulations)
            states = [self._simulations[name] for name in targets if name in self._simulations]
        for state in states: state.stop.set()
        return [state.scenario_id for state in states]

    def manual_action(self, incident_id: str, action: str, actor: str = "operator") -> dict[str, Any]:
        action = action.upper()
        if action not in {"ALERT", "BLOCK", "RATE_LIMIT", "ISOLATE", "RECOVER"}:
            raise ValueError("Unsupported response action")
        incident = self.store.incident(incident_id)
        if not incident: raise KeyError(f"Unknown incident: {incident_id}")
        if action == "RECOVER":
            if incident["lifecycle_state"] == "CONTAINED":
                incident = self.store.transition_incident(incident_id, "RECOVERING", actor, "Operator requested recovery verification; waiting for observable normal state.")
            result = "PENDING_OBSERVABLE_VERIFICATION"
        else:
            if incident["lifecycle_state"] in {"DETECTED", "TRIAGED"}:
                incident = self.store.transition_incident(incident_id, "RESPONDING", actor, f"Operator selected simulated {action}.")
            if incident["lifecycle_state"] == "RESPONDING":
                incident = self.store.transition_incident(incident_id, "CONTAINED", actor, "Manual containment is simulated; no host policy changed.")
            result = "SIMULATED_NOT_ENFORCED"
        stored = self.store.record_action(event_id=incident["event_id"], incident_id=incident_id, action=action, reason="operator request", policy="manual-response-v1", mode="MANUAL", result=result)
        self.publish("response", stored); self.publish("incident", incident)
        return {"action": stored, "incident": incident}

    def start_baseline(self, tick_seconds: float | None = None) -> None:
        """Continuously generate legitimate baseline OT traffic windows when no attack simulation is active."""
        if hasattr(self, "_baseline_thread") and self._baseline_thread and self._baseline_thread.is_alive():
            return
        self._baseline_stop = threading.Event()
        interval = tick_seconds or self.settings.demo_tick_seconds

        def run() -> None:
            sequence = 0
            while not self._baseline_stop.is_set():
                with self._lock:
                    active_sims = bool(self._simulations)
                if not active_sims:
                    try:
                        self.ingest(generate_window("normal", intensity=1, sequence=sequence))
                        sequence += 1
                    except Exception:
                        pass
                self._baseline_stop.wait(interval)

        self._baseline_thread = threading.Thread(target=run, name="aegis-live-baseline", daemon=True)
        self._baseline_thread.start()

    def stop_baseline(self) -> None:
        """Stop the background baseline telemetry generator."""
        if hasattr(self, "_baseline_stop") and self._baseline_stop:
            self._baseline_stop.set()

    def status(self) -> dict[str, Any]:
        latest = self.store.telemetry(limit=1)
        return {
            "service": "AEGIS-OT laboratory gateway", "status": "ONLINE", "source_modes": ["SIMULATED", "SYNTHETIC", "REPLAYED", "MEASURED (opt-in capture)"],
            "response_mode": self.response.mode, "auto_response": self.response.auto, "host_enforcement": False,
            "latest": latest[-1] if latest else None, "active_simulations": [{"scenario_id": state.scenario_id, "intensity": state.intensity, "windows": state.windows} for state in self._simulations.values()],
            "model_version": self.detector.model_version, "feature_version": "window-features-v2", "database": str(self.settings.database_path),
        }
