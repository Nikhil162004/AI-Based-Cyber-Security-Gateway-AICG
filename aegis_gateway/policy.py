"""Policy planner: actions are recorded simulations, never host enforcement."""

from __future__ import annotations

from dataclasses import dataclass

from .detection import Decision
from .schema import TelemetryEvent


@dataclass
class ResponsePlan:
    action: str
    reason: str
    mode: str
    result: str
    requires_incident: bool


class ResponseEngine:
    def __init__(self, mode: str = "DRY_RUN", auto: bool = True):
        self.mode = mode.upper()
        self.auto = auto
        self.simulated_isolates: set[str] = set()

    def plan(self, event: TelemetryEvent, decision: Decision) -> ResponsePlan:
        if decision.prediction == "NORMAL":
            return ResponsePlan("ALERT", "No containment needed; baseline observation recorded.", self.mode, "NOT_APPLIED", False)
        if not self.auto or self.mode == "MANUAL":
            return ResponsePlan("ALERT", "Manual approval required by response policy.", "MANUAL", "PENDING_OPERATOR", True)
        if decision.severity == "CRITICAL": action = "ISOLATE"
        elif event.attack_type in {"syn_flood", "slow_rate"}: action = "RATE_LIMIT"
        else: action = "BLOCK"
        return ResponsePlan(action, "Hybrid detection threshold reached; simulated response only.", self.mode, "SIMULATED_NOT_ENFORCED", True)

    def apply_simulation(self, plan: ResponsePlan, device_id: str | None) -> None:
        if plan.action == "ISOLATE" and device_id and plan.mode != "MANUAL":
            self.simulated_isolates.add(device_id)
        if plan.action == "RECOVER" and device_id:
            self.simulated_isolates.discard(device_id)
