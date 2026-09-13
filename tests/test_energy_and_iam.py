"""Tests for cause-based energy model, IAM access decisions, and dynamic trust governance."""

from aegis_gateway.energy import EnergyModel
from aegis_gateway.iam import IAMService
from aegis_gateway.scenarios import generate_window


def test_energy_correlation_normal_vs_attack():
    model = EnergyModel()
    norm_event = generate_window("normal", intensity=1, sequence=0)
    model.correlate(norm_event)

    assert norm_event.resource_state == "NORMAL"
    assert norm_event.energy_rate is not None
    assert norm_event.energy_deviation is not None
    assert norm_event.energy_cause.startswith("MODELLED:")
    assert norm_event.cpu_activity is not None

    atk_event = generate_window("udp_flood", intensity=4, sequence=0)
    model.correlate(atk_event)

    assert atk_event.resource_state == "ELEVATED"
    assert atk_event.energy_deviation > norm_event.energy_deviation
    assert atk_event.cpu_activity > norm_event.cpu_activity
    assert atk_event.radio_rx > norm_event.radio_rx


def test_iam_access_decisions():
    iam = IAMService()

    # Authenticated sensor with high trust -> ALLOW
    sensor_acc = iam.access("SENSOR-01")
    assert sensor_acc["decision"] == "ALLOW"
    assert sensor_acc["authorization_status"] == "AUTHORIZED"
    assert sensor_acc["authentication_status"] == "AUTHENTICATED"

    # Untrusted attacker -> DENY
    atk_acc = iam.access("ATK-01")
    assert atk_acc["decision"] == "DENY"
    assert atk_acc["authorization_status"] == "DENIED"

    # Unknown device -> DENY until verified
    unknown_acc = iam.access("ROGUE-NODE")
    assert unknown_acc["identity"] == "ROGUE-NODE"
    assert unknown_acc["role"] == "unknown"


def test_dynamic_trust_decay_and_recovery():
    iam = IAMService()
    identity_name = "TEST-NODE"

    # Initial state
    ident = iam.get(identity_name)
    assert ident.trust_score == 45.0

    # Suspicious detection penalty (-20)
    ident, delta, reason = iam.adjust_trust(identity_name, attack=True)
    assert delta == -20.0
    assert ident.trust_score == 25.0

    # Authentication failure penalty (-15)
    ident, delta, reason = iam.adjust_trust(identity_name, attack=False, auth_failure=True)
    assert delta == -15.0
    assert ident.trust_score == 10.0

    # Recovery observation rewards (+3)
    ident, delta, reason = iam.adjust_trust(identity_name, attack=False, recovered=True)
    assert delta == 3.0
    assert ident.trust_score == 13.0

    # Bound check: trust score never drops below 0
    for _ in range(10):
        iam.adjust_trust(identity_name, attack=True)
    assert iam.get(identity_name).trust_score >= 0.0

    # Bound check: trust score never exceeds 100
    for _ in range(50):
        iam.adjust_trust(identity_name, attack=False, recovered=True)
    assert iam.get(identity_name).trust_score <= 100.0
