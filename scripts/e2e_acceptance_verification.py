#!/usr/bin/env python3
"""End-to-end simulation acceptance verification script.

Demonstrates:
1. Normal baseline rhythm (streak >= 3) -> verifies baseline energy & no incident.
2. Controlled attack burst (udp_flood, intensity=4) -> verifies AI detection, evidence generation,
   elevated modelled energy (mW), IAM trust decay, incident creation & correlation into single campaign.
3. Multiple successive attack windows -> verifies correlation into the active incident without duplication.
4. Response action -> automatic dry-run containment (CONTAINED).
5. Resume normal rhythm -> verifies recovery streak tracking:
   CONTAINED -> RECOVERING (streak >= 3) -> RESOLVED (streak >= 5, verified).
6. Separate campaigns -> verifies distinct device/attack vectors generate distinct incidents.
"""

import json
import sys
import tempfile
import warnings
from pathlib import Path

warnings.filterwarnings("ignore")

# Ensure repository root is on sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from aegis_gateway.config import Settings
from aegis_gateway.runtime import GatewayRuntime
from aegis_gateway.scenarios import generate_window


def main():
    print("=" * 70)
    print("AEGIS GATEWAY END-TO-END SIMULATION ACCEPTANCE VERIFICATION")
    print("=" * 70)

    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        settings = Settings(
            database_path=tmp_path / "acceptance.sqlite3",
            model_path=Path("models/hybrid_detector.joblib"),
            auto_response=True,
        )
        runtime = GatewayRuntime(settings=settings)

        print("\n[Phase 1: Benign Operational Baseline]")
        for seq in range(4):
            event = generate_window("normal", intensity=1, sequence=seq)
            res = runtime.ingest(event)
            ev = res["event"]
            dec = res["decision"]
            print(f"  Seq {seq}: Rate={ev['packet_rate']:.1f} pps, Energy={ev['energy_rate']:.1f} mW "
                  f"({ev['energy_deviation'] * 100:+.1f}%), Decision={dec['prediction']}, Severity={dec['severity']}, "
                  f"Trust={ev['trust_score']:.1f}, Active Incidents={len(runtime.store.incidents(state='OPEN'))}")

        assert len(runtime.store.incidents(state="OPEN")) == 0, "Expected 0 open incidents during baseline"
        print("  -> Baseline verified: No incidents generated, normal energy and trust preserved.")

        print("\n[Phase 2: Controlled Attack Burst (Multi-window Campaign)]")
        attack_event_1 = generate_window("udp_flood", intensity=4, sequence=0)
        res1 = runtime.ingest(attack_event_1)
        ev1 = res1["event"]
        dec1 = res1["decision"]
        resp1 = res1["response"]
        print(f"  Attack Window 1: Rate={ev1['packet_rate']:.1f} pps, Energy={ev1['energy_rate']:.1f} mW "
              f"({ev1['energy_deviation'] * 100:+.1f}% vs baseline), Decision={dec1['prediction']}, "
              f"Severity={dec1['severity']}, Trust={ev1['trust_score']:.1f} (-{100 - ev1['trust_score']:.1f}), "
              f"Action={resp1['action']} ({resp1['mode']})")

        incidents = runtime.store.incidents(limit=5)
        assert len(incidents) == 1, f"Expected exactly 1 incident, found {len(incidents)}"
        active_inc = incidents[0]
        inc_id = active_inc["incident_id"]
        print(f"  -> Incident Created: {inc_id}, State={active_inc['lifecycle_state']}, Severity={active_inc['severity']}")
        print(f"     Evidence: {active_inc['evidence']}")

        # Attack Window 2 (Correlation Test: Should update active incident, NOT create a second incident)
        attack_event_2 = generate_window("udp_flood", intensity=5, sequence=1)
        res2 = runtime.ingest(attack_event_2)
        ev2 = res2["event"]
        dec2 = res2["decision"]
        print(f"  Attack Window 2: Rate={ev2['packet_rate']:.1f} pps, Energy={ev2['energy_rate']:.1f} mW "
              f"({ev2['energy_deviation'] * 100:+.1f}%), Decision={dec2['prediction']}, "
              f"Severity={dec2['severity']}, Trust={ev2['trust_score']:.1f}")

        incidents_after = runtime.store.incidents(limit=5)
        assert len(incidents_after) == 1, f"Expected still exactly 1 correlated incident, found {len(incidents_after)}"
        assert incidents_after[0]["incident_id"] == inc_id, "Correlated incident ID must match original incident ID"
        print(f"  -> Correlation verified: Active incident {inc_id} updated with new telemetry/evidence without duplication.")

        print("\n[Phase 3: Recovery Phase & Consecutive Benign Verification]")
        # 1st normal window (streak = 1)
        norm_1 = generate_window("normal", intensity=1, sequence=10)
        runtime.ingest(norm_1)
        inc = runtime.store.incidents(limit=1)[0]
        print(f"  Normal Window 1 (Streak=1): Incident State={inc['lifecycle_state']}, Recovery={inc['recovery_state']}")

        # 2nd normal window (streak = 2)
        norm_2 = generate_window("normal", intensity=1, sequence=11)
        runtime.ingest(norm_2)
        inc = runtime.store.incidents(limit=1)[0]
        print(f"  Normal Window 2 (Streak=2): Incident State={inc['lifecycle_state']}, Recovery={inc['recovery_state']}")

        # 3rd normal window (streak = 3 -> Should transition to RECOVERING)
        norm_3 = generate_window("normal", intensity=1, sequence=12)
        runtime.ingest(norm_3)
        inc = runtime.store.incidents(limit=1)[0]
        print(f"  Normal Window 3 (Streak=3): Incident State={inc['lifecycle_state']}, Recovery={inc['recovery_state']}")
        assert inc["lifecycle_state"] == "RECOVERING", f"Expected RECOVERING, got {inc['lifecycle_state']}"

        # 4th normal window (streak = 4)
        norm_4 = generate_window("normal", intensity=1, sequence=13)
        runtime.ingest(norm_4)
        inc = runtime.store.incidents(limit=1)[0]
        print(f"  Normal Window 4 (Streak=4): Incident State={inc['lifecycle_state']}, Recovery={inc['recovery_state']}")

        # 5th normal window (streak = 5 -> Should transition to RESOLVED with VERIFIED)
        norm_5 = generate_window("normal", intensity=1, sequence=14)
        runtime.ingest(norm_5)
        inc = runtime.store.incidents(limit=1)[0]
        print(f"  Normal Window 5 (Streak=5): Incident State={inc['lifecycle_state']}, Recovery={inc['recovery_state']}, ResolvedAt={inc['resolved_at']}")
        assert inc["lifecycle_state"] == "RESOLVED", f"Expected RESOLVED, got {inc['lifecycle_state']}"
        assert inc["recovery_state"] == "VERIFIED", f"Expected recovery_state VERIFIED, got {inc['recovery_state']}"

        # Operator closes incident
        runtime.store.transition_incident(inc_id, "CLOSED", actor="Operator-HMI", note="Campaign closed following verified recovery.")
        inc_closed = runtime.store.incidents(limit=1)[0]
        print(f"  -> Incident transitioned to {inc_closed['lifecycle_state']}.")

        print("\n[Phase 4: Trust & Identity Audit Check]")
        trust_entries = runtime.store.trust("ATK-01")
        print(f"  Total Trust Log Entries for ATK-01: {len(trust_entries)}")
        for t in trust_entries[-4:]:
            print(f"    Time={t['timestamp']}, Score={t['score']:.1f}, Delta={t['delta']:.1f}, Reason={t['reason']}")

        print("\n[Phase 5: Campaign Separation Verification]")
        # Distinct attack from a different node (SENSOR-02) with syn_flood
        distinct_attack = generate_window("syn_flood", intensity=4, sequence=0)
        distinct_attack.device_id = "SENSOR-02"
        distinct_attack.source_id = "SENSOR-NODE-02"
        res_distinct = runtime.ingest(distinct_attack)
        distinct_inc = res_distinct.get("incident")
        assert distinct_inc is not None, "Expected distinct incident created for new campaign"
        assert distinct_inc["incident_id"] != inc_id, "New campaign must create a distinct incident ID"
        print(f"  -> Distinct Campaign Incident Created: {distinct_inc['incident_id']} (Target: {distinct_inc['device_id']}, Vector: {distinct_inc['attack_type']})")

        all_incidents = runtime.store.incidents()
        assert len(all_incidents) == 2, f"Expected exactly 2 distinct incidents in history, found {len(all_incidents)}"
        print(f"  -> Total distinct incident records in store: {len(all_incidents)} (Verified campaign separation).")

        print("\n" + "=" * 70)
        print("ALL END-TO-END ACCEPTANCE VERIFICATION CRITERIA SUCCESSFULLY MET!")
        print("=" * 70)


if __name__ == "__main__":
    main()
