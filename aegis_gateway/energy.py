"""Transparent cause-based resource and energy model; it is not a physical hardware power meter."""

from __future__ import annotations

from dataclasses import dataclass

from .schema import TelemetryEvent


@dataclass(frozen=True)
class EnergyModel:
    """Physics-informed cause-based energy dissipation model for edge gateways.

    Estimates quiescent and active power dissipation (in mW) and window energy (in mJ)
    from observed packet rate, byte volume, unique sources, and protocol flags.
    All outputs are explicitly labeled with PROVENANCE: MODELLED.
    """

    baseline_rate: float = 55.0  # Nominal quiescent gateway baseline dissipation (mW)

    def correlate(self, event: TelemetryEvent) -> TelemetryEvent:
        packets = float(event.packet_count or 0)
        packet_rate = float(event.packet_rate or 0)
        byte_count = float(event.byte_count or 0)
        sources = float(event.unique_sources or 1)

        # Modeled subsystem utilization percentages (0..100)
        tx = min(100.0, 4.0 + packet_rate * 0.15)
        rx = min(100.0, 5.0 + packet_rate * 0.20)
        cpu = min(100.0, 5.0 + packet_rate * 0.18 + sources * 1.2)
        memory = min(100.0, 10.0 + sources * 1.5 + (1 if event.tcp_flags else 0) * 8.0)

        # Active power components (mW)
        # Quiescent baseline: 50.0 mW
        # Processing & protocol handling: ~0.35 mW per packet/s
        # Subsystem active overhead: CPU up to 15 mW, Radio TX/RX up to 16 mW
        energy_rate = 50.0 + packet_rate * 0.35 + (cpu / 100.0) * 15.0 + (tx + rx) * 0.08
        energy_rate = max(self.baseline_rate * 0.8, round(energy_rate, 2))

        # Relative deviation from quiescent baseline
        deviation = round((energy_rate - self.baseline_rate) / self.baseline_rate, 4)

        # 1-second observation window: 1 mW * 1 s = 1 mJ
        energy_consumed = round(energy_rate * 1.0, 2)
        energy_per_packet = round(energy_consumed / packets, 3) if packets > 0 else 0.0

        event.radio_tx = round(tx, 2)
        event.radio_rx = round(rx, 2)
        event.radio_idle = round(max(0.0, 100.0 - tx - rx / 2.0), 2)
        event.cpu_activity = round(cpu, 2)
        event.memory_activity = round(memory, 2)

        event.energy_baseline = self.baseline_rate
        event.energy_rate = energy_rate
        event.energy_consumed = energy_consumed
        event.energy_deviation = deviation

        # Resource classification
        if deviation >= 1.0:
            event.resource_state = "CRITICAL"
        elif deviation >= 0.25:
            event.resource_state = "ELEVATED"
        else:
            event.resource_state = "NORMAL"

        event.energy_cause = (
            f"MODELLED: {packets:.0f} pkts/s, TX {tx:.0f}%, RX {rx:.0f}%, CPU {cpu:.0f}% -> "
            f"{energy_rate:.1f} mW ({deviation * 100:+.1f}% vs {self.baseline_rate:.1f} mW baseline, "
            f"{energy_per_packet:.2f} mJ/pkt)"
        )
        return event
