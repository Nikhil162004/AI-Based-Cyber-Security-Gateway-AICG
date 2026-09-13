"""Transparent cause-based resource and energy model; it is not a power meter."""

from __future__ import annotations

from dataclasses import dataclass

from .schema import TelemetryEvent


@dataclass(frozen=True)
class EnergyModel:
    baseline_rate: float = 0.018  # arbitrary model units / window

    def correlate(self, event: TelemetryEvent) -> TelemetryEvent:
        packets = float(event.packet_count or 0)
        packet_rate = float(event.packet_rate or 0)
        byte_count = float(event.byte_count or 0)
        tx = min(100.0, 4.0 + packet_rate * .22)
        rx = min(100.0, 5.0 + packet_rate * .30)
        cpu = min(100.0, 6.0 + packet_rate * .24 + (event.unique_sources or 0) * 1.2)
        memory = min(100.0, 12.0 + (event.unique_sources or 0) * 2.0 + (1 if event.tcp_flags else 0) * 8)
        energy_rate = self.baseline_rate + packets * .00010 + byte_count * .00000003 + cpu * .00018 + (tx + rx) * .00005
        deviation = (energy_rate - self.baseline_rate) / self.baseline_rate
        event.radio_tx, event.radio_rx, event.radio_idle = round(tx, 2), round(rx, 2), round(max(0, 100 - tx - rx / 2), 2)
        event.cpu_activity, event.memory_activity = round(cpu, 2), round(memory, 2)
        event.energy_baseline, event.energy_rate = self.baseline_rate, round(energy_rate, 6)
        event.energy_consumed, event.energy_deviation = round(energy_rate, 6), round(deviation, 4)
        event.resource_state = "ELEVATED" if deviation >= .4 else "NORMAL"
        event.energy_cause = (
            f"MODELLED: {packets:.0f} packets, TX {tx:.0f}%, RX {rx:.0f}%, CPU {cpu:.0f}% "
            f"produce {deviation * 100:.0f}% deviation from the model baseline."
        )
        return event
