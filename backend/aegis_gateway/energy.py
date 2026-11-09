"""Transparent cause-based resource and energy model; it is not a physical hardware power meter."""

from __future__ import annotations

import hashlib
import math
from dataclasses import dataclass

from .schema import TelemetryEvent


@dataclass(frozen=True)
class EnergyModel:
    """Physics-informed cause-based energy dissipation model for edge gateways.

    Estimates quiescent and active power dissipation (in mW) and window energy (in mJ)
    from observed packet rate, byte volume, unique sources, and protocol flags.
    Incorporates protocol state tracking complexity, packet-size inspection overhead,
    and deterministic gateway background task fluctuations to model realistic
    physical dissipation rather than pure linear packet-rate encoding.
    All outputs are explicitly labeled with PROVENANCE: MODELLED.
    """

    baseline_rate: float = 55.0  # Nominal quiescent gateway baseline dissipation (mW)

    def correlate(self, event: TelemetryEvent) -> TelemetryEvent:
        packets = float(event.packet_count or 0)
        packet_rate = float(event.packet_rate or 0)
        byte_count = float(event.byte_count or 0)
        byte_rate = float(event.byte_rate or 0)
        sources = float(event.unique_sources or 1)
        packet_size = float(event.packet_size or (byte_count / packets if packets > 0 else 200.0))
        protocol = (event.protocol or "UDP").upper()
        has_flags = bool(event.tcp_flags)

        # 1. Deterministic system-state hash (simulates quiescent thermal & background scheduler variation)
        key = f"{event.device_id or 'gw'}:{event.flow_id or 'flow'}:{event.src_port or 0}".encode("utf-8")
        h = int(hashlib.md5(key).hexdigest()[:8], 16)
        state_factor = ((h % 1000) / 500.0) - 1.0  # Normalized deterministic perturbation in [-1.0, 1.0]

        # 2. Protocol state handling complexity:
        # TCP requires connection tracking and sequence validation; ICMP is lightweight control; UDP is datagram dispatch.
        if protocol == "TCP":
            proto_cost = 1.15 if has_flags else 1.08
        elif protocol in {"ICMP", "ICMPV6"}:
            proto_cost = 0.95
        else:
            proto_cost = 1.00

        # 3. Packet size efficiency:
        # Small packets (<120 B) incur interrupt storm overhead; large packets (>650 B) increase memory bus & buffer load.
        size_penalty = 1.10 if packet_size < 120 else (1.08 if packet_size > 650 else 1.0)

        # 4. Modeled subsystem utilization percentages (0..100)
        tx = min(100.0, max(2.0, 4.0 + packet_rate * 0.15 + (byte_rate / 100000.0) * 5.0 + state_factor * 0.8))
        rx = min(100.0, max(2.0, 5.0 + packet_rate * 0.20 + (byte_rate / 80000.0) * 6.0 - state_factor * 0.6))

        cpu_base = 5.0 + (packet_rate * 0.18 * proto_cost * size_penalty) + (sources * 1.2)
        cpu = min(100.0, max(3.0, cpu_base + state_factor * 1.5))

        mem_base = 10.0 + sources * 1.5 + (8.0 if has_flags else 0.0)
        memory = min(100.0, max(5.0, mem_base + state_factor * 1.2))

        # Active power components (mW)
        # Quiescent baseline: ~50.0 mW
        # Processing & protocol handling with protocol-specific weighting
        # Subsystem overhead: CPU up to 15 mW, Radio TX/RX up to 16 mW
        energy_rate = (
            50.0
            + (packet_rate * 0.35 * proto_cost)
            + (cpu / 100.0) * 15.0
            + (tx + rx) * 0.08
            + (state_factor * 1.2)
        )
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
