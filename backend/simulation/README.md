# AICG NS-3 Simulation Models & Licensing

This directory contains discrete-event network simulation models developed for the
**AI-Based Cyber Security Gateway for Industry 4.0 (AICG)** project.

## Simulation Files Inventory

1. `normal_iiot.cc`: Baseline IIoT network topology generating legitimate sensor telemetry flows.
2. `ns3/ddos_udp.cc`: Multi-attacker UDP flood simulation across distributed edge nodes.
3. `ns3/ddos_udp_baseline_v1.cc`: Baseline UDP attack pattern benchmark model.
4. `ns3/ddos_udp_low_v1.cc`: Low-rate stealthy pulsing DDoS simulation model.
5. `ns3/ddos_udp_mid_v1.cc`: Moderate-rate burst DDoS simulation model.
6. `ns3/ddos_udp_midlow_v1.cc`: Intermediate low-to-moderate rate multi-vector attack model.

## Licensing Architecture

- **GNU General Public License v2 (GPL-2.0-only)**
- The simulation programs in this directory were created for compilation and execution within
  the **NS-3 Network Simulator** framework (https://www.nsnam.org/).
- Because they include NS-3 module headers (`ns3/core-module.h`, `ns3/network-module.h`,
  `ns3/internet-module.h`, `ns3/point-to-point-module.h`, `ns3/applications-module.h`,
  `ns3/flow-monitor-module.h`) and link against the NS-3 simulation engine, these simulation
  sources are governed by the **GNU General Public License version 2 (GPLv2)**.
- This licensing applies strictly to the simulation programs and does not extend to the
  independent, standalone Python gateway software in `backend/aegis_gateway/` or the
  user interface in `frontend/`, which are licensed under the root MIT License.

## Compilation and Execution

To execute these models:
1. Ensure a working installation of NS-3 (version 3.35 or later, tested with 3.48).
2. Copy the desired simulation file to your local NS-3 `scratch/` directory:
   ```bash
   cp backend/simulation/ns3/ddos_udp.cc /path/to/ns-allinone-3.48/ns-3.48/scratch/
   ```
3. Run the simulation using the NS-3 build system:
   ```bash
   ./ns3 run scratch/ddos_udp
   ```
4. Generated PCAP packet captures can be analyzed with Wireshark/tshark or ingested into
   the AICG canonical pipeline via the offline trace import mechanism.
