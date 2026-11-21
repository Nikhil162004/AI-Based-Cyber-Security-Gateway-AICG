# AICG Simulation Datasets & Telemetry Traces

This directory contains research datasets, PCAP packet traces, and pre-extracted feature CSVs
generated to validate the **AI-Based Cyber Security Gateway for Industry 4.0 (AICG)** detection engine.

## Provenance and Contents

- **NS-3 Simulation PCAPs**: Packet capture files generated from discrete-event simulation runs
  using `normal_iiot.cc` (legitimate sensor traffic) and `ns3/ddos_udp*.cc` (attack traffic).
- **Extracted Feature CSVs**: Normalized telemetry datasets representing network velocities,
  packet intervals, flow metrics, and modeled energy dissipation readings.
- **Cooja Trace Extracts**: 6LoWPAN mote radio and duty-cycle logs generated in the Cooja simulator.

## Licensing and Usage Terms

- **Exclusion from Root MIT License**: All datasets, raw PCAP packet traces, and extracted CSVs
  contained in this directory are strictly excluded from the root MIT License.
- **No Open Reuse License Granted**: These files are NOT licensed under CC0-1.0, CC-BY, MIT, or
  any other open-source or public reuse license.
- **Scope of Availability**: Provided solely for non-commercial academic research reference,
  independent verification, and reproducing testbench results of the AICG security gateway.
- **Reservation of Rights**: No redistribution, republication, commercial exploitation, or
  sublicensing is permitted. All rights are reserved by the copyright holder (JAYDEEP JOTIRAM MULIK).
