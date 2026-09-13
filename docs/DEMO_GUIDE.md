# Aegis Gateway: Evaluator & Reviewer Demonstration Guide

This guide provides an end-to-end walkthrough for evaluators, reviewers, and oral examiners to inspect, verify, and interact with the **AI-Based Cyber Security Gateway for Industry 4.0**.

---

## Pre-Requisites & Verification

All commands should be executed from the repository root:
```bash
cd /home/kali/AI-Edge-DDoS-Gateway
```

Ensure the Python 3.14 virtual environment is available:
```bash
.venv/bin/python --version
```

---

## Step 1: Automated Test Suite (Code Quality & Defensibility)

Run the full automated pytest suite covering schema bounds, scenarios, detection rules, calibrated ML, cause-based energy, IAM trust governance, storage, adapters, and API endpoints:

```bash
.venv/bin/pytest tests/
```

**Expected Outcome:**
- 38 passing unit and integration tests.
- 1 cleanly skipped test (skips external Cooja path only if the Contiki-NG directory is not locally present).
- 0 failures, 0 errors.

---

## Step 2: Automated End-to-End Incident Lifecycle Run

Execute the automated scripted verification to witness the entire four-phase incident progression without touching the browser:

```bash
.venv/bin/python scripts/e2e_acceptance_verification.py
```

**Key Phases Verified in Console Output:**
1. **Benign Operational Baseline**: Four normal windows; confirms modeled energy is at idle (~14.5 mW), trust is 100.0, and 0 incidents are opened.
2. **Controlled Attack Burst**: High-rate UDP flood (intensity 4); verifies AI detection, evidence list generation, modeled energy surge, IAM trust penalty (decaying to 15.0), automatic dry-run containment, and incident creation.
3. **Multi-Window Campaign Correlation**: A second attack window is injected; verifies that the gateway **correlates into the existing active incident** rather than spamming duplicate records.
4. **Verified Recovery Streak**: Five consecutive normal windows are injected; confirms progression from `CONTAINED` $\rightarrow$ `RECOVERING` (at streak $\ge$ 3) $\rightarrow$ `RESOLVED` with `recovery_state="VERIFIED"` (at streak $\ge$ 5).
5. **Trust Audit History**: Verifies bounded trust decay entries in the SQLite audit log.

---

## Step 3: Launching the Live Gateway

Launch the integrated Flask REST API and SSE event server:

```bash
.venv/bin/python -m aegis_gateway.api
```

The gateway listens on `http://127.0.0.1:8000`.

Open two browser tabs:
1. **Operator HMI**: `http://127.0.0.1:8000/`
2. **Attacker Simulation Console**: `http://127.0.0.1:8000/attacker`

---

## Step 4: Operator HMI Live Walkthrough

### 4.1. Real-Time Telemetry & SSE Streaming
On `http://127.0.0.1:8000/`:
- Notice the **Live Topology** panel showing connected edge sensor nodes (`SENSOR-01`, `SENSOR-02`, `SENSOR-03`), the Aegis Edge Gateway, and external industrial networks.
- Notice the live telemetry cards: **Packet Rate**, **Modelled Energy Consumption**, **Gateway Threat Level**, and **Active Incident Count**.
- The frontend connects automatically via Server-Sent Events (`/events`), updating the interface in real time without page refreshes.

### 4.2. Triggering Attacks from the Scenario Catalogue
In the **Attack Simulation Catalogue** panel on the dashboard:
1. Click any attack scenario button, e.g., **`UDP Flood`**, **`SYN Flood`**, or **`Modbus Anomaly`**.
2. Immediately observe:
   - **Packet Rate Gauge** surges upward.
   - **Modelled Energy Meter** reflects increased CPU/radio dissipation.
   - **Threat Level** turns red (`CRITICAL` or `HIGH`).
   - **Identity Trust Score** decays with an explainable penalty.
   - A new incident card appears in the **Durable Incident Journal**.
3. Trigger a second burst of the same attack:
   - Notice that the **Incident Journal updates the active incident** with peak packet rates and merged evidence, preserving campaign correlation without duplicate incident rows.

### 4.3. Response Mode Control (AUTO vs MANUAL)
- In the **Mitigation Policy & Controls** section, switch the mode toggle between **`AUTO`** and **`MANUAL`**.
- When in `MANUAL` mode, newly detected attacks transition to `DETECTED` and wait for operator intervention.
- The operator can click:
  - **`Simulate Block`**: Applies simulated IP drop.
  - **`Simulate Rate Limit`**: Applies simulated traffic throttling.
  - **`Simulate Isolate`**: Quarantines node credentials in IAM.
- All actions are strictly **DRY_RUN** and recorded to the immutable audit historian.

### 4.4. Closed-Loop Recovery Demonstration
1. Allow normal traffic to flow (or inject normal baseline windows).
2. As normal observation windows arrive:
   - After 3 consecutive normal windows, the incident badge turns blue: **`RECOVERING`**.
   - After 5 consecutive normal windows, the incident transitions to green: **`RESOLVED`** with `recovery_state="VERIFIED"`.
3. The operator can click **`Close`** to transition the incident to `CLOSED` for permanent archival.

### 4.5. Forensic Evidence Export
At the bottom of the HMI:
- Click **`Export Telemetry (CSV)`** or **`Export Telemetry (JSON)`** to download full canonical telemetry with cryptographic hashes and model evidence.
- Click **`Export Incidents (CSV)`** to download incident lifecycle history.

---

## Step 5: Controlled Attacker Simulation Console

Navigate to `http://127.0.0.1:8000/attacker`:
- This interface allows an evaluator to act as a red-team operator in a controlled, safe environment.
- Choose an attack vector from the dropdown (e.g., `Burst Exhaustion`, `Slow Rate`, or `RPL Anomaly`).
- Adjust the **Intensity Slider** (1 to 6) and **Duration** (seconds).
- Click **`Launch In-Process Attack Simulation`**.
- Notice the immediate HTTP 200 response with simulated flow parameters, while the Operator HMI in the other tab reacts in real time to the simulated traffic.

---

## Step 6: Multi-Source Adapter Verification

The gateway natively ingests diverse edge evidence sources:

### 6.1. NS-3 Network Simulator Traces
The gateway supports both aggregated feature CSVs and packet-trace dumps:
```python
from pathlib import Path
from aegis_gateway.adapters import ns3_csv_events

# Ingest NS-3 low-rate DDoS feature window
events = list(ns3_csv_events(Path("dataset/ns3_low_v1_features.csv")))
print(f"Ingested {len(events)} NS-3 simulation windows.")
```

### 6.2. Contiki-NG / Cooja 6LoWPAN Sensor Traces
Cooja mote simulation datasets are ingested as `source_type="COOJA"`, `provenance="SIMULATED"`:
```python
from pathlib import Path
from aegis_gateway.adapters import cooja_csv_events

cooja_path = Path("/home/kali/contiki-ng/examples/ai_edge_iiot/data/cooja_ml_ready_v1.csv")
if cooja_path.exists():
    events = list(cooja_csv_events(cooja_path))
    print(f"Ingested {len(events)} Cooja 6LoWPAN windows.")
```

### 6.3. PCAP Packet Replay
Raw PCAPs can be replayed window-by-window without raw socket privileges:
```python
from pathlib import Path
from aegis_gateway.adapters import pcap_window_events

pcap_file = Path("dataset/sample.pcap")
if pcap_file.exists():
    events = list(pcap_window_events(pcap_file, window_seconds=1.0))
```

---

## Step 7: Machine Learning & Calibration Assurance

Inspect the ML evaluation report:
```bash
cat reports/evaluation.json | python3 -m json.tool
```

**Evaluation Highlights:**
- **Zero Leakage**: Grouped by campaign ID via `GroupShuffleSplit` across train (60%), validation (20%), and test (20%).
- **Platt Probability Calibration**: Probability calibration curves minimize the Brier score ($< 0.0002$), guaranteeing that output probabilities reflect true attack likelihood.
- **Held-out Generalization**: The `mixed_vector` scenario is completely withheld during model fitting and evaluated separately to prove out-of-distribution detection capability.

---

## Step 8: Academic Defense Notes & Technical Rationale

| Evaluation Criterion | Implementation in Aegis Gateway |
| :--- | :--- |
| **Claim Discipline** | Explicit provenance tags (`SIMULATED`, `SYNTHETIC`, `MODELLED`, `REPLAYED`). No false claims of connected hardware power meters. |
| **Defensible ML** | Stratified campaign grouping guarantees zero test-set leakage. Platt probability calibration prevents overconfident thresholding. |
| **Zero-Trust IAM** | Dynamic trust decay and recovery bounded strictly within $[0, 100]$. Explainable reason codes logged for every trust modification. |
| **Alert Fatigue Prevention** | Intelligent multi-window correlation groups attack waves into a single incident entity instead of creating hundreds of alerts. |
| **Closed-Loop Recovery** | Incidents are not arbitrarily closed; they require mathematically verified benign streaks (3 windows for `RECOVERING`, 5 windows for `RESOLVED`). |
| **Host System Safety** | 100% user-space dry-run simulation. Zero modification of host routing tables, NIC interfaces, or `iptables`. |
