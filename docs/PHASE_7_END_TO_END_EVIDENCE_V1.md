# Phase 7 — End-to-End Controlled Decision & Evidence Validation V1

## 1. Purpose

Phase 7 validates the existing end-to-end cybersecurity decision path and packages the resulting evidence without modifying the frozen ML model, regenerating attack traffic, or altering the controlled simulation datasets.

## 2. End-to-End Decision Path

```text
Traffic / Feature Window
        |
        v
Live Feature Adapter
        |
        v
Frozen ML Inference
        |
        v
Security Decision
        |
        v
Mitigation Decision
        |
        v
Explainability Evidence
        |
        v
Security Lifecycle Evidence
```

## 3. Live Decision Evidence

Existing live pipeline artifacts contain 18 decision windows.

Validated live evidence:

- dataset/live_features_v1.csv
- dataset/live_predictions_v1.csv
- results/live_security_decisions_v1.csv
- results/live_mitigation_decisions_v1.csv
- results/live_explainability_v1.csv
- results/security_lifecycle_v1.csv

The current live prediction evidence is NORMAL-only. Therefore, the live pipeline evidence demonstrates the NORMAL path rather than representing a live DDoS attack run.

## 4. NORMAL Decision Path

Validated NORMAL behavior:

```text
Prediction: NORMAL
        |
        v
Security action: ALLOW
        |
        v
Mitigation action: ALLOW
```

The controlled decision evidence contains 4 NORMAL windows with NORMAL -> ALLOW security action and NORMAL -> ALLOW mitigation action.

## 5. Controlled DDOS Decision Path

Controlled evidence is provided by:

`results/mitigation_decisions.csv`

Validated controlled evidence contains:

- 14 `DDOS_UDP` windows
- DDoS probability: 1.0 in the controlled evidence
- Packet-rate values at or above the mitigation threshold
- Security action: `ALERT`
- Severity: `HIGH`
- Mitigation action: `RATE_LIMIT_AND_DROP`
- Mitigation reason: `High-confidence DDoS traffic`

Decision policy thresholds:

- `DDOS_PROBABILITY_THRESHOLD = 0.8`
- `PACKET_RATE_THRESHOLD = 100.0`

The controlled decision chain is:

```text
DDOS_UDP
   |
   +--> ALERT
   |
   +--> HIGH
   |
   +--> RATE_LIMIT_AND_DROP
```

This is controlled simulation evidence and must not be represented as evidence from real-world attack traffic.

## 6. Explainability Evidence

`results/live_explainability_v1.csv` contains 18 rows corresponding to the live decision evidence.

The explainability artifact records prediction, prediction probabilities, feature values, security action, severity, mitigation action, mitigation reason, observed evidence, provenance, and evidence status.

Current attribution fields indicate that SHAP/LIME attribution is not implemented.

Accordingly, the current explainability layer is described as observed decision evidence and provenance evidence, not as completed SHAP/LIME model attribution.

## 7. Security Lifecycle Evidence

`results/security_lifecycle_v1.csv` contains 18 rows.

The lifecycle evidence records the decision state and lifecycle stage associated with the live pipeline.

Current evidence includes lifecycle state, lifecycle stage, implementation status, enforcement status, and recovery status.

The current artifact records implementation as observed while enforcement and recovery remain marked as not implemented where applicable.

## 8. Energy Context Integration

The Energy Context Adapter was validated against:

`dataset/ns3_current_energy_analysis.csv`

Validated source:

- 19 energy-analysis rows
- NORMAL and `DDOS_UDP` labels
- Required energy fields present

The adapter resolves the existing producer output under:

`dataset/ns3_current_energy_analysis.csv`

The dashboard `/api/energy-context` endpoint was validated successfully.

API evidence:

- HTTP status: 200
- 19 energy contexts returned
- source: `NS3_CURRENT_ENERGY_ANALYSIS`
- environment: `CONTROLLED_SIMULATION`
- measurement status: `MODELLED`
- hardware measured: `False`

## 9. Energy Evidence Examples

NORMAL energy evidence includes energy estimate, energy rate, energy per packet, baseline energy, energy deviation, energy increase percentage, and energy cause.

Controlled DDOS energy evidence includes elevated modelled energy activity.

The final energy-only controlled window contains:

- label: `DDOS_UDP`
- packet count: 457
- packets per second: 457.0
- energy increase: 1461.08%
- energy cause: `High network traffic activity`

These are modelled controlled-simulation values, not hardware measurements.

## 10. Energy / Decision Alignment Boundary

The energy-analysis artifact contains 19 rows.

The mitigation decision artifact contains 18 rows.

Exact timestamp intersection is limited because the artifacts preserve different original timestamp sequences after the first five windows.

Sequential comparison of the first 18 windows showed:

- 18/18 NORMAL/DDOS label matches
- 4 NORMAL decision rows
- 14 `DDOS_UDP` decision rows

However, the packet-rate fields are not numerically interchangeable:

- energy artifact field: `packets_per_second`
- mitigation artifact field: `packet_rate`

Only 2 of the 18 sequential rows had identical numeric values.

Therefore, this project does not claim exact timestamp or packet-rate identity between these two artifacts.

Original timestamps and original metric values are preserved.

No artificial timestamp normalization was performed.

The evidence relationship is limited to the validated sequential label correspondence and the independently validated energy and decision artifacts.

## 11. Phase 6 Controlled Comparison

The existing controlled comparison artifact is:

`results/normal_vs_controlled_attack_v1.json`

Validated scope:

- 73 total windows
- 17 NORMAL
- 56 controlled attack
- attack label: `DDOS_UDP`
- 4 controlled scenarios
- V3 five-feature contract
- controlled simulation environment
- offline dataset measurement
- real attack traffic: false
- attack generation: false
- model training: false
- model replacement: false
- live pipeline: false

This artifact remains a controlled/offline comparison and is not a claim of real-world attack generalization.

## 12. Cross-Artifact Evidence Chain

Validated relationships include:

```text
Live Predictions
      |
      v
Security Decisions
      |
      v
Mitigation Decisions
      |
      v
Explainability Evidence
      |
      v
Security Lifecycle Evidence
```

Controlled decision evidence independently validates:

```text
NORMAL
  -> ALLOW
  -> ALLOW

DDOS_UDP
  -> ALERT / HIGH
  -> RATE_LIMIT_AND_DROP
```

Energy evidence independently validates:

```text
NS-3 Energy Features
  -> Energy Analysis
  -> Energy Context Adapter
  -> Dashboard Energy Context API
```

## 13. Provenance Boundary

The validated evidence is based on existing project artifacts and controlled simulation outputs.

The following are explicitly outside the demonstrated scope:

- real-world attack traffic
- hardware-measured energy
- real industrial deployment
- production enforcement
- real-world generalization
- automated attack generation
- replacement of the frozen ML model
- new model training during Phase 7

The energy context is marked:

```text
environment: CONTROLLED_SIMULATION
measurement_status: MODELLED
hardware_measured: False
```

## 14. Safety / Reproducibility Boundary

During the Phase 7 validation sequence:

- No real attack traffic was generated.
- No attack-generation procedure was executed.
- No NS-3/Cooja simulation was regenerated.
- No model training was performed.
- No frozen model was modified.
- Existing evidence files were not rewritten for alignment.
- Original timestamps were preserved.
- Original metric values were preserved.

The Phase 7 work is therefore an evidence-validation and packaging phase.

## 15. Phase 7 Conclusion

Phase 7 establishes a defensible controlled evidence chain for the existing gateway architecture.

The strongest demonstrated decision result is:

```text
NORMAL
  -> ALLOW

CONTROLLED DDOS_UDP
  -> ALERT / HIGH
  -> RATE_LIMIT_AND_DROP
```

The energy context path is operational and dashboard-accessible:

```text
NS-3 Current Energy Analysis
  -> Energy Context Adapter
  -> Dashboard API
```

The principal evidence limitation is that the energy-analysis and mitigation-decision artifacts were produced with different timestamp and packet-rate sequences. This limitation is explicitly preserved rather than hidden through artificial normalization.

Phase 7 therefore validates the existing evidence without overstating synchronization, real-world deployment, hardware measurement, or attack realism.
