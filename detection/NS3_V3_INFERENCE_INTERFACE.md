# NS-3 V3 ML Inference Interface

## Model

Model file: `detection/ns3_ddos_model_v3.pkl`

Model type: Random Forest Classifier

Model version: V3

## Required Features

The inference interface accepts exactly five traffic-window features:

- `packet_count` — Number of packets observed in the traffic window
- `bytes_total` — Total captured bytes in the traffic window
- `unique_sources` — Number of unique source IP addresses
- `average_packet_size` — Mean packet/frame size
- `flow_count` — Number of distinct flows

Feature order:

1. packet_count
2. bytes_total
3. unique_sources
4. average_packet_size
5. flow_count

## Input Contract

Example:

```json
{"packet_count":364,"bytes_total":187928,"unique_sources":4,"average_packet_size":516.285714,"flow_count":4}
```

## Output Contract

Example:

```json
{"prediction":"DDOS_UDP","normal_probability":0.0,"ddos_probability":1.0}
```

## Supported Predictions

- `NORMAL`
- `DDOS_UDP`

## Processing

The gateway-side traffic pipeline creates a fixed traffic window. The five required features are calculated from that window and passed to the V3 inference component. The V3 model returns prediction, NORMAL probability, and DDOS probability.

## Decision Layer

The ML prediction is an input to the gateway security decision layer. The ML model itself does not directly perform packet blocking.

A later policy layer may use the prediction to:

- generate an alert
- increase threat severity
- isolate a suspicious source
- request dashboard notification

## Current Prototype Scope

The current V3 model has been evaluated only on controlled NS-3 scenarios.

Tested DDoS intensity regimes:

- LOW_V1 — 5 ms interval
- MIDLOW_V1 — 3 ms interval
- MID_V1_CLEAN — 2 ms interval
- BASELINE_V1 — 1 ms interval

Four-regime held-out evaluation achieved 100% accuracy for each tested regime.

This result applies to the controlled NS-3 experimental family and must not be presented as real-world generalization.

## Integration Boundary

The following components remain separate:

- NS-3 simulation
- trained ML model
- inference wrapper
- gateway implementation
- dashboard

The existing NS-3 scenarios, datasets, and previous model versions must remain unchanged.

## Versioning

Current frozen ML artifacts:

- `dataset/ns3_ml_ready_combined_v4.csv`
- `detection/ns3_ddos_model_v3.pkl`
- `detection/ns3_ml_inference_v3.py`

Previous versions must not be overwritten.
