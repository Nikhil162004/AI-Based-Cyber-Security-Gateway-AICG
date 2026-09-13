# Live Gateway Integration V1

## 1. Purpose

This document records the validated V1 live gateway pipeline for the
AI-Powered Edge Security Gateway.

The pipeline connects live traffic capture data to feature extraction,
machine-learning inference, security decision logic, and dry-run
mitigation recommendations.

V1 is a host-side integration and decision pipeline.

It does not perform real packet blocking, rate limiting, device isolation,
firewall modification, routing modification, or physical disconnection.

---

## 2. Live Pipeline

The validated live pipeline is:

    Traffic Capture
          |
          v
    dataset/traffic_data.csv
          |
          v
    live_feature_adapter_v1.py
          |
          v
    dataset/live_features_v1.csv
          |
          v
    live_ml_inference_v1.py
          |
          v
    dataset/live_predictions_v1.csv
          |
          v
    live_security_decision_v1.py
          |
          v
    results/live_security_decisions_v1.csv
          |
          v
    live_mitigation_decision_v1.py
          |
          v
    results/live_mitigation_decisions_v1.csv

---

## 3. Live Traffic Dataset

Input:

    dataset/traffic_data.csv

Validated capture:

- 93 packets
- Required traffic-monitor fields present
- Capture contains TCP and UDP traffic
- No attack label is assigned to this live capture

The capture is therefore used for pipeline/integration testing and
not as independent detection-accuracy evidence.

---

## 4. Live Feature Adapter V1

Component:

    detection/live_feature_adapter_v1.py

Output:

    dataset/live_features_v1.csv

Validated result:

- 17 one-second windows
- 15 ML features
- 16 columns including window_start
- No label column is added

Feature order:

1. packet_count
2. bytes_total
3. packets_per_second
4. bytes_per_second
5. unique_sources
6. unique_destinations
7. udp_count
8. tcp_count
9. icmp_count
10. syn_count
11. ack_count
12. rst_count
13. fin_count
14. average_packet_size
15. flow_count

The feature order matches the legacy Random Forest model interface.

---

## 5. Live ML Inference V1

Component:

    detection/live_ml_inference_v1.py

Model:

    detection/ddos_model.pkl

Model characteristics:

- Random Forest classifier
- 100 estimators
- 15 input features
- Classes:
  - DDOS_UDP
  - NORMAL

Output:

    dataset/live_predictions_v1.csv

Validated result:

- 17 inference windows
- All 17 predictions were NORMAL
- DDoS probability range: 0.00 to 0.12
- Highest observed DDoS probability: 0.12

This result demonstrates inference compatibility with the live feature
schema. It does not establish generalization accuracy because the live
capture is not an independently labeled attack/normal evaluation set.

---

## 6. Live Security Decision V1

Component:

    detection/live_security_decision_v1.py

Output:

    results/live_security_decisions_v1.csv

Decision rules:

    NORMAL
        -> ALLOW
        -> NORMAL severity

    DDOS_UDP
        -> ALERT
        -> HIGH severity

Validated live result:

- 17 windows processed
- 17 NORMAL predictions
- 17 ALLOW actions
- 17 NORMAL severity results

Behavioral testing also verified:

    NORMAL -> ALLOW / NORMAL

    DDOS_UDP -> ALERT / HIGH

The DDOS branch was tested using controlled synthetic decision-layer
inputs and did not generate network traffic.

---

## 7. Live Mitigation Decision V1

Component:

    detection/live_mitigation_decision_v1.py

Output:

    results/live_mitigation_decisions_v1.csv

This component is a dry-run recommendation layer.

It does not enforce mitigation.

Rules:

    NORMAL
        -> ALLOW

    DDOS_UDP with DDoS probability < 0.80
        -> RATE_LIMIT

    DDOS_UDP with DDoS probability >= 0.80
    and packet rate < 100 packets/second
        -> RATE_LIMIT

    DDOS_UDP with DDoS probability >= 0.80
    and packet rate >= 100 packets/second
        -> RATE_LIMIT_AND_DROP

Thresholds:

    DDOS_PROBABILITY_THRESHOLD = 0.80
    PACKET_RATE_THRESHOLD = 100.0 packets/second

Controlled behavioral testing verified all four cases.

Live dry-run result:

- 17 windows processed
- 17 NORMAL predictions
- 17 ALLOW security decisions
- 17 ALLOW mitigation recommendations
- No traffic enforcement performed

---

## 8. Legacy Mitigation Boundary

The existing legacy component:

    mitigation/mitigation_engine.py

consumes:

    results/energy_aware_detection.csv

It expects energy-related fields including:

- energy_increase_percent
- energy_cause

The new live pipeline does not currently provide these validated fields.

Therefore the legacy mitigation engine is not directly connected to the
live pipeline.

Energy values must not be fabricated merely to satisfy the interface.

---

## 9. NS-3 V3 Boundary

The existing NS-3 V3 gateway path uses:

    detection/gateway_ml_bridge_v1.py
    detection/gateway_security_decision_v1.py

The NS-3 V3 bridge uses a five-feature schema:

- packet_count
- bytes_total
- unique_sources
- average_packet_size
- flow_count

The live gateway path uses the legacy 15-feature model.

These schemas remain intentionally separate.

The existing NS-3 V3 components were not modified during live gateway
integration.

---

## 10. Enforcement Boundary

Current V1 implementation stops at:

    Detection
        ->
    Security Decision
        ->
    Mitigation Recommendation

No actual enforcement is implemented.

Specifically, V1 does not:

- execute firewall commands
- modify iptables or nftables
- configure traffic control
- drop packets at the operating-system network layer
- isolate an IIoT device
- modify Contiki routing
- disconnect a device
- physically isolate a network segment

This boundary is intentional for the V1 integration stage.

---

## 11. Validation Summary

### Live integration

    Traffic packets:              93
    Feature windows:              17
    ML prediction windows:        17
    Security decision windows:    17
    Mitigation decision windows:  17

### Live observed result

    NORMAL predictions:           17
    DDOS predictions:              0
    ALLOW security actions:       17
    ALERT security actions:        0
    ALLOW mitigation decisions:   17

### Controlled behavior tests

Security decision:

    NORMAL -> ALLOW / NORMAL
    DDOS   -> ALERT / HIGH

Mitigation decision:

    NORMAL -> ALLOW
    low-confidence DDoS -> RATE_LIMIT
    high-confidence low-rate DDoS -> RATE_LIMIT
    high-confidence high-rate DDoS -> RATE_LIMIT_AND_DROP

---

## 12. Important Limitations

The live capture is not a labeled independent test set.

Therefore the following claims must NOT be made from the 17 live windows:

- independent live detection accuracy
- production-grade DDoS detection performance
- false-positive rate on representative enterprise traffic
- generalization to unseen attacks
- effectiveness of actual traffic blocking

The current results establish:

- feature-schema compatibility
- successful live inference execution
- successful prediction-to-decision integration
- successful decision-to-mitigation recommendation integration
- correct interface behavior under controlled tests

---

## 13. Current Status

LIVE GATEWAY INTEGRATION V1:

    STATUS: VALIDATED

Implemented:

    [x] Live feature adaptation
    [x] 15-feature model input compatibility
    [x] Live ML inference
    [x] Security decision layer
    [x] Dry-run mitigation recommendation layer
    [x] Controlled behavioral tests
    [x] Live pipeline integration
    [x] Interface/schema validation

Not implemented:

    [ ] Real packet enforcement
    [ ] Firewall integration
    [ ] Device isolation
    [ ] Automated blocking
    [ ] Physical network isolation
    [ ] Real-time dashboard
    [ ] Production deployment

---

## 14. Versioning Policy

The following existing components remain unchanged:

    gateway_ml_bridge_v1.py
    gateway_security_decision_v1.py
    mitigation_engine.py

New live components are versioned independently:

    live_feature_adapter_v1.py
    live_ml_inference_v1.py
    live_security_decision_v1.py
    live_mitigation_decision_v1.py

Future changes should use a new version rather than silently changing
validated V1 behavior.

---

## 15. Architecture Checkpoint

The current architecture is intentionally divided into two validated
paths.

NS-3 / existing path:

    NS-3 features
        ->
    NS-3 V3 ML inference
        ->
    Gateway ML bridge V1
        ->
    Security Policy V1
        ->
    Gateway Security Decision V1

Live gateway path:

    Traffic capture
        ->
    15-feature live adapter
        ->
    Legacy Random Forest inference
        ->
    Live Security Decision V1
        ->
    Live Mitigation Decision V1
        ->
    DRY-RUN recommendation

This separation prevents incompatible feature schemas and unsupported
energy fields from being mixed between pipelines.

---

## 16. Final V1 Statement

The live gateway integration has reached a validated V1 checkpoint.

The system can process captured gateway traffic through feature
engineering, machine-learning inference, security decision logic, and
dry-run mitigation recommendation.

Actual network enforcement remains outside the V1 scope.
