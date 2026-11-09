# NS-3 ML Baseline V1

## Dataset

Primary ML-ready dataset: dataset/ns3_ml_ready_primary_v1.csv

- Total windows: 19
- NORMAL: 5
- DDOS_UDP: 14
- Features: 5
- Time-window size: 1 second
- Missing values: 0
- Exact duplicate rows: 12
- Unique feature patterns: 7

## Features

1. packet_count
2. bytes_total
3. unique_sources
4. average_packet_size
5. flow_count

Energy-derived features are retained separately and are not part of the primary ML baseline.

## Model

Model: detection/ns3_ddos_model_v1.pkl

Algorithm: Random Forest Classifier

Configuration:
- Number of trees: 100
- Random state: 42
- Class weighting: balanced
- Evaluation: Leave-One-Out Cross-Validation (LOOCV)

## Baseline Evaluation

LOOCV accuracy: 1.0000

Confusion matrix:

              NORMAL  DDOS
Actual NORMAL     5      0
Actual DDOS       0     14

## Inference Component

Inference script: detection/ns3_ml_inference_v1.py

Representative NORMAL sample: NORMAL
Representative DDoS sample: DDOS_UDP

## Important Limitation

This baseline is a proof-of-pipeline result, not evidence of production-grade generalization.

The dataset contains only one controlled NS-3 DDoS scenario and 19 one-second windows. Multiple exact duplicate windows are present, and several features are highly correlated because they are derived from the same packet counts and window structure.

Therefore, the 1.0000 LOOCV accuracy must not be interpreted as real-world detection accuracy.

The next ML stage should use additional independent traffic scenarios, attack intensities, timing variations, and normal-traffic variations before claiming generalization.

## Reproducibility

Active NS-3 simulation source:
ns-allinone-3.48/ns-3.48/scratch/ddos_udp.cc

Model-training script:
detection/train_ns3_baseline_v1.py

Evaluation script:
detection/evaluate_ns3_baseline_v1.py

Inference script:
detection/ns3_ml_inference_v1.py
