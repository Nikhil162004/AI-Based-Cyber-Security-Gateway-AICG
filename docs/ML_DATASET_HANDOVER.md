# AI-Edge DDoS Gateway
## ML-Ready Dataset & Feature Engineering Handover

---

## 1. Purpose

This document describes the completed work related to:

- Traffic data collection and generation
- Data preprocessing
- Traffic feature extraction
- NS-3 traffic integration
- Energy-related feature engineering
- Cause-based energy consumption analysis
- Final ML-ready dataset preparation
- Dataset validation

This handover is intended for the teammate responsible for the subsequent machine-learning model development.

---

# 2. Scope of Responsibility

The completed scope covers the preparation of data required for ML.

### Included

1. Traffic data collection/generation
2. Packet-level preprocessing
3. Traffic-window feature extraction
4. NORMAL and DDOS_UDP labeling
5. NS-3 traffic integration
6. Energy feature calculation
7. Energy baseline calculation
8. Energy deviation and percentage-increase calculation
9. Cause-based energy classification
10. Combining original and NS-3 datasets
11. Final ML-ready numerical feature dataset
12. Dataset validation

### Not Included

The following tasks are outside this dataset/feature-engineering scope:

- Random Forest training
- Model selection
- Hyperparameter tuning
- Model evaluation
- Accuracy analysis
- Confusion matrix evaluation
- Model testing
- Production deployment of the trained model

These tasks are to be handled by the ML/model-development teammate.

---

# 3. Overall Data Pipeline

The implemented data pipeline is:

    Traffic generation / collection
                |
                v
        Packet-level data
                |
                v
       Traffic preprocessing
                |
                v
       Feature extraction
                |
                v
          NS-3 integration
                |
                v
       Energy calculation
                |
                v
      Energy baseline analysis
                |
                v
     Cause-based energy analysis
                |
                v
     Original + NS-3 combination
                |
                v
       Final ML-ready dataset
                |
                v
          Dataset validation
                |
                v
             HANDOVER

---

# 4. Traffic Data

The project contains traffic generated/collected from multiple sources.

Relevant dataset components include:

- Original traffic captures
- NS-3 normal traffic
- NS-3 attacker traffic
- Packet-level CSV datasets
- Traffic-window feature datasets

The traffic scenarios currently represented are:

- NORMAL
- DDOS_UDP

---

# 5. Traffic Feature Engineering

Traffic was converted from packet-level observations into time-window based features.

The ML traffic features are:

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

These features describe:

- Traffic volume
- Packet rate
- Bandwidth consumption
- Source diversity
- Destination diversity
- Protocol distribution
- TCP flag activity
- Packet-size characteristics
- Flow activity

---

# 6. NS-3 Integration

NS-3 traffic was integrated into the ML data pipeline.

Current NS-3 packet data includes:

- Source IP
- Destination IP
- Protocol
- Source port
- Destination port
- Packet size
- Timestamp
- Traffic label

The current NS-3 traffic contains both:

- NORMAL traffic
- DDOS_UDP traffic

NS-3 packet captures were inspected using TShark.

The attacker traffic was verified as UDP traffic originating from:

    10.0.4.1

and targeting:

    10.0.10.2

on UDP port:

    9001

The normal traffic was observed on UDP port:

    9000

---

# 7. NS-3 Feature Extraction

The NS-3 packet-level dataset was converted into time-window based features.

Current NS-3 feature extraction result:

    Windows: 19

Class distribution:

    NORMAL    : 4
    DDOS_UDP  : 15

The resulting file is:

    dataset/ns3_current_features.csv

---

# 8. Energy Feature Engineering

Energy-related features were added to the traffic feature pipeline.

The following numeric energy/activity features were generated:

1. tx_packet_count
2. rx_packet_count
3. tx_activity
4. rx_activity
5. cpu_activity
6. energy_estimate
7. energy_rate
8. energy_per_packet
9. traffic_intensity
10. baseline_energy
11. energy_deviation
12. energy_increase_percent

These features allow the ML pipeline to represent the relationship between:

    Network traffic
          +
    Device activity
          +
    Estimated energy consumption

---

# 9. Cause-Based Energy Monitoring

A cause-based energy analysis was implemented.

The system calculates:

- Baseline energy
- Energy deviation
- Percentage energy increase
- Traffic/activity indicators
- Energy-related cause classification

The original dataset identified causes such as:

    Normal traffic activity
    Elevated device activity
    High-rate UDP flooding

The current NS-3 dataset identified:

    Normal traffic activity
    Elevated device activity
    High network traffic activity

This provides a data-level representation of the mentor-requested
cause-based energy monitoring requirement.

---

# 10. Energy Baseline

The current calculated normal baseline is:

    Baseline energy = 55.625

This baseline is used to calculate:

    energy_deviation
    energy_increase_percent

For example, high-rate DDoS traffic in the original dataset produced
a very large increase relative to the normal baseline.

The energy values are currently estimated from traffic/device activity
features. They should therefore be treated as an analytical/estimated
energy model rather than physical power measurements from hardware.

---

# 11. Current Energy Results

For the original traffic dataset:

    NORMAL windows     : 4
    DDOS_UDP windows   : 14

Average values observed:

    NORMAL packet rate       : 29.25 pkt/s
    NORMAL energy estimate   : 55.62

    DDOS packet rate         : 1029.79 pkt/s
    DDOS energy estimate     : 1956.64

    Average energy increase  : 3417.56%

For the NS-3 dataset, the generated energy features show the same
general relationship:

    NORMAL traffic
        -> lower packet activity
        -> lower estimated energy

    DDOS traffic
        -> significantly higher packet activity
        -> higher estimated energy

---

# 12. Final ML-Ready Dataset

The original and current NS-3 feature datasets were combined.

Source datasets:

    dataset/traffic_energy_analysis.csv
    dataset/ns3_current_energy_analysis.csv

Final dataset:

    dataset/final_ml_ready_dataset.csv

Final dataset size:

    37 windows
    27 ML features
    1 label
    28 total columns

Class distribution:

    DDOS_UDP  : 29
    NORMAL    : 8

---

# 13. Final ML Feature Set

The final dataset contains 27 numerical ML features.

### Traffic features

    packet_count
    bytes_total
    packets_per_second
    bytes_per_second
    unique_sources
    unique_destinations
    udp_count
    tcp_count
    icmp_count
    syn_count
    ack_count
    rst_count
    fin_count
    average_packet_size
    flow_count

### Energy/activity features

    tx_packet_count
    rx_packet_count
    tx_activity
    rx_activity
    cpu_activity
    energy_estimate
    energy_rate
    energy_per_packet
    traffic_intensity
    baseline_energy
    energy_deviation
    energy_increase_percent

### Target label

    label

Possible labels:

    NORMAL
    DDOS_UDP

---

# 14. Deliberately Excluded Fields

The following fields from the analytical datasets were not included
as direct ML features:

    window_start
    energy_cause

Reason:

`window_start` is primarily a temporal identifier.

`energy_cause` is an interpreted/derived textual classification.
Including it directly as an input could introduce information leakage
or make the model depend on an already-derived attack interpretation.

The final dataset therefore contains numerical traffic and energy
features plus the target label.

---

# 15. Dataset Validation

The final dataset was validated.

### Dataset structure

    Rows              : 37
    Total columns     : 28
    ML features       : 27
    Label column      : Present

### Missing values

    Total missing values: 0

Status:

    PASS

### Numeric feature validation

    Numeric features checked: 27
    Non-numeric ML features: 0

Status:

    PASS

### Feature validation

    Expected features: 27
    Actual features:   27

Status:

    PASS

### Label validation

    DDOS_UDP: 29
    NORMAL:    8

Status:

    PASS

### Leakage check

No known leakage-prone columns were found in the final dataset.

Status:

    PASS

---

# 16. Duplicate Investigation

The final dataset initially reported:

    Duplicate rows: 26

These were investigated based on repeated feature patterns.

The investigation showed that many repeated rows correspond to
different traffic windows exhibiting the same traffic characteristics.

Examples include repeated DDoS windows such as:

    packet_count = 1030
    bytes_total   = 548900
    energy        = 1957.05

and repeated NS-3 attack windows such as:

    packet_count = 479
    bytes_total   = 250258
    energy        = 910.15

These represent sustained/repeated traffic conditions rather than
automatically proving accidental data duplication.

Therefore, the repeated feature patterns were not blindly removed.

---

# 17. Important Dataset Limitation

The final dataset currently contains only:

    37 windows

with:

    29 DDOS_UDP
    8 NORMAL

Therefore, the dataset is relatively small and class-imbalanced.

This limitation should be considered by the teammate during model
development and evaluation.

Possible future improvements may include:

- More normal traffic windows
- More attack scenarios
- More NS-3 simulation runs
- Different attack intensities
- Different packet rates
- Different packet sizes
- Different source counts
- Additional protocols
- Additional device behavior patterns

These improvements are optional future work and are not required before
the current dataset handover unless the model-development teammate
determines that more data is required.

---

# 18. Current Repository Deliverables

Important files produced during the data/feature-engineering phase
include:

    dataset/traffic_features.csv

    dataset/traffic_energy_features.csv

    dataset/traffic_energy_analysis.csv

    dataset/ns3_current_ml_packets.csv

    dataset/ns3_current_features.csv

    dataset/ns3_current_energy_features.csv

    dataset/ns3_current_energy_analysis.csv

    dataset/ml_training_data_combined.csv

    dataset/final_ml_ready_dataset.csv

Energy processing scripts include:

    energy/energy_calculator.py
    energy/energy_baseline.py
    energy/energy_summary.py
    energy/energy_visualization.py
    energy/energy_aware_detection.py

NS-3-specific energy processing includes:

    energy/energy_calculator_ns3_current.py
    energy/energy_baseline_ns3_current.py
    energy/energy_aware_detection_ns3_current.py

NS-3 conversion/feature processing includes:

    detection/ns3_dataset_converter.py
    detection/feature_extractor_ns3_current.py

---

# 19. Handover to ML Teammate

The primary handover file is:

    dataset/final_ml_ready_dataset.csv

The teammate can use this file as the input dataset for the subsequent
ML/model-development phase.

The target column is:

    label

The input features are the 27 numerical columns listed in Section 13.

---

# 20. Work Completed

The following work is completed:

    [x] Traffic data collection/generation
    [x] Packet-level preprocessing
    [x] Traffic feature extraction
    [x] NORMAL/DDOS_UDP labeling
    [x] NS-3 traffic integration
    [x] NS-3 feature extraction
    [x] Energy feature calculation
    [x] Energy baseline calculation
    [x] Energy deviation calculation
    [x] Energy increase calculation
    [x] Cause-based energy analysis
    [x] Original + NS-3 data combination
    [x] Final ML-ready dataset creation
    [x] Missing-value validation
    [x] Data-type validation
    [x] Feature-set validation
    [x] Label validation
    [x] Leakage-prone column check
    [x] Duplicate-pattern investigation

---

# 21. Explicit Handover Boundary

DATASET / FEATURE ENGINEERING:

    COMPLETED

MODEL TRAINING:

    HANDLED BY ML TEAMMATE

MODEL EVALUATION:

    HANDLED BY ML TEAMMATE

MODEL TESTING:

    HANDLED BY ML TEAMMATE

---

# 22. Recommended Next Phase

The next phase after this handover is the ML/model-development phase.

The teammate should independently perform:

    Final dataset loading
            |
            v
    Train/test split
            |
            v
    Appropriate preprocessing
            |
            v
    Baseline Random Forest
            |
            v
    Model evaluation
            |
            v
    Error analysis
            |
            v
    Model improvement
            |
            v
    Final model selection

This document marks the completion of the dataset and feature-engineering
responsibility.
