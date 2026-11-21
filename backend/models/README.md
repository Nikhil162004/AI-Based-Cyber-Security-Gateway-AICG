# AICG Pre-Trained Machine Learning Models

This directory contains pre-trained machine learning model bundles serialized with Joblib.

## Model Inventory

1. `realistic_detector_v1.joblib`: Calibrated hybrid detector combining Platt-calibrated
   Random Forest with Isolation Forest for out-of-distribution anomaly detection.
2. `hybrid_detector.joblib`: Baseline multi-stage detection pipeline bundle.

## Provenance and Architecture

- Trained using `scikit-learn` on synthetic/simulated IIoT telemetry extracted from the
  NS-3 and Cooja testbed experiments.
- Frozen estimator weights trained to detect volumetric floods, low-rate pulsing attacks,
  and energy exhaustion patterns.

## Licensing and Usage Terms

- **Exclusion from Root MIT License**: These pre-trained machine learning model artifacts are
  strictly excluded from the root MIT License.
- **No Open License Granted**: These model artifacts are NOT licensed under CC-BY-4.0, MIT, or
  any other open license.
- **Scope of Availability**: Provided solely for non-commercial benchmark evaluation, offline
  testing, and verifying the published detection performance of the AICG gateway.
- **Reservation of Rights**: Commercial deployment, retraining redistribution, or sublicensing
  is not permitted pending a separate licensing decision. All rights are reserved by the
  copyright holder (JAYDEEP JOTIRAM MULIK).
