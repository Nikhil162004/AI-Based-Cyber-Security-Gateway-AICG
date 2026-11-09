# AEGIS Gateway – Backend Tier

## Overview
The `backend/` directory houses the entire server-side runtime, machine learning pipeline, telemetry ingestion, incident policy engine, database persistence layer, and automated test suite for the **AI-Based Cyber Security Gateway for Industry 4.0 (AICG / Aegis Gateway)**.

## Architecture & Components
- **`aegis_gateway/`**: Canonical production package:
  - `api.py`: Flask REST API, Server-Sent Events (SSE) streaming (`/events`), and forensic export endpoints.
  - `runtime.py`: `GatewayRuntime` coordinator managing in-memory event queues and subscribers.
  - `detection.py`: 15-dimensional ML feature extraction and `HybridDetector` engine.
  - `energy.py`: Physics-informed Energy Dissipation Model (`EnergyModel`).
  - `ml.py`: Dataset generation, training, and Platt probability calibration.
  - `policy.py`: Automated incident lifecycle and mitigation policy engine.
  - `security.py`: RBAC, administrative authentication, session rotation, and audit logging.
  - `storage.py`: Durable SQLite persistence and WAL management.
  - `iam.py`: HMAC-SHA256 zero-trust device credential verification and dynamic trust scoring.
  - `scenarios.py`: 11 synthetic and realistic attack/normal traffic window generators.
  - `adapters.py`: PCAP, NS-3, and Cooja trace parsing adapters.
  - `config.py`: Centralized environment and filesystem path resolution.
  - `cli.py`: Unified command-line interface.
- **`models/`**: Pretrained machine learning model bundles:
  - `hybrid_detector.joblib` (3.15 MB synthetic baseline detector)
  - `realistic_detector_v1.joblib` (4.45 MB realistic benchmark detector)
- **`data/`**: Operational state and canonical datasets:
  - `aegis_gateway.sqlite3`: Active SQLite runtime database (11 tables).
  - `datasets/`: Canonical ML training datasets and metadata JSON files.
- **`dataset/`**: 67 raw NS-3 and PCAP simulation traces.
- **`simulation/`**: NS-3 C++ network simulation topology (`normal_iiot.cc`).
- **`tests/`**: Complete 17-file automated test suite (236 passing tests).
- **`scripts/`**: End-to-end verification and browser automation scripts.
- **`reports/`**: Academic SRS drafts, evaluation metrics, and screenshot evidence.
- **`legacy_prototypes/`**: Early historical prototype scripts from initial project milestones.

## Running the Backend
```bash
# From repository root:
.venv/bin/python backend/app.py

# Or directly from backend:
cd backend && ../.venv/bin/python app.py
```

## Running Tests
```bash
# From repository root:
.venv/bin/pytest backend/tests/ -v

# Or from backend:
cd backend && ../.venv/bin/pytest tests/ -v
```
