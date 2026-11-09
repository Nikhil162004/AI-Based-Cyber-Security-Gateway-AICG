# AICG Software Requirements Specification (SRS)
## Manual Confirmation & Institutional Input Checklist

**Project Title:** AI-Based Cyber Security Gateway for Industry 4.0  
**Project Identifier / Abbreviation:** AICG / Aegis Gateway  
**Document Code:** AICG-SRS-MANUAL-INPUTS-V1  
**Project Group:** Group G15 (Verified from `reference/AEGIS-OT-TECHNICAL-AUDIT.docx`)  
**Repository Branch:** `feat/phase23-security-ml-hardening`  
**Current Baseline Tag:** `v2.10.0` (Commit `de23b4c`)  
**Audit Reference:** `reports/srs/phase_srs01_technical_content_audit_plan.md`  

---

### Purpose of this Document

During the strict plan-only technical audit (`phase_srs01_technical_content_audit_plan.md`), all technical, functional, architectural, database, and algorithmic details of the codebase were verified against concrete code, tests, and configurations. However, non-code academic metadata (student names, university roll/seat numbers, faculty guide designations, institution department names, and institutional deadlines) cannot be fabricated or inferred by an AI assistant.

This document identifies **every single item requiring manual confirmation** by the project team. The team must fill in the bracketed placeholders `[ ... ]` before final submission of the academic SRS and Progress Evaluation dossier.

---

## 1. Project Team Identification (Group G15)

The repository documentation (`reference/AEGIS-OT-TECHNICAL-AUDIT.docx`) establishes that the project belongs to **Group G15**.

### Confirmed Team Contribution Structure (Three Groups)
- **Part 1 — Jaydeep Jotiram Mulik (Roll No. A42) & Nikhil Fepade (Roll No. A11):**  
  Network Simulation, Data Pipeline, NS-3/Cooja & Energy Modeling;  
  Core Gateway, Runtime, Incident Lifecycle & Recovery.
- **Part 2 — Prasad Mestri (Roll No. A40):**  
  AI/ML Detection, Hybrid Fusion & Benchmarking.
- **Part 3 — Shruti Pawar (Roll No. B75) & Srushti Mali (Roll No. A95):**  
  Security/IAM + SOC Dashboard, Testing & Forensic Evidence.

### Team Member 1 (Part 1 — Core Gateway & Network Simulation)
- **Full Name:** Jaydeep Jotiram Mulik
- **University Seat Number (USN) / Roll No:** A42
- **Email Address:** `[STUDENT EMAIL 1]`
- **Verified Repository Focus:** Gateway Core Runtime (`aegis_gateway/runtime.py`), In-Process Software Policy Enforcer (`aegis_gateway/policy.py`), Incident Lifecycle Management, and Closed-Loop Recovery.
- **Confirmation Status:** **CONFIRMED** (Name & Roll No.) / `[STUDENT EMAIL 1]`

### Team Member 2 (Part 2 — Machine Learning & Benchmarking)
- **Full Name:** Prasad Mestri
- **University Seat Number (USN) / Roll No:** A40
- **Email Address:** `[STUDENT EMAIL 2]`
- **Verified Repository Focus:** Supervised Random Forest Classifier, Isolation Forest Outlier Scorer, Platt Scaling Probability Calibration (`CalibratedClassifierCV`), GroupShuffleSplit Campaign Validation, and Realistic Benchmark Evaluation (`aegis_gateway/ml.py`, `aegis_gateway/detection.py`).
- **Confirmation Status:** **CONFIRMED** (Name & Roll No.) / `[STUDENT EMAIL 2]`

### Team Member 3 (Part 1 — Network Simulation, Traces & Data Pipeline)
- **Full Name:** Nikhil Fepade
- **University Seat Number (USN) / Roll No:** A11
- **Email Address:** `[STUDENT EMAIL 3]`
- **Verified Repository Focus:** Multi-Source Telemetry Adapters (`aegis_gateway/adapters.py`), Discrete-Event Simulation Scripts (`ns-allinone-3.48/ns-3.48/scratch/`), Contiki-NG / Cooja 6LoWPAN Mote Emulation Dataset Ingestion, and Physics-Informed Cause-Based Energy Dissipation Modeling (`aegis_gateway/energy.py`).
- **Confirmation Status:** **CONFIRMED** (Name & Roll No.) / `[STUDENT EMAIL 3]`

### Team Member 4 (Part 3 — Security Hardening & Zero-Trust IAM)
- **Full Name:** Shruti Pawar
- **University Seat Number (USN) / Roll No:** B75
- **Email Address:** `[STUDENT EMAIL 4]`
- **Verified Repository Focus:** Two-Stage Authentication & Simulated MFA (`aegis_gateway/security.py`), Zero-Trust Dynamic IAM & HMAC Replay Protection Cache (`aegis_gateway/iam.py`), and Brute-Force Rate Limiting.
- **Confirmation Status:** **CONFIRMED** (Name & Roll No.) / `[STUDENT EMAIL 4]`

### Team Member 5 (Part 3 — SOC Console, E2E Verification & Forensic Storage)
- **Full Name:** Srushti Mali
- **University Seat Number (USN) / Roll No:** A95
- **Email Address:** `[STUDENT EMAIL 5]`
- **Verified Repository Focus:** Industrial SOC HMI Dashboard (`dashboard/`), Headless Chrome Selenium E2E Test Suite (`scripts/run_browser_e2e_admin.py`), SQLite Storage with WAL, and SHA-256 Tamper-Evident Audit Ledger (`aegis_gateway/storage.py`).
- **Confirmation Status:** **CONFIRMED** (Name & Roll No.) / `[STUDENT EMAIL 5]`

---

## 2. Institutional & Supervisory Metadata

The confirmed institutional details for the cover page, approval certificates, and institutional metadata:

- **Project Title:** AI-Based Cyber Security Gateway for Industry 4.0
- **Internal / Working Title:** Aegis Gateway (AEGIS-OT)
- **Department:** Department of Computer Science and Engineering (**CONFIRMED**)
- **Faculty / College Name:** D. Y. Patil School Of Engineering and Management, Kolhapur (**CONFIRMED**)
- **University Affiliation:** Deemed to be University (**CONFIRMED**)
- **Academic Year:** 2026-27 (**CONFIRMED**)
- **Degree / Program:** B.Tech (**CONFIRMED**)
- **Submission Date:** 9 October 2026 (**CONFIRMED**)

### Faculty Project Guide / Supervisor
- **Guide Name:** Dr. R. D. Bhosale (**CONFIRMED**)
- **Academic Designation:** `[GUIDE DESIGNATION, e.g., Associate Professor / Assistant Professor / Professor]`
- **Department:** Department of Computer Science and Engineering (**CONFIRMED**)
- **Institutional Email:** `[GUIDE EMAIL]`

### Department Leadership
- **Head of Department (HOD) Name:** Dr. G. V. Otari (**CONFIRMED**)

---

## 3. Academic Milestones & Timeline Dates

Please confirm the following key institutional dates:

| Academic Milestone | Status | Institutional Date | Confirmation Status |
|---|---|---|---|
| **Project Synopsis Submission & Defense** | Completed | `[SYNOPSIS DATE, e.g., August 2026]` | `[MANUAL CONFIRMATION REQUIRED]` |
| **Progress Evaluation 1 / Phase Review 1** | Upcoming (Target) | `[EVALUATION 1 DATE, e.g., October 2026]` | `[MANUAL CONFIRMATION REQUIRED]` |
| **Draft SRS Submission** | Completed | 9 October 2026 | **CONFIRMED** |
| **Phase Review 2 / Progress Evaluation 2** | Scheduled | `[EVALUATION 2 DATE, e.g., December 2026]` | `[MANUAL CONFIRMATION REQUIRED]` |
| **Final Dissertation & Viva-Voce Defense** | Final Milestone | `[FINAL VIVA DATE, e.g., May 2027]` | `[MANUAL CONFIRMATION REQUIRED]` |

---

## 4. Hardware Deployment Targets (Future Scope Confirmation)

The repository demonstrates 100% user-space Linux execution with software-modeled devices. For Section 2.4 (Operating Environment) and Chapter 5 (Hardware Interfaces), please confirm the preferred hardware platform for the future deployment roadmap:

- **Option A (Recommended Default):** Single-Board Edge Computer — Raspberry Pi 4 Model B (Quad-core Cortex-A72 @ 1.5 GHz, 4GB/8GB LPDDR4, Gigabit Ethernet, 32GB MicroSD running Raspberry Pi OS 64-bit).
- **Option B:** Accelerated Edge Compute Unit — NVIDIA Jetson Nano / Orin Nano Developer Kit (for dedicated TensorRT hardware acceleration of Random Forest and Isolation Forest ensembles).
- **Option C:** Ruggedized Industrial DIN-Rail Gateway — Advantech UNO-2271G / Moxa UC-8100 Series (Dual GbE LAN, RS-485 isolated serial, DIN-rail mountable for industrial enclosures).
- **Selected Target Hardware for SRS Section 5.2:** `[CONFIRM SELECTION: Option A / Option B / Option C]`

---

## 5. Verification Checklist Before Submission

- [x] All student names (Jaydeep Jotiram Mulik, Prasad Mestri, Nikhil Fepade, Shruti Pawar, Srushti Mali) and roll numbers (A42, A40, A11, B75, A95) populated across SRS documents.
- [x] Guide name (Dr. R. D. Bhosale), HOD (Dr. G. V. Otari), Department, College, University (Deemed to be University), Degree (B.Tech), and Academic Year (2026-27) confirmed.
- [x] All student roll numbers (A42, A40, A11, B75, A95) confirmed and populated; obsolete [USN / ROLL NO.] tags removed.
- [ ] Student and faculty email address placeholders are populated (retained intentionally).
- [x] University affiliation confirmed as "Deemed to be University".
- [x] Submission date confirmed as "9 October 2026".
