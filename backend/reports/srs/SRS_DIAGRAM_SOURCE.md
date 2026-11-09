# AICG Software Requirements Specification (SRS)
## System Models & Diagram Source Definitions

**Project Title:** AI-Based Cyber Security Gateway for Industry 4.0  
**Project Identifier / Abbreviation:** AICG / Aegis Gateway  
**Document Code:** AICG-SRS-DIAGRAM-SOURCE-V1  
**Project Group:** Group G15  
**Repository Branch:** `feat/phase23-security-ml-hardening`  
**Current Baseline Tag:** `v2.10.0` (Commit `de23b4c`)  
**Audit Reference:** `reports/srs/phase_srs01_technical_content_audit_plan.md`  

---

### Overview & Visual Modeling Standards

This document provides the authoritative Mermaid diagram source specifications for Chapter 7 (*System Models*) and Chapter 6 (*Use Case Requirements*) of the AICG Software Requirements Specification. Every diagram models the **actual repository implementation** as audited in `phase_srs01_technical_content_audit_plan.md`.

All entities, actors, data stores, states, and process names maintain 100% terminological consistency across all diagrams:
- **Actors:** `Security Administrator`, `Plant Security Operator`, `Edge Sensor Node`, `Detection Engine`, `Mitigation Engine`, `Simulation Console`.
- **States:** `DETECTED`, `TRIAGED`, `RESPONDING`, `CONTAINED`, `RECOVERING`, `RESOLVED`, `CLOSED`.
- **Data Stores:** The 11 normalized SQLite tables (`telemetry`, `incidents`, `incident_history`, `actions`, `iam_events`, `trust_history`, `metadata`, `admin_users`, `admin_alerts`, `admin_audit_log`, `device_identities`).
- **Core Modules:** `aegis_gateway.runtime`, `aegis_gateway.detection`, `aegis_gateway.policy`, `aegis_gateway.iam`, `aegis_gateway.energy`, `aegis_gateway.storage`, `aegis_gateway.api`.

---

## 1. Use Case Diagram

The Use Case Diagram visualizes interactions between human operators, edge sensors, internal subsystems, and administrative security functions.

```mermaid
flowchart LR
    subgraph HumanActors ["Human Actors"]
        Admin["Security Administrator<br/>(ROLE_ADMIN)"]
        Operator["Plant Security Operator<br/>(ROLE_OPERATOR)"]
    end

    subgraph ExternalActors ["External System Actors"]
        Sensor["Edge Sensor Device<br/>(Authenticated IIoT Sensor)"]
        Simulator["Simulation Engine<br/>(In-Process Test Module)"]
    end

    subgraph InternalSubsystems ["Autonomous Internal Subsystems"]
        Detector["AI Detection Engine<br/>(HybridDetector)"]
        Mitigator["Mitigation Engine<br/>(InProcessPolicyEnforcer)"]
    end

    subgraph GatewayBoundary ["AICG Gateway Boundary"]
        UC01(["UC-01: Two-Stage MFA Login"])
        UC02(["UC-02: Terminate Session (POST Logout)"])
        UC03(["UC-03: Ingest & Authenticate Telemetry"])
        UC04(["UC-04: Detect DDoS Attack Pattern"])
        UC05(["UC-05: Correlate Multi-Window Campaign"])
        UC06(["UC-06: Acknowledge Security Alert"])
        UC07(["UC-07: Autonomous 5-Streak Recovery"])
        UC08(["UC-08: Verify Audit Log Integrity"])
        UC09(["UC-09: Inject Attack Simulation"])
        UC10(["UC-10: Export Forensic Datasets"])
        UC11(["UC-11: Manage User Accounts"])
        UC12(["UC-12: Monitor Live Stream via SSE"])
    end

    Admin --> UC01
    Admin --> UC02
    Admin --> UC06
    Admin --> UC08
    Admin --> UC09
    Admin --> UC10
    Admin --> UC11
    Admin --> UC12

    Operator --> UC01
    Operator --> UC02
    Operator --> UC06
    Operator --> UC10
    Operator --> UC12

    Sensor --> UC03
    Simulator --> UC09

    Detector --> UC04
    Detector --> UC05
    Detector --> UC07

    Mitigator --> UC05
    Mitigator --> UC07
```

---

## 2. System Context Diagram

The System Context Diagram defines the operational boundary of the AICG Edge Gateway in relation to industrial field devices, the SCADA sink, SOC analysts, and offline laboratory simulators.

```mermaid
flowchart TD
    subgraph IndustrialFieldZone ["Industrial Field Zone (Cell / Area)"]
        S1["IIoT Sensor SENSOR-01<br/>(10.42.0.11 / MQTT / CoAP)"]
        S2["Sensor Cluster SENSOR-02<br/>(10.42.0.12 / High Rate)"]
        S3["Autonomous Mote SENSOR-03<br/>(10.42.0.13 / Periodic)"]
        PLC["Industrial PLC Sink<br/>(10.42.0.10 / Target Endpoint)"]
    end

    subgraph AdversarySimulation ["Controlled Adversary Simulation"]
        ATK["Simulated Attack Node ATK-01<br/>(10.42.0.250 / 10 Vectors)"]
    end

    subgraph GatewayCore ["AI-Based Cyber Security Gateway (AICG) Boundary"]
        GW["AICG Edge Gateway Engine<br/>(10.42.0.1 / Port 8000)<br/>- 52-Field Normalization<br/>- Cause-Based Energy Model (MODELLED)<br/>- HMAC Device Auth & Replay Cache<br/>- Hybrid Fusion (0.40 Rule / 0.45 RF / 0.15 iForest)<br/>- In-Process Software Policy Enforcer<br/>- Closed-Loop Lifecycle Manager<br/>- SQLite Historian & SHA-256 Audit Chain"]
    end

    subgraph SOCZone ["Industrial SOC / Operations Management"]
        AdminUser["Security Administrator<br/>(Full Governance & Audit Inspection)"]
        OpUser["Plant Operator<br/>(Monitoring & Alert Triage)"]
        HMI["Industrial SOC HMI Dashboard<br/>(Live SSE Stream / Visual Stepper)"]
    end

    subgraph ExternalTraceSources ["Offline Laboratory Simulation Traces"]
        NS3["NS-3.48 Trace Converter<br/>(ns3_*.pcap / ns3_*.csv)"]
        Cooja["Contiki-NG / Cooja 6LoWPAN<br/>(Mote Emulation Datasets)"]
    end

    S1 -- "Authenticated Telemetry (HMAC-SHA256)" --> GW
    S2 -- "Authenticated Telemetry (HMAC-SHA256)" --> GW
    S3 -- "Authenticated Telemetry (HMAC-SHA256)" --> GW
    ATK -- "Controlled Flood Traffic (In-Process)" --> GW

    GW -- "Permitted Benign Traffic (Software ALLOW)" --> PLC

    GW -- "Real-Time Telemetry & Alerts (SSE /events)" --> HMI
    HMI --> AdminUser
    HMI --> OpUser

    AdminUser -- "HTTPS / REST Administration & Simulations" --> GW
    OpUser -- "HTTPS / REST Alert Acknowledgment" --> GW

    NS3 -- "Offline CSV Trace Import (/api/ns3/import)" --> GW
    Cooja -- "Offline Mote Trace Import (/api/cooja/import)" --> GW
```

---

## 3. Data Flow Diagram Level 0 (Context Level DFD)

The DFD Level 0 diagram represents the gateway as a single high-level software transformation process (`0.0`), identifying data flows between external entities and persistent storage.

```mermaid
flowchart TD
    SensorEntity["External Entity:<br/>IIoT Edge Devices / Sensors"]
    AttackerEntity["External Entity:<br/>Controlled Adversary Generator"]
    OperatorEntity["External Entity:<br/>Plant Security Operator"]
    AdminEntity["External Entity:<br/>Security Administrator"]

    Process0["Process 0.0:<br/>AI-Based Cyber Security Gateway<br/>(AICG Core Runtime Engine)"]

    StoreTelemetry[("D1: Telemetry Historian<br/>(telemetry table)")]
    StoreIncidents[("D2: Incident & Alert Ledger<br/>(incidents, admin_alerts)")]
    StoreAudit[("D3: Tamper-Evident Audit Log<br/>(admin_audit_log table)")]
    StoreIAM[("D4: Device & User Identities<br/>(device_identities, admin_users)")]

    SensorEntity -- "1. Raw Telemetry Windows + HMAC Tokens" --> Process0
    AttackerEntity -- "2. Simulated Attack Bursts" --> Process0
    AdminEntity -- "3. Administrative Commands & Simulations" --> Process0
    OperatorEntity -- "4. Alert Acknowledgment & Mitigation Commands" --> Process0

    Process0 -- "5. Filtered Telemetry Stream (SSE)" --> OperatorEntity
    Process0 -- "6. Security Alerts & Incident History" --> OperatorEntity
    Process0 -- "7. Audit Verification & Forensic Exports" --> AdminEntity

    Process0 -- "Normalized Windows" --> StoreTelemetry
    Process0 -- "Incidents, Transitions, Actions" --> StoreIncidents
    Process0 -- "Hashed Administrative Events" --> StoreAudit
    Process0 -- "Trust Scores & Credentials" --> StoreIAM
    StoreIAM -- "Enrolled Keys & Roles" --> Process0
```

---

## 4. Data Flow Diagram Level 1 (Detailed Subsystem Decomposition)

The DFD Level 1 diagram decomposes the gateway into five core functional sub-processes, mapping the exact internal data flow through each transformation stage.

```mermaid
flowchart TD
    subgraph ExternalEntities ["External Entities"]
        SensorNode["IIoT Sensor Node"]
        AttackerNode["Attacker Node / Simulator"]
        Operator["SOC Operator / Admin"]
    end

    subgraph Processes ["Subsystem Processes"]
        P1["Process 1.0<br/>Telemetry Normalization<br/>& Device Authentication<br/>(schema.py, iam.py)"]
        P2["Process 2.0<br/>Physics-Informed Energy<br/>& Resource Modeling<br/>(energy.py)"]
        P3["Process 3.0<br/>Calibrated Hybrid AI/ML<br/>Threat Detection<br/>(detection.py, ml.py)"]
        P4["Process 4.0<br/>Policy Enforcement,<br/>Lifecycle & Recovery<br/>(policy.py, runtime.py)"]
        P5["Process 5.0<br/>Presentation, Alerting<br/>& Audit Verification<br/>(api.py, storage.py)"]
    end

    subgraph DataStores ["SQLite Database Stores"]
        D_Ident[("D4: device_identities<br/>& TokenReplayCache")]
        D_Telem[("D1: telemetry table")]
        D_Inc[("D2: incidents &<br/>incident_history")]
        D_Alert[("D5: admin_alerts")]
        D_Audit[("D3: admin_audit_log<br/>(SHA-256 Hash Chain)")]
    end

    SensorNode -- "Window + Auth Token" --> P1
    AttackerNode -- "Simulated Flood Window" --> P1
    D_Ident -- "Verify PSK / Check Replay" --> P1
    P1 -- "Update Trust & Last Seen" --> D_Ident

    P1 -- "Canonical TelemetryEvent" --> P2
    P2 -- "Modelled Power (mW) & Dissipation" --> P3

    P3 -- "Feature Mapping (15 Features)" --> P3
    P3 -- "Threat Decision Score (θ = 0.50)" --> P4

    P4 -- "Policy Action (DROP / RATE_LIMIT / ALLOW)" --> P4
    P4 -- "Append Normalized Window" --> D_Telem
    P4 -- "Correlate Incident & State" --> D_Inc
    P4 -- "Create / Synchronize Alert" --> D_Alert

    Operator -- "Acknowledge Alert / Trigger Action" --> P5
    P5 -- "Transition State / Manual Mitigation" --> P4
    P5 -- "Record Tamper-Evident Action" --> D_Audit
    D_Alert -- "Active Alerts" --> P5
    D_Inc -- "Lifecycle Stepper Status" --> P5
    D_Telem -- "Telemetry Ingestion History" --> P5
    D_Audit -- "Audit Records for Verification" --> P5

    P5 -- "Live SSE Stream (/events)" --> Operator
    P5 -- "Audit Integrity Result" --> Operator
```

---

## 5. Activity Diagram

### Activity Flow 1: Two-Stage MFA Authentication & Session Rotation
Visualizes the login workflow enforcing credential validation, brute-force rate limiting, simulated MFA verification, session rotation, and audit recording.

```mermaid
flowchart TD
    StartLogin([Start User Authentication]) --> EnterCreds["Enter Username & Password"]
    EnterCreds --> CheckRateLimit{"Failed Attempts >= 10<br/>in 60 seconds?"}

    CheckRateLimit -- Yes --> RejectRateLimit["Return HTTP 429<br/>RATE_LIMIT_EXCEEDED"]
    RejectRateLimit --> EndRateLimit([Authentication Blocked])

    CheckRateLimit -- No --> VerifyPassword{"Verify Password Hash<br/>(PBKDF2/scrypt)"}

    VerifyPassword -- Invalid --> LogFailedCreds["Record LOGIN_FAILED<br/>in admin_audit_log"]
    LogFailedCreds --> Return401["Return HTTP 401<br/>INVALID_CREDENTIALS"]
    Return401 --> EndFailedAuth([Authentication Failed])

    VerifyPassword -- Valid --> SetPreMFA["Store Pre-MFA Candidate<br/>in Session (10-min TTL)"]
    SetPreMFA --> ReturnMFAChallenge["Return HTTP 200<br/>mfa_required: true"]
    ReturnMFAChallenge --> EnterMFA["User Enters MFA Token"]

    EnterMFA --> CheckPreMFA{"Pre-MFA Session<br/>Valid & Unexpired?"}
    CheckPreMFA -- Expired/Missing --> ReturnPreAuthReq["Return HTTP 401<br/>PRE_AUTH_REQUIRED"]
    ReturnPreAuthReq --> EndFailedAuth

    CheckPreMFA -- Valid --> ValidateToken{"Constant-Time Verify<br/>Token == '123456'"}

    ValidateToken -- Invalid Token --> LogFailedMFA["Record MFA_FAILED<br/>in admin_audit_log"]
    LogFailedMFA --> Return401MFA["Return HTTP 401<br/>INVALID_MFA_TOKEN"]
    Return401MFA --> EndFailedAuth

    ValidateToken -- Valid Token --> RotateSession["rotate_session()<br/>(Execute session.clear())"]
    RotateSession --> EstablishSession["Set session['user'] =<br/>{username, role, authenticated: True}"]
    EstablishSession --> LogSuccess["Record LOGIN_SUCCESS<br/>in admin_audit_log with Record Hash"]
    LogSuccess --> SetCookie["Issue Secure Session Cookie<br/>(HttpOnly=True, SameSite='Lax')"]
    SetCookie --> EndSuccess([Authenticated Session Established])
```

---

### Activity Flow 2: Telemetry Ingest, In-Process Mitigation & Autonomous 5-Streak Recovery
Visualizes telemetry processing from ingestion through detection, in-process software drops, incident campaign correlation, and autonomous multi-window recovery.

```mermaid
flowchart TD
    StartIngest([Start Telemetry Window Ingest]) --> Normalize["Normalize to 52-Field TelemetryEvent<br/>Validate Non-Negative Bounds"]
    Normalize --> EnergyModel["Calculate Cause-Based Power<br/>(MODELLED Active Power in mW)"]
    EnergyModel --> CheckDeviceAuth{"Verify Device HMAC Token<br/>& Check TokenReplayCache"}

    CheckDeviceAuth -- Impersonator/Unauthenticated --> DenyAccess["Set authorization_status = 'DENIED'<br/>Preserve Legitimate Sensor Trust"]
    CheckDeviceAuth -- Valid Token --> AuthOK["Set authorization_status = 'AUTHORIZED'<br/>Record in iam_events"]

    DenyAccess --> CheckMitigationBoundary
    AuthOK --> CheckMitigationBoundary

    CheckMitigationBoundary{"Is Device Contained &<br/>Mode == ACTIVE/ENFORCING?"}

    CheckMitigationBoundary -- Yes & Not Recovery Window --> DropEvent["In-Process Software Intercept:<br/>DROP Event in Software Boundary"]
    DropEvent --> AuditDrop["Record Action: DROP<br/>in actions & telemetry tables"]
    AuditDrop --> PublishDrop["Broadcast DROP via SSE (/events)"]
    PublishDrop --> EndDrop([Event Dropped in Memory])

    CheckMitigationBoundary -- No or Recovery Observation --> ExtractFeatures["Extract 15 Statistical Features<br/>(Rates, Flag Ratios, Deviations)"]
    ExtractFeatures --> RunML["Execute Rules, Platt-Calibrated RF,<br/>and Isolation Forest Anomaly Scorer"]
    RunML --> FuseScore["Compute Calibrated Fusion Score:<br/>Score = 0.40 Rule + 0.45 RF + 0.15 iForest"]

    FuseScore --> EvaluateThreshold{"Ensemble Threat Score<br/>>= 0.50 (Threshold θ)?"}

    EvaluateThreshold -- Attack Detected (Score >= 0.50) --> PenalizeTrust["Penalize Trust Score (-20.0)<br/>Reset Normal Streak to 0"]
    PenalizeTrust --> CorrelateIncident{"Active Campaign Exists<br/>for Device / Vector?"}

    CorrelateIncident -- Yes --> UpdateCampaign["Correlate into Existing Incident<br/>Preserve Single Incident Entity"]
    CorrelateIncident -- No --> CreateIncident["Create Incident (DETECTED)<br/>Auto-Progress: TRIAGED -> RESPONDING"]

    UpdateCampaign --> EnforceMitigation["Apply Software Mitigation:<br/>ISOLATE / BLOCK / RATE_LIMIT"]
    CreateIncident --> EnforceMitigation
    EnforceMitigation --> UpdateAlert["Create / Update Linked Alert<br/>(Re-Escalate if Previously Acknowledged)"]
    UpdateAlert --> TransitionContained["Transition Lifecycle -> CONTAINED"]
    TransitionContained --> PublishState["Publish Event & Lifecycle over SSE"]
    PublishState --> EndAttack([Incident Active & Device Contained])

    EvaluateThreshold -- Normal Baseline (Score < 0.50) --> CheckContained{"Is Device in State<br/>CONTAINED or RECOVERING?"}

    CheckContained -- Not Contained --> RoutineNormal["Increment Device Trust (+3.0)<br/>Maintain Normal Baseline"]
    RoutineNormal --> PublishState
    PublishState --> EndNormal([Normal Event Recorded])

    CheckContained -- Contained/Recovering --> IncrementStreak["Increment Device Normal Streak<br/>_device_normal_streaks[device_id] += 1"]
    IncrementStreak --> CheckStreak{"Device Normal Streak<br/>Count"}

    CheckStreak -- Streak == 3 --> TransitionRecovering["Transition Incident -> RECOVERING<br/>Set Policy State: RECOVERING (Trial)"]
    TransitionRecovering --> SyncAlertRec["Synchronize Alert -> RECOVERING"]
    SyncAlertRec --> PublishState

    CheckStreak -- Streak >= 5 --> TransitionResolved["Transition Incident -> RESOLVED<br/>Release Mitigation (release(device_id))"]
    TransitionResolved --> SyncAlertRes["Synchronize Alert -> RESOLVED"]
    SyncAlertRes --> ResetDeviceStreak["Remove Device from Streak Dict"]
    ResetDeviceStreak --> PublishState
    PublishState --> EndRecovered([Autonomous Recovery Verified])

    CheckStreak -- Streak < 3 or (Streak 4) --> ContinueTrial["Continue Baseline Observation<br/>Maintain Current Lifecycle State"]
    ContinueTrial --> PublishState
```

---

## 6. Sequence Diagram

### Sequence 1: Two-Stage MFA Login, RBAC Authorization & Audit Integrity Verification
Visualizes message exchanges between human clients, API controllers, security decorators, rate limiters, storage engines, and the SHA-256 hash ledger.

```mermaid
sequenceDiagram
    autonumber
    actor Admin as Security Administrator
    participant API as Flask Web API (/api/auth)
    participant Sec as Security Decorators (security.py)
    participant Limiter as AuthRateLimiter
    participant Store as GatewayStore
    participant Ledger as admin_audit_log (SHA-256)

    Note over Admin,API: Step 1: Primary Credentials Verification
    Admin->>API: POST /api/auth/login {username: "admin", password: "..."}
    API->>Limiter: is_rate_limited(client_ip, "admin")
    alt Rate Limit Exceeded
        Limiter-->>API: True (Count >= 10)
        API-->>Admin: 429 Too Many Requests
    else Under Rate Limit
        Limiter-->>API: False
        API->>Store: verify_user_credentials("admin", password)
        Store-->>API: True (Password Validated)
        API->>API: set_pre_mfa_user("admin", role="ADMIN")
        API-->>Admin: 200 OK {mfa_required: true, username: "admin"}
    end

    Note over Admin,API: Step 2: Second-Factor Simulated MFA
    Admin->>API: POST /api/auth/mfa/verify {mfa_token: "123456"}
    API->>API: get_pre_mfa_user()
    API->>API: verify_simulated_mfa("123456")
    API->>API: rotate_session() [session.clear()]
    API->>API: establish_session(username="admin", role="ADMIN")
    API->>Store: record_audit("LOGIN_SUCCESS", user="admin", role="ADMIN")
    Store->>Ledger: Compute Record Hash = SHA256(prev_hash | event_id | ...)
    Store-->>API: Audit Committed
    API-->>Admin: 200 OK {authenticated: true, user: "admin", role: "ADMIN"}

    Note over Admin,API: Step 3: RBAC-Guarded Resource Access
    Admin->>API: GET /api/admin/audit/integrity
    API->>Sec: @roles_required(ROLE_ADMIN)
    Sec->>Sec: Check session["user"]["role"] == "ADMIN"
    Sec-->>API: Authorized
    API->>Store: verify_audit_log_integrity()
    Store->>Ledger: Sequentially Recompute & Verify SHA-256 Digest Chain
    Store-->>API: {valid: true, records_verified: 42}
    API-->>Admin: 200 OK {valid: true, records_verified: 42}

    Note over Admin,API: Step 4: CSRF-Hardened Session Termination (Phase A3)
    Admin->>API: POST /logout
    API->>API: session.pop("user", None)
    API->>Store: record_audit("LOGOUT", user="admin", role="ADMIN")
    Store-->>API: Audit Recorded
    API-->>Admin: 302 Redirect (/login)
```

---

### Sequence 2: Multi-Window DDoS Detection, Software Mitigation & Autonomous Recovery
Visualizes multi-window traffic ingestion, ensemble model fusion, in-process software drops, incident correlation, alert deduplication, and 5-streak recovery.

```mermaid
sequenceDiagram
    autonumber
    actor Atk as Attacker Simulation (ATK-01)
    actor Sensor as Benign Sensor (SENSOR-01)
    participant Runtime as GatewayRuntime
    participant Enforcer as InProcessPolicyEnforcer
    participant Detector as HybridDetector
    participant Store as GatewayStore
    participant SSE as EventSource Stream (/events)

    Note over Atk,Runtime: Phase 1: Attack Window 1 Ingestion (Initial Detection)
    Atk->>Runtime: ingest(TelemetryEvent: UDP Flood, rate=150 pps, device="ATK-01")
    Runtime->>Enforcer: evaluate("ATK-01", event, mode="ACTIVE")
    Enforcer-->>Runtime: PolicyDecision: ALLOW (No previous containment)
    Runtime->>Detector: analyze(event)
    Detector->>Detector: Compute Features: packet_rate=150, udp_ratio=1.0, dev=0.45
    Detector->>Detector: Fusion = min(1.0, 0.40*0.65 + 0.45*0.99 + 0.15*0.80) = 0.825
    Detector-->>Runtime: Decision: ATTACK (score=0.825, severity="HIGH")
    Runtime->>Store: create_incident(device="ATK-01", type="udp_flood", state="DETECTED")
    Runtime->>Store: transition_incident(id, "TRIAGED" -> "RESPONDING")
    Runtime->>Enforcer: isolate("ATK-01", action="ISOLATE", state="CONTAINED")
    Runtime->>Store: transition_incident(id, "CONTAINED")
    Runtime->>Store: create_or_update_alert(incident_id, severity="HIGH")
    Runtime->>SSE: publish("incident", state="CONTAINED")
    Runtime->>SSE: publish("alert", status="ACTIVE")

    Note over Atk,Runtime: Phase 2: Attack Window 2 Ingestion (In-Process Software Intercept)
    Atk->>Runtime: ingest(TelemetryEvent: UDP Flood, rate=160 pps, device="ATK-01")
    Runtime->>Enforcer: evaluate("ATK-01", event, mode="ACTIVE")
    Note over Enforcer: Device actively ISOLATED in software memory
    Enforcer-->>Runtime: PolicyDecision: DROP (drop=True, enforced=True)
    Runtime->>Store: append_telemetry(action="DROP", state="FILTERED")
    Runtime->>Store: record_action(action="DROP", result="SOFTWARE_INTERCEPT")
    Runtime->>SSE: publish("response", action="DROP", provenance="SOFTWARE_INTERCEPT")

    Note over Sensor,Runtime: Phase 3: Attack Stopped — Autonomous Recovery Qualification
    loop 3 Consecutive Benign Windows (Streak 1, 2, 3)
        Sensor->>Runtime: ingest(TelemetryEvent: Normal Baseline, rate=16 pps, device="ATK-01")
        Runtime->>Enforcer: evaluate("ATK-01", event) [Allows baseline observation]
        Runtime->>Detector: analyze(event) -> Decision: NORMAL (score=0.08)
        Runtime->>Runtime: _device_normal_streaks["ATK-01"] += 1
    end
    Note over Runtime: Streak reaches 3 -> Trigger Qualification
    Runtime->>Store: transition_incident(id, "RECOVERING")
    Runtime->>Enforcer: mark_recovering("ATK-01")
    Runtime->>Store: sync_alert_with_incident(state="RECOVERING")
    Runtime->>SSE: publish("incident", state="RECOVERING")

    loop 2 Additional Benign Windows (Streak 4, 5)
        Sensor->>Runtime: ingest(TelemetryEvent: Normal Baseline, rate=15 pps, device="ATK-01")
        Runtime->>Detector: analyze(event) -> Decision: NORMAL
        Runtime->>Runtime: _device_normal_streaks["ATK-01"] += 1
    end
    Note over Runtime: Streak reaches 5 -> Sustained Baseline Verified
    Runtime->>Enforcer: release("ATK-01") [Clear active isolation & rate limiters]
    Runtime->>Store: transition_incident(id, "RESOLVED", recovery_state="VERIFIED")
    Runtime->>Store: sync_alert_with_incident(state="RESOLVED")
    Runtime->>SSE: publish("incident", state="RESOLVED")
    Runtime->>SSE: publish("alert", status="RESOLVED")
```

---

## 7. Class Diagram

The UML Class Diagram models the core Python classes, dataclasses, methods, and relationships implemented in the `aegis_gateway` package.

```mermaid
classDiagram
    class TelemetryEvent {
        +str event_id
        +str timestamp
        +str source_type
        +str device_id
        +str src_ip
        +str dst_ip
        +int src_port
        +int dst_port
        +str protocol
        +int packet_count
        +int byte_count
        +float packet_rate
        +float byte_rate
        +float packet_size
        +str flow_id
        +str tcp_flags
        +str attack_type
        +str label
        +float confidence
        +str model_version
        +str provenance
        +float energy_rate
        +float energy_deviation
        +float trust_score
        +str lifecycle_state
        +str response_action
        +normalize() TelemetryEvent
        +to_dict() dict
        +from_mapping(data) TelemetryEvent
    }

    class Decision {
        +str prediction
        +float confidence
        +str severity
        +list evidence
        +float score
        +str supervised_prediction
        +float anomaly_score
        +str model_version
        +float calibrated_probability
        +as_dict() dict
    }

    class HybridDetector {
        +dict bundle
        +str model_version
        +analyze(event: TelemetryEvent) Decision
    }

    class EnergyModel {
        +float baseline_rate
        +correlate(event: TelemetryEvent) TelemetryEvent
    }

    class IAMService {
        +GatewayStore storage
        +str master_key
        +TokenReplayCache replay_cache
        +dict identities
        +authenticate_device(device_id, token, timestamp, flow_id) tuple
        +enroll_device(device_id, role, psk) dict
        +revoke_device(device_id) dict
        +access(identity, resource) dict
        +adjust_trust(identity, attack, auth_failure, recovered) tuple
    }

    class TokenReplayCache {
        -Lock _lock
        -dict _entries
        +int max_size
        +float retention_seconds
        +check_and_record(device_id, token, timestamp, retention) tuple
        -prune_expired(now_mono) void
        +clear() void
    }

    class ResponseEngine {
        +str mode
        +bool auto
        +bool in_process_enforcement
        +InProcessPolicyEnforcer enforcer
        +evaluate(device_id, event) PolicyDecision
        +plan(event, decision) ResponsePlan
        +isolate(device_id, action, reason) void
        +release(device_id) void
        +reset() void
    }

    class InProcessPolicyEnforcer {
        +bool enabled
        +dict active_isolates
        +dict rate_limiters
        -RLock _lock
        +evaluate(device_id, event, mode) PolicyDecision
        +isolate(device_id, action, reason, state, severity) void
        +mark_recovering(device_id) void
        +set_rate_limit(device_id, capacity, refill_rate) void
        +release(device_id) void
        +reset() void
    }

    class TokenBucket {
        +float capacity
        +float refill_rate
        +float tokens
        +float last_update
        +consume(count) bool
        +reset() void
    }

    class GatewayStore {
        +Path path
        +str master_key
        +connection() Connection
        +initialize() void
        +append_telemetry(event) void
        +create_incident(event, evidence, notes) dict
        +correlate_incident(incident_id, event, evidence, notes) dict
        +transition_incident(incident_id, state, actor, notes) dict
        +find_active_incident(device_id, attack_type) dict
        +create_or_update_alert(incident, event, decision, plan) dict
        +record_action(event_id, incident_id, action, reason, mode) dict
        +record_audit(username, role, action, resource, result, details) void
        +verify_audit_log_integrity() dict
        +upsert_device_identity(device_id, role, auth_key_hash) void
    }

    class GatewayRuntime {
        +Settings settings
        +GatewayStore store
        +HybridDetector detector
        +EnergyModel energy
        +IAMService iam
        +ResponseEngine response
        -RLock _lock
        -dict _simulations
        -dict _device_normal_streaks
        +ingest(event) dict
        +start_simulation(scenario_id, intensity, duration, device_id) dict
        +stop_simulation(scenario_id) list
        +step_device_recovery(device_id) list
        +status() dict
        -_verify_recovery(device_id) void
    }

    GatewayRuntime --> GatewayStore : persists state to
    GatewayRuntime --> HybridDetector : executes inference via
    GatewayRuntime --> EnergyModel : correlates physics via
    GatewayRuntime --> IAMService : verifies identity via
    GatewayRuntime --> ResponseEngine : plans mitigation via
    GatewayRuntime ..> TelemetryEvent : ingests and normalizes

    HybridDetector ..> Decision : produces
    IAMService --> TokenReplayCache : guards against replay via
    ResponseEngine --> InProcessPolicyEnforcer : delegates to
    InProcessPolicyEnforcer *-- TokenBucket : manages per-device limiters
```

---

## 8. Entity-Relationship (ER) Diagram

The Entity-Relationship Diagram defines the complete logical database schema implemented in `aegis_gateway/storage.py` across all 11 normalized SQLite tables, including foreign keys, cardinalities, and constraints.

```mermaid
erDiagram
    telemetry {
        TEXT event_id PK
        TEXT timestamp
        TEXT source_type
        TEXT source_id
        TEXT device_id
        TEXT src_ip
        TEXT dst_ip
        TEXT protocol
        TEXT packet_count
        TEXT byte_count
        TEXT packet_rate
        TEXT byte_rate
        TEXT packet_size
        TEXT flow_id
        TEXT tcp_flags
        TEXT attack_type
        TEXT label
        TEXT confidence
        TEXT energy_consumed
        TEXT energy_rate
        TEXT energy_deviation
        TEXT trust_score
        TEXT response_action
        TEXT lifecycle_state
        TEXT raw_json
    }

    incidents {
        TEXT incident_id PK
        TEXT created_at
        TEXT updated_at
        TEXT event_id
        TEXT device_id
        TEXT source_id
        TEXT attack_type
        TEXT severity
        REAL confidence
        TEXT evidence_json
        TEXT affected_resources
        TEXT energy_impact
        TEXT iam_impact
        TEXT trust_impact
        TEXT response_action
        TEXT response_mode
        TEXT operator
        TEXT lifecycle_state
        TEXT recovery_state
        TEXT resolved_at
        TEXT provenance
    }

    incident_history {
        TEXT history_id PK
        TEXT incident_id FK
        TEXT timestamp
        TEXT previous_state
        TEXT state
        TEXT actor
        TEXT note
        TEXT evidence_json
    }

    actions {
        TEXT action_id PK
        TEXT timestamp
        TEXT event_id
        TEXT incident_id FK
        TEXT action
        TEXT reason
        TEXT policy
        TEXT mode
        TEXT result
        TEXT provenance
    }

    admin_alerts {
        TEXT alert_id PK
        TEXT incident_id FK "UNIQUE"
        TEXT timestamp
        TEXT severity
        TEXT attack_type
        TEXT device_id
        TEXT source_id
        TEXT target
        REAL confidence
        TEXT detection_reason
        TEXT lifecycle_state
        TEXT recommended_action
        TEXT current_action
        TEXT acknowledgement_state
        TEXT acknowledged_by
        TEXT acknowledged_at
        TEXT status
        TEXT evidence_json
    }

    iam_events {
        TEXT iam_event_id PK
        TEXT timestamp
        TEXT identity
        TEXT role
        TEXT authentication_status
        TEXT authorization_status
        TEXT access_request
        TEXT decision
        TEXT reason
        TEXT provenance
    }

    trust_history {
        TEXT trust_event_id PK
        TEXT timestamp
        TEXT identity
        REAL score
        REAL delta
        TEXT reason
        TEXT provenance
    }

    device_identities {
        TEXT device_id PK
        TEXT role
        TEXT status
        TEXT auth_key_hash
        REAL trust_score
        INTEGER failures
        TEXT mfa_status
        TEXT created_at
        TEXT last_seen
    }

    admin_users {
        TEXT user_id PK
        TEXT username "UNIQUE"
        TEXT password_hash
        TEXT role
        TEXT status
        INTEGER mfa_enabled
        TEXT mfa_status
        TEXT created_at
        TEXT last_login
    }

    admin_audit_log {
        TEXT event_id PK
        TEXT timestamp
        TEXT username
        TEXT role
        TEXT action
        TEXT resource
        TEXT resource_id
        TEXT result
        TEXT source_ip
        TEXT details
        TEXT prev_hash "SHA-256"
        TEXT record_hash "SHA-256 Chain"
    }

    metadata {
        TEXT metadata_id PK
        TEXT kind
        TEXT version
        TEXT created_at
        TEXT payload_json
    }

    incidents ||--o{ incident_history : "has state history (CASCADE)"
    incidents ||--o| admin_alerts : "synchronizes with (1:1 UNIQUE, CASCADE)"
    incidents ||--o{ actions : "triggers mitigation actions (SET NULL)"

    device_identities ||--o{ trust_history : "records score adjustments"
    device_identities ||--o{ iam_events : "authenticates requests"

    admin_users ||--o{ admin_audit_log : "performs audited actions"
```

---

## 9. Deployment Diagram (Laboratory User-Space Sandbox)

### 9.1 Architecture and Node Classification Narrative
The Deployment Diagram models the physical and logical runtime environment of the AICG Edge Gateway in its **current laboratory verification state**. To maintain absolute academic honesty, this diagram explicitly models the system as executing entirely inside an unprivileged user-space Linux environment on an x86_64 host workstation. It does **not** depict or assert physical hardware deployments (e.g., DIN-rail PLCs, hardware current sensors, or physical edge routers), which remain designated for future scope.

The deployment topology categorizes nodes into four distinct operational classifications:
1. **Actual Software / Runtime Node (`GatewayProcess`):** The core `aegis_gateway` daemon running as an unprivileged user-space Linux process (Python 3.14.x). It hosts the Flask WSGI server (port 8000), REST API handlers, the Server-Sent Events (`/events`) streaming engine, the `EnergyModel` physics engine, `IAMService` with in-memory `TokenReplayCache`, the Platt-calibrated `HybridDetector`, and the `InProcessPolicyEnforcer`.
2. **Simulation / Test Node (`SimEnvironment`):** In-process synthetic generator threads executing within the same Python process (`aegis_gateway/scenarios.py`), generating background benign baseline traffic (14–18 pps) and 10 controlled DDoS/anomaly attack profiles. Additionally, offline trace ingestion adapters parse discrete-event simulation datasets from NS-3.48 (`ns-allinone-3.48/ns-3.48/scratch/`), Contiki-NG / Cooja 6LoWPAN mote logs (`/home/kali/contiki-ng/examples/ai_edge_iiot/data/`), and raw PCAP captures without transmitting live physical packets.
3. **Persistent Storage Node (`StorageArtifacts`):** Local filesystem storage hosting the single-file SQLite 3 relational database (`data/aegis_gateway.sqlite3`) running under Write-Ahead Logging (`WAL`) mode with 11 normalized tables and the SHA-256 forward-chained ledger, alongside serialized Scikit-learn joblib model bundles (`models/hybrid_detector.joblib` and `models/realistic_detector_v1.joblib`).
4. **Operator Interface Node (`ClientNode`):** A modern HTML5/ES6+ web browser (Chromium / Firefox) executing on the local workstation or adjacent LAN client, rendering the responsive dark-mode industrial SOC HMI (`/`), real-time SVG network topology, 7-stage incident stepper, and the red-team Attacker Simulation Console (`/attacker`).

> [!CAUTION]
> **Defensive Academic Laboratory Boundary:**  
> All edge sensors (`SENSOR-01` to `SENSOR-03`), industrial sink targets (`PLC-SINK`), and adversary nodes (`ATK-01`) execute as software-modeled entities in memory. The gateway performs in-process software drops (`SOFTWARE_INTERCEPT`) and does not manipulate host Linux routing tables or kernel firewall filters (`iptables`, `nftables`).

### 9.2 Mermaid Deployment Diagram Specification

```mermaid
flowchart TD
    subgraph HostNode ["Node: Linux Workstation Execution Environment (x86_64 OS / User-Space Sandbox)"]
        
        subgraph GatewayProcess ["Software Node: aegis_gateway Daemon Process (Python 3.14 / User Space)"]
            APIService["Flask Web & API Service<br/>(:8000 / HTTP / JSON)"]
            SSEService["EventSource SSE Streaming Engine<br/>(/events / text/event-stream)"]
            RuntimeCoord["GatewayRuntime Coordinator<br/>(1-Second Window Loop)"]
            EnergyEngine["EnergyModel<br/>(Cause-Based Physics Formulas)"]
            IAMService["IAMService & TokenReplayCache<br/>(HMAC-SHA256 & 300s Sliding Cache)"]
            HybridDetectorNode["HybridDetector Engine<br/>(0.40 Rule + 0.45 RF + 0.15 iForest)"]
            PolicyEnforcerNode["InProcessPolicyEnforcer<br/>(Token Bucket & Software Drops)"]
        end

        subgraph StorageNode ["Persistent Storage Node: Local Linux Filesystem"]
            SQLiteFile[("SQLite 3 Database File<br/>(data/aegis_gateway.sqlite3)<br/>WAL Mode / 11 Tables / SHA-256 Ledger")]
            ModelFiles["Machine Learning Artifacts<br/>(models/hybrid_detector.joblib<br/>models/realistic_detector_v1.joblib)"]
        end

        subgraph SimNode ["Simulation & Trace Node: In-Process & Offline Generators"]
            AttackThreads["In-Process Attack Simulation Threads<br/>(10 Attack Profiles in scenarios.py)"]
            BaselineThread["Quiescent Baseline Daemon Thread<br/>(14-18 pps / 55 mW Normal Rhythm)"]
            TraceFiles["Offline Trace Storage & Adapters<br/>- NS-3.48 CSV/PCAP Traces<br/>- Cooja 6LoWPAN Mote Logs<br/>- PCAP Window Replayer"]
        end

        subgraph ClientNode ["Operator Interface Node: Modern Web Browser Client"]
            SOCHMI["Industrial SOC Dashboard<br/>(dashboard/templates/index.html)<br/>- Real-Time SVG Network Map<br/>- 7-Stage Incident Lifecycle Stepper<br/>- Detection Pipeline Card 5"]
            AttackerHMI["Attacker Simulation Console<br/>(dashboard/templates/attacker.html)<br/>- Red-Team Scenario Cockpit"]
        end
    end

    %% Internal Communication & Dependencies
    AttackThreads -->|"In-Memory Synthetic Windows"| RuntimeCoord
    BaselineThread -->|"Quiescent Background Windows"| RuntimeCoord
    TraceFiles -->|"POST /api/ns3/import & /cooja/import"| APIService

    APIService <--> RuntimeCoord
    SSEService <--> RuntimeCoord
    RuntimeCoord --> EnergyEngine
    RuntimeCoord --> IAMService
    RuntimeCoord --> HybridDetectorNode
    RuntimeCoord --> PolicyEnforcerNode

    RuntimeCoord <-->|"Read / Write (WAL Mode Pragmas)"| SQLiteFile
    HybridDetectorNode <-->|"joblib.load() / Deserialized Model"| ModelFiles

    SOCHMI <-->|"HTTP / REST API (Port 8000)"| APIService
    SOCHMI <--"Persistent SSE Push Stream (/events)"-- SSEService
    AttackerHMI <-->|"POST /api/simulations/start"| APIService
```

