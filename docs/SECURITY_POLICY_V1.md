# Security Policy V1

## 1. Purpose

Security Policy V1 converts the validated machine-learning prediction from the gateway ML bridge into a security action and severity level.

The policy is host-side and does not directly modify Contiki networking or block traffic.

## 2. Policy Rules

| ML Prediction | Action | Severity |
|---|---|---|
| NORMAL | ALLOW | NORMAL |
| DDOS_UDP | ALERT | HIGH |

## 3. Input Validation

The policy accepts only these ML predictions:

- NORMAL
- DDOS_UDP

Normal and DDoS probabilities must each be within the inclusive range 0.0 to 1.0.

Invalid predictions and invalid probability values raise a ValueError.

NaN and infinity values are rejected by the probability range validation.

## 4. Integration

Current decision pipeline:

NS-3 Feature Vector
→ NS-3 V3 ML Inference
→ gateway_ml_bridge_v1
→ Security Policy V1
→ Gateway Security Decision V1

## 5. Validation Status

Security Policy V1 was tested for:

- NORMAL prediction
- DDOS_UDP prediction
- Unsupported prediction
- Probability greater than 1
- Negative probability
- NaN probability
- Infinity probability

The policy was also integrated with the validated NS-3 ML bridge and tested against representative:

- NORMAL traffic
- LOW DDoS
- MIDLOW DDoS
- MID DDoS
- BASELINE DDoS

All integrated representative cases produced the expected policy decision.

## 6. Enforcement Boundary

V1 stops at the decision layer.

Implemented:

- ML prediction
- Probability handling
- ALLOW decision
- ALERT decision
- Severity classification

Not implemented:

- Automatic packet blocking
- Device isolation
- Firewall rule modification
- Contiki routing modification
- Physical network disconnection

These functions belong to a future enforcement layer and must be validated separately.

## 7. Artifact

Source:

detection/security_policy_v1.py

SHA-256:

578e0a4f287407b72b3f8d67a52bfeb56a16d6b757d447ac413462541da224fc

## 8. Status

Security Policy V1: VALIDATED AND FROZEN

Future changes should use a new policy version rather than silently changing V1.
