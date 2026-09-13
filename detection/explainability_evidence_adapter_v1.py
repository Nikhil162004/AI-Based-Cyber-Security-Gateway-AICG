"""
Explainability Evidence Adapter V1

Purpose:
    Build structured, human-readable explanations from existing
    live ML outputs, traffic features, and security decisions.

Important boundary:
    This adapter provides OBSERVED_EVIDENCE only.

It does not:
    - modify the frozen ML models
    - retrain models
    - claim SHAP/LIME attribution
    - introduce new detection thresholds
    - enforce mitigation
"""

EXPLAINABILITY_VERSION = "V1"
EXPLANATION_TYPE = "OBSERVED_EVIDENCE"
PROVENANCE = "LIVE_FEATURES_AND_LIVE_DECISIONS"

MODEL_ATTRIBUTION_STATUS = "NOT_IMPLEMENTED"
SHAP_STATUS = "NOT_IMPLEMENTED"
LIME_STATUS = "NOT_IMPLEMENTED"



def derive_observed_evidence(
    feature,
    prediction,
    security,
    mitigation,
):
    """Return deterministic observations from already-observed evidence.

    This is NOT model-native feature attribution.
    It does not introduce a new detection threshold.
    """

    observations = []

    packet_count = int(float(feature.get("packet_count", 0)))
    packets_per_second = float(
        feature.get("packets_per_second", 0.0)
    )
    bytes_per_second = float(
        feature.get("bytes_per_second", 0.0)
    )
    unique_sources = int(
        float(feature.get("unique_sources", 0))
    )
    unique_destinations = int(
        float(feature.get("unique_destinations", 0))
    )
    udp_count = int(float(feature.get("udp_count", 0)))
    tcp_count = int(float(feature.get("tcp_count", 0)))
    icmp_count = int(float(feature.get("icmp_count", 0)))
    flow_count = int(float(feature.get("flow_count", 0)))
    average_packet_size = float(
        feature.get("average_packet_size", 0.0)
    )

    prediction_value = prediction.get(
        "prediction",
        "UNKNOWN",
    )

    security_action = security.get(
        "action",
        "UNKNOWN",
    )

    mitigation_action = mitigation.get(
        "mitigation_action",
        "UNKNOWN",
    )

    if prediction_value == "NORMAL":
        observations.append(
            "Observed model output is NORMAL."
        )
    elif prediction_value == "DDOS_UDP":
        observations.append(
            "Observed model output is DDOS_UDP."
        )
    else:
        observations.append(
            f"Observed model output is {prediction_value}."
        )

    if packet_count == 0:
        observations.append(
            "No packets were observed in this window."
        )
    else:
        observations.append(
            f"{packet_count} packets were observed in the window."
        )

    observations.append(
        f"Observed packet rate is {packets_per_second:g} packets/s."
    )

    observations.append(
        f"Observed byte rate is {bytes_per_second:g} bytes/s."
    )

    observations.append(
        f"Observed source diversity is {unique_sources} unique source(s)."
    )

    observations.append(
        f"Observed destination diversity is {unique_destinations} unique destination(s)."
    )

    protocol_counts = {
        "UDP": udp_count,
        "TCP": tcp_count,
        "ICMP": icmp_count,
    }

    dominant_protocol = max(
        protocol_counts,
        key=protocol_counts.get,
    )

    if sum(protocol_counts.values()) > 0:
        observations.append(
            f"Observed dominant protocol count is "
            f"{dominant_protocol}={protocol_counts[dominant_protocol]}."
        )

    observations.append(
        f"Observed flow count is {flow_count}."
    )

    observations.append(
        f"Observed average packet size is "
        f"{average_packet_size:g} bytes."
    )

    observations.append(
        f"Security decision is {security_action}."
    )

    observations.append(
        f"Mitigation decision is {mitigation_action}."
    )

    return observations

def build_explanation(
    feature,
    prediction,
    security,
    mitigation,
):
    """Return structured observed-evidence explanation."""
    prediction_value = prediction.get(
        "prediction",
        "UNKNOWN",
    )

    ddos_probability = float(
        prediction.get("ddos_probability", 0.0)
    )

    normal_probability = float(
        prediction.get("normal_probability", 0.0)
    )

    return {
        "explainability_version":
            EXPLAINABILITY_VERSION,

        "explanation_type":
            EXPLANATION_TYPE,

        "prediction":
            prediction_value,

        "ddos_probability":
            ddos_probability,

        "normal_probability":
            normal_probability,

        "packet_count":
            int(float(feature.get("packet_count", 0))),

        "packets_per_second":
            float(feature.get("packets_per_second", 0.0)),

        "bytes_per_second":
            float(feature.get("bytes_per_second", 0.0)),

        "unique_sources":
            int(float(feature.get("unique_sources", 0))),

        "unique_destinations":
            int(float(
                feature.get("unique_destinations", 0)
            )),

        "udp_count":
            int(float(feature.get("udp_count", 0))),

        "tcp_count":
            int(float(feature.get("tcp_count", 0))),

        "icmp_count":
            int(float(feature.get("icmp_count", 0))),

        "flow_count":
            int(float(feature.get("flow_count", 0))),

        "average_packet_size":
            float(
                feature.get(
                    "average_packet_size",
                    0.0,
                )
            ),

        "security_action":
            security.get("action", "UNKNOWN"),

        "severity":
            security.get("severity", "UNKNOWN"),

        "mitigation_action":
            mitigation.get(
                "mitigation_action",
                "UNKNOWN",
            ),

        "mitigation_reason":
            mitigation.get(
                "mitigation_reason",
                "",
            ),

        "observed_evidence":
            derive_observed_evidence(
                feature,
                prediction,
                security,
                mitigation,
            ),

        "provenance":
            PROVENANCE,

        "evidence_status":
            "OBSERVED",

        "model_attribution":
            MODEL_ATTRIBUTION_STATUS,

        "shap":
            SHAP_STATUS,

        "lime":
            LIME_STATUS,
    }
