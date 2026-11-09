"""Hybrid, explainable detector used by the canonical gateway runtime."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import joblib
import numpy as np

from .schema import TelemetryEvent


FEATURE_VERSION = "window-features-v2"
MODEL_VERSION = "rules-v2-untrained"
FEATURES = [
    "packet_count", "byte_count", "packet_rate", "byte_rate", "unique_sources", "unique_destinations",
    "packet_size", "udp_ratio", "tcp_ratio", "icmp_ratio", "syn_ratio", "flow_count", "cpu_activity",
    "memory_activity", "energy_deviation",
]


def feature_mapping(event: TelemetryEvent) -> dict[str, float]:
    count = max(float(event.packet_count or 0), 1.0)
    protocol = (event.protocol or "").upper()
    return {
        "packet_count": count, "byte_count": float(event.byte_count or 0), "packet_rate": float(event.packet_rate or 0),
        "byte_rate": float(event.byte_rate or 0), "unique_sources": float(event.unique_sources or 0),
        "unique_destinations": float(event.unique_destinations or 0), "packet_size": float(event.packet_size or 0),
        "udp_ratio": 1.0 if protocol == "UDP" else 0.0, "tcp_ratio": 1.0 if protocol == "TCP" else 0.0,
        "icmp_ratio": 1.0 if protocol in {"ICMP", "ICMPV6"} else 0.0,
        "syn_ratio": 1.0 if "S" in (event.tcp_flags or "") else 0.0,
        "flow_count": float(event.unique_sources or 1), "cpu_activity": float(event.cpu_activity or 0),
        "memory_activity": float(event.memory_activity or 0), "energy_deviation": float(event.energy_deviation or 0),
    }


@dataclass
class Decision:
    prediction: str
    confidence: float
    severity: str
    evidence: list[str]
    score: float
    supervised_prediction: str | None
    anomaly_score: float | None
    model_version: str
    feature_version: str = FEATURE_VERSION
    calibrated_probability: float | None = None

    def as_dict(self) -> dict[str, Any]:
        return self.__dict__.copy()


class HybridDetector:
    """Rules always remain available; RF/Isolation Forest enhance a trained model.

    ``confidence`` is an ensemble decision score, not a calibrated probability,
    unless training metadata reports calibration separately.
    """

    def __init__(self, model_path: Path | None = None):
        self.bundle: dict[str, Any] | None = None
        if model_path and model_path.exists():
            candidate = joblib.load(model_path)
            if isinstance(candidate, dict) and "classifier" in candidate:
                self.bundle = candidate

    @property
    def model_version(self) -> str:
        return str(self.bundle.get("model_version")) if self.bundle else MODEL_VERSION

    def analyze(self, event: TelemetryEvent) -> Decision:
        values = feature_mapping(event)
        evidence: list[str] = []
        rule_score = 0.0
        rate = values["packet_rate"]
        sources = values["unique_sources"]
        if rate >= 100:
            ratio = rate / 20.0
            evidence.append(f"Packet rate is {ratio:.1f}x the 20 pps modeled baseline.")
            rule_score += min(.55, .15 + ratio / 12)
        if sources >= 5:
            evidence.append(f"Unique source count is {int(sources)} in this window.")
            rule_score += .12
        if values["udp_ratio"] and rate >= 80:
            evidence.append("UDP dominates a high-rate observation window.")
            rule_score += .16
        if values["syn_ratio"]:
            evidence.append("TCP SYN flag was observed in the traffic window.")
            rule_score += .25
        if values["icmp_ratio"] and rate >= 60:
            evidence.append("ICMP/ICMPv6 dominates a high-rate observation window.")
            rule_score += .16
        if values["energy_deviation"] >= .15:
            evidence.append("Modelled energy rate rose concurrently with traffic/resource activity.")
            rule_score += .08
        rule_score = min(1.0, rule_score)
        if event.attack_type:
            evidence.append(f"Source scenario labels this controlled profile as {event.attack_type}.")


        supervised_prediction, anomaly_score, model_score = None, None, 0.0
        calibrated_probability: float | None = None
        if self.bundle:
            import pandas as pd
            features_list = self.bundle["features"]
            row_data = {name: [values[name]] for name in features_list}
            df_sample = pd.DataFrame(row_data)
            clf = self.bundle.get("calibrated_classifier") or self.bundle["classifier"]
            classes = list(clf.classes_)
            probabilities = clf.predict_proba(df_sample)[0]
            supervised_prediction = str(classes[int(np.argmax(probabilities))])
            attack_index = classes.index("ATTACK") if "ATTACK" in classes else int(np.argmax(probabilities))
            model_score = float(probabilities[attack_index])
            if self.bundle.get("calibrated"):
                calibrated_probability = round(model_score, 4)
            anomaly = self.bundle.get("anomaly")
            scaler = self.bundle.get("anomaly_scaler")
            if anomaly is not None and scaler is not None:
                scaled = scaler.transform(df_sample)
                # Map IsolationForest decision_function: positive for normal inliers, negative for outliers.
                # Bounded mapping in [0.0, 1.0] where inliers yield < 0.35 and anomalous outliers yield > 0.60.
                raw_dfunc = float(anomaly.decision_function(scaled)[0])
                anomaly_score = max(0.0, min(1.0, round(0.5 - raw_dfunc * 4.0, 4)))
                if anomaly_score >= .6:
                    evidence.append("Isolation Forest found the window unlike benign training windows.")

            # Explainable documentation of contradictory evidence between heuristic rules and ML
            if rule_score >= 0.40 and model_score < 0.30:
                evidence.append(f"Heuristic rule activation ({rule_score:.2f}) was dampened by low ML attack probability ({model_score:.2f}).")
            elif model_score >= 0.70 and rule_score < 0.20:
                evidence.append(f"ML model detected statistical attack pattern ({model_score:.2f}) despite weak heuristic rule activation ({rule_score:.2f}).")

        if self.bundle:
            # Audited Phase 23 Wave 2 candidate fusion: 0.40 Rule + 0.45 Supervised RF + 0.15 Isolation Forest
            score = min(1.0, .40 * rule_score + .45 * model_score + .15 * (anomaly_score or 0.0))
        else:
            score = min(1.0, rule_score)
        attack = score >= .50
        if not evidence:
            evidence.append("Traffic is within the configured demonstration baseline; no attack signature fired.")
        if attack:
            severity = "CRITICAL" if score >= .85 else "HIGH" if score >= .68 else "MEDIUM"
            return Decision("ATTACK", round(score, 3), severity, evidence, round(score, 3), supervised_prediction, anomaly_score, self.model_version, calibrated_probability=calibrated_probability)
        return Decision("NORMAL", round(max(0.0, 1 - score), 3), "INFO", evidence, round(score, 3), supervised_prediction, anomaly_score, self.model_version, calibrated_probability=calibrated_probability)
