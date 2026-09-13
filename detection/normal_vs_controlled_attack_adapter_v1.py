from pathlib import Path
import json


RESULT_FILE = Path(
    "results/normal_vs_controlled_attack_v1.json"
)


def get_normal_vs_controlled_attack_context():
    """
    Return the existing Phase 6 controlled NS-3
    Normal-vs-Attack comparison context.

    This adapter is OFFLINE / CONTROLLED / VALIDATED.
    It does not execute NS-3, generate traffic,
    train models, or modify the live gateway pipeline.
    """

    if not RESULT_FILE.exists():
        return {
            "status": "UNAVAILABLE",
            "version": "V1",
            "comparison_type": "NORMAL_VS_CONTROLLED_ATTACK",
        }

    return json.loads(
        RESULT_FILE.read_text()
    )


if __name__ == "__main__":
    context = get_normal_vs_controlled_attack_context()

    print("NORMAL VS CONTROLLED ATTACK ADAPTER V1")
    print(
        "Status:",
        context.get("status")
    )
    print(
        "Total windows:",
        context.get("total_windows")
    )
    print(
        "Normal windows:",
        context.get("normal_windows")
    )
    print(
        "Controlled attack windows:",
        context.get("controlled_attack_windows")
    )

    for scenario in context.get(
        "scenarios",
        []
    ):
        print(
            scenario["scenario"],
            "|",
            "normal=",
            scenario["normal_windows"],
            "|",
            "attack=",
            scenario["attack_windows"],
        )
