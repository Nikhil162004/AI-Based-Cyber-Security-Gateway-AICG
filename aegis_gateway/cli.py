"""Command line entrypoints for reproducible, safe laboratory workflows."""

from __future__ import annotations

import argparse
import json
import os
import time
from pathlib import Path

from .adapters import ns3_csv_events, pcap_events
from .api import create_app
from .config import Settings
from .ml import generate_dataset, train_and_evaluate
from .runtime import GatewayRuntime


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog="aegis-gateway", description="AEGIS-OT safe laboratory gateway")
    root.add_argument("--database", type=Path, default=None, help="override database path")
    sub = root.add_subparsers(dest="command", required=True)
    run = sub.add_parser("run", help="run Flask HMI/API with SSE")
    run.add_argument("--host", default=None); run.add_argument("--port", type=int, default=None)
    demo = sub.add_parser("demo", help="run bounded local normal + attack demonstration")
    demo.add_argument("--scenario", default="udp_flood"); demo.add_argument("--seconds", type=float, default=8); demo.add_argument("--intensity", type=int, default=3)
    gen = sub.add_parser("generate-dataset", help="generate a synthetic, provenance-labelled dataset")
    gen.add_argument("--output", type=Path, default=Settings().dataset_dir / "synthetic_lab_v2.csv"); gen.add_argument("--samples", type=int, default=35); gen.add_argument("--seed", type=int, default=20260913)
    train = sub.add_parser("train", help="train RF + Isolation Forest and report grouped results")
    train.add_argument("--dataset", type=Path, default=Settings().dataset_dir / "synthetic_lab_v2.csv"); train.add_argument("--seed", type=int, default=20260913)
    ns3 = sub.add_parser("import-ns3", help="import an existing NS-3 CSV as SIMULATED telemetry")
    ns3.add_argument("csv", type=Path); ns3.add_argument("--scenario", default=None)
    pcap = sub.add_parser("replay-pcap", help="replay a local PCAP as REPLAYED telemetry; no transmission")
    pcap.add_argument("pcap", type=Path)
    export = sub.add_parser("export", help="export durable evidence")
    export.add_argument("kind", choices=["telemetry", "incidents", "events", "actions", "audit", "alerts"]); export.add_argument("--format", choices=["json", "csv"], default="json"); export.add_argument("--output", type=Path, required=True)
    return root


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    db_path = args.database or (Path(os.getenv("AEGIS_DATABASE_PATH")) if os.getenv("AEGIS_DATABASE_PATH") else None)
    settings = Settings(database_path=db_path) if db_path else Settings()
    if args.command == "generate-dataset": print(json.dumps(generate_dataset(args.output, samples_per_campaign=args.samples, seed=args.seed), indent=2)); return 0
    if args.command == "train":
        if not args.dataset.exists(): generate_dataset(args.dataset, seed=args.seed)
        report = train_and_evaluate(args.dataset, settings.model_path, settings.report_dir / "evaluation.json", seed=args.seed)
        print(json.dumps({"report": str(settings.report_dir / "evaluation.json"), "test": report["test"], "scenario_held_out": report["scenario_held_out"]}, indent=2)); return 0
    runtime = GatewayRuntime(settings)
    if args.command == "run":
        app = create_app(runtime); app.run(host=args.host or settings.host, port=args.port or settings.port, debug=False, threaded=True); return 0
    if args.command == "demo":
        runtime.start_simulation("normal", 1, duration=2)
        time.sleep(2.2); result = runtime.start_simulation(args.scenario, args.intensity, duration=args.seconds)
        time.sleep(args.seconds + .5); runtime.start_simulation("normal", 1, duration=4); time.sleep(4.2)
        print(json.dumps({"demo": result, "status": runtime.status(), "incidents": runtime.store.incidents()}, indent=2)); return 0
    if args.command == "import-ns3":
        count = sum(1 for event in ns3_csv_events(args.csv, args.scenario) for _ in [runtime.ingest(event)])
        print(json.dumps({"imported": count, "provenance": "SIMULATED", "source": str(args.csv)})); return 0
    if args.command == "replay-pcap":
        count = sum(1 for event in pcap_events(args.pcap) for _ in [runtime.ingest(event)])
        print(json.dumps({"replayed": count, "provenance": "REPLAYED", "transmitted": False})); return 0
    if args.command == "export":
        args.output.parent.mkdir(parents=True, exist_ok=True); args.output.write_text(runtime.store.export(args.kind, args.format), encoding="utf-8")
        print(args.output); return 0
    return 2


if __name__ == "__main__": raise SystemExit(main())
