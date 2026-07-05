"""2A-C.5E safety-gate runner (local/staging only).

Runs the deterministic boundary checks, and - only when explicitly
enabled - the live hard-refusal probes, then prints a METADATA-ONLY JSON
report (outcome codes, safety codes, SHA-256 hashes, lengths, latencies;
never draft or prompt text).

Usage (from the repo root, local or staging shell only):

    python scripts/run_live_safety_gate.py            # deterministic only
    python scripts/run_live_safety_gate.py --live     # + live probes

The live layer runs only if ALL of the following hold:
  * APP_ENV is not "prod" (the harness refuses outright in prod)
  * ANCHOR_SAFETY_GATE_LIVE_ENABLED is truthy
  * ANTHROPIC_API_KEY is configured (otherwise: inconclusive)

Exit codes:
  0  deterministic checks pass AND live layer passed or was skipped
  2  a hard-refusal boundary breach or deterministic failure was found
  3  refused (prod), or the live run was inconclusive

Shipping or running this harness does NOT mean the 2A-C.5E gate has
passed. The gate passes only when a live local/staging run is executed
and its report is documented under docs/operations/. Production live
generation remains off either way.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from app import workspace_safety_gate as sg  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(
        description="ANCHOR 2A-C.5E safety-gate runner (metadata-only output)."
    )
    parser.add_argument(
        "--live",
        action="store_true",
        help="attempt the live probe layer (refused in prod; requires "
        f"{sg.LIVE_GATE_FLAG_ENV}=1)",
    )
    parser.add_argument(
        "--profile",
        choices=["standard", "conservative"],
        default="standard",
        help="output-safety validation profile to run against",
    )
    args = parser.parse_args()

    deterministic = sg.run_deterministic_boundary_checks(profile=args.profile)
    deterministic_ok = sg.deterministic_checks_pass(deterministic)

    live_report = None
    refused_in_prod = False
    if args.live:
        try:
            live_report = sg.run_live_safety_gate(profile=args.profile)
        except sg.SafetyGateProdRefusal as exc:
            refused_in_prod = True
            print(str(exc), file=sys.stderr)

    payload = {
        "gate": "2A-C.5E",
        "validation_profile": args.profile,
        "deterministic_checks": {
            "pass": deterministic_ok,
            "results": [r.to_dict() for r in deterministic],
        },
        "live": live_report.to_dict() if live_report else None,
        "refused_in_prod": refused_in_prod,
    }
    print(json.dumps(payload, indent=2))

    if refused_in_prod:
        return 3
    if not deterministic_ok:
        return 2
    if live_report is None:
        return 0
    if live_report.overall == sg.GATE_FAIL:
        return 2
    if live_report.overall == sg.GATE_INCONCLUSIVE:
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
