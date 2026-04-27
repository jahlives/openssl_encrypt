#!/usr/bin/env python3
"""
Standalone CLI for the tamper-evident audit chain.

Invoke via:

    python -m openssl_encrypt.modules.audit_cli verify [--log PATH] [--seed PATH]
                                                       [--state PATH] [--json]
    python -m openssl_encrypt.modules.audit_cli status [--log-dir PATH] [--json]

Exit codes (verify):
    0 — chain intact
    1 — I/O error (log/seed/state missing or unreadable)
    2 — chain broken (tamper, gap, MAC mismatch, etc.)
    3 — required key material missing (seed or state file)

A future commit will fold this into the main ``openssl_encrypt`` argparse
tree as ``openssl_encrypt audit ...``; keeping it standalone for now keeps
the diff small and lets the verifier be invoked from a clean Python that
doesn't pull in the whole CLI stack.
"""

import argparse
import json
import logging
import sys
from dataclasses import asdict
from pathlib import Path
from typing import List, Optional

from .audit_chain import ChainState
from .audit_verifier import VerificationReport, verify_chain

EXIT_OK = 0
EXIT_IO_ERROR = 1
EXIT_BROKEN = 2
EXIT_MISSING_KEY = 3

DEFAULT_LOG_DIR = Path.home() / ".openssl_encrypt"


def _default_log_paths(log_path: Path) -> List[Path]:
    """Return [<rotated...>, current] in oldest→newest order."""
    log_dir = log_path.parent
    base_name = log_path.name
    rotated: List[Path] = []
    # security-audit.log.5 → ... → security-audit.log.1 → security-audit.log
    for i in range(5, 0, -1):
        candidate = log_dir / f"{base_name}.{i}"
        if candidate.exists():
            rotated.append(candidate)
    return rotated + [log_path]


def _format_report_human(report: VerificationReport, log_paths: List[Path]) -> str:
    lines: List[str] = []
    if report.intact:
        lines.append(f"Chain INTACT: {report.records_verified} records verified.")
        lines.append(
            f"  range: seq=[{report.first_seq}..{report.last_seq}] across {len(log_paths)} file(s)"
        )
    else:
        lines.append(f"Chain BROKEN at seq={report.failures[0].seq}.")
        lines.append(f"  records verified before failure: {report.records_verified}")
        for f in report.failures:
            lines.append(f"  - seq={f.seq}  reason={f.reason}")
            lines.append(f"      {f.message}")
    return "\n".join(lines)


def _report_to_json(report: VerificationReport) -> dict:
    return {
        "intact": report.intact,
        "records_verified": report.records_verified,
        "first_seq": report.first_seq,
        "last_seq": report.last_seq,
        "failures": [asdict(f) for f in report.failures],
    }


def _cmd_verify(args: argparse.Namespace) -> int:
    log_path = Path(args.log) if args.log else DEFAULT_LOG_DIR / "security-audit.log"
    seed_path = Path(args.seed) if args.seed else DEFAULT_LOG_DIR / "audit-seed.bin"
    state_path = Path(args.state) if args.state else DEFAULT_LOG_DIR / "audit-state.json"

    if not seed_path.exists():
        msg = f"audit verify: seed file not found at {seed_path}"
        if args.json:
            print(json.dumps({"error": "missing_seed", "path": str(seed_path)}))
        else:
            print(msg, file=sys.stderr)
        return EXIT_MISSING_KEY

    try:
        seed = seed_path.read_bytes()
    except OSError as exc:
        if args.json:
            print(json.dumps({"error": "io_error", "message": str(exc)}))
        else:
            print(f"audit verify: cannot read seed: {exc}", file=sys.stderr)
        return EXIT_IO_ERROR

    state: Optional[ChainState] = None
    if state_path.exists():
        try:
            state = ChainState.load(state_path)
        except Exception as exc:
            if args.json:
                print(json.dumps({"error": "state_load_error", "message": str(exc)}))
            else:
                print(f"audit verify: cannot load state: {exc}", file=sys.stderr)
            return EXIT_IO_ERROR

    if not log_path.exists():
        if args.json:
            print(json.dumps({"error": "missing_log", "path": str(log_path)}))
        else:
            print(f"audit verify: log not found at {log_path}", file=sys.stderr)
        return EXIT_IO_ERROR

    log_paths = _default_log_paths(log_path)
    report = verify_chain(
        log_paths,
        seed=seed,
        expected_first_seq=args.from_seq,
        state=state,
    )

    if args.json:
        print(json.dumps(_report_to_json(report)))
    else:
        print(_format_report_human(report, log_paths))

    return EXIT_OK if report.intact else EXIT_BROKEN


def _cmd_status(args: argparse.Namespace) -> int:
    log_dir = Path(args.log_dir) if args.log_dir else DEFAULT_LOG_DIR
    log_path = log_dir / "security-audit.log"
    seed_path = Path(args.seed) if getattr(args, "seed", None) else log_dir / "audit-seed.bin"
    state_path = Path(args.state) if getattr(args, "state", None) else log_dir / "audit-state.json"

    info = {
        "log_dir": str(log_dir),
        "log_present": log_path.exists(),
        "log_size_bytes": log_path.stat().st_size if log_path.exists() else 0,
        "seed_present": seed_path.exists(),
        "state_present": state_path.exists(),
    }
    if state_path.exists():
        try:
            state = ChainState.load(state_path)
            info["current_seq"] = state.current_seq
            info["last_record_hash"] = state.last_record_hash
            info["last_anchor_seq"] = state.last_anchor_seq
            info["state_version"] = state.version
        except Exception as exc:
            info["state_error"] = str(exc)

    if args.json:
        print(json.dumps(info, sort_keys=True))
    else:
        for key in (
            "log_dir",
            "log_present",
            "log_size_bytes",
            "seed_present",
            "state_present",
            "current_seq",
            "last_record_hash",
            "last_anchor_seq",
            "state_version",
            "state_error",
        ):
            if key in info:
                print(f"{key}: {info[key]}")
    return EXIT_OK


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="audit",
        description="Verify and inspect the tamper-evident audit chain.",
    )
    sub = parser.add_subparsers(dest="action", required=True, metavar="action")

    verify = sub.add_parser("verify", help="Verify the audit chain.")
    verify.add_argument("--log", help="Path to security-audit.log (default: ~/.openssl_encrypt/)")
    verify.add_argument("--seed", help="Path to audit-seed.bin")
    verify.add_argument("--state", help="Path to audit-state.json (enables tail-truncation check)")
    verify.add_argument(
        "--from-seq",
        dest="from_seq",
        type=int,
        default=0,
        metavar="N",
        help="Expected first seq number (default: 0).",
    )
    verify.add_argument("--json", action="store_true", help="Emit a machine-readable JSON report.")

    status = sub.add_parser("status", help="Show audit-chain state summary.")
    status.add_argument("--log-dir", dest="log_dir", help="Override the log directory.")
    status.add_argument("--seed", help="Path to audit-seed.bin (override).")
    status.add_argument("--state", help="Path to audit-state.json (override).")
    status.add_argument("--json", action="store_true", help="Emit JSON.")

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    logging.basicConfig(level=logging.WARNING, format="%(message)s")
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.action == "verify":
        return _cmd_verify(args)
    if args.action == "status":
        return _cmd_status(args)
    parser.print_help()
    return EXIT_IO_ERROR


if __name__ == "__main__":
    sys.exit(main())
