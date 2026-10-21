"""Test harness and efficacy store: Generate test plans, run efficacy tests, track results."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests

from .models import (
    DEFAULT_GUARD_MODEL,
    EFFICACY_DIR,
    META_DIR,
    RAIL_YAML_DIR,
    AttackRecord,
    EfficacyRecord,
    Option,
    Recommendation,
    Signal,
    to_dict,
)

# EFFICACY TRACKING: Append-only records and per-rail summaries


def catalog_version() -> str:
    """SHA256 of sorted YAML filenames + bytes in RAIL_YAML_DIR (first 12 hex)."""
    yaml_dir = Path(RAIL_YAML_DIR)
    yaml_files = sorted(yaml_dir.glob("*.yaml"))
    digest = hashlib.sha256()
    for f in yaml_files:
        digest.update(f.name.encode("utf-8"))
        digest.update(f.read_bytes())
    return digest.hexdigest()[:12]


def append_records(records: list[EfficacyRecord]) -> Path:
    """Append records to EFFICACY_DIR/records.jsonl; create dir if needed."""
    EFFICACY_DIR.mkdir(parents=True, exist_ok=True)
    path = EFFICACY_DIR / "records.jsonl"
    with open(path, "a") as f:
        for record in records:
            f.write(json.dumps(to_dict(record)) + "\n")
    return path


def load_records() -> list[EfficacyRecord]:
    """Load all records from EFFICACY_DIR/records.jsonl."""
    path = EFFICACY_DIR / "records.jsonl"
    if not path.exists():
        return []
    records = []
    with open(path) as f:
        for line in f:
            if line.strip():
                data = json.loads(line)
                records.append(EfficacyRecord(**data))
    return records


def summarize(records: list[EfficacyRecord] | None = None) -> dict[str, dict[str, Any]]:
    """
    Per rail id (only where len(rails)==1, i.e. attributable), compute:
    - tested, blocked, block_rate, errors, mean latency_ms
    - breakdowns by threat_id, by each signal in attack_features.signals, by use_case
    Also count blocking_rail attribution separately for multi-rail records as "blocked_as_member".
    Write summaries to META_DIR/<rail_id>.yaml.
    Return the summary dict.
    """
    if records is None:
        records = load_records()

    # Segregate attributable (len(rails)==1) vs multi-rail
    attributable: dict[str, list[EfficacyRecord]] = {}
    multi_rail_blocked_members: dict[str, int] = {}

    for record in records:
        if len(record.rails) == 1:
            rail_id = record.rails[0]
            if rail_id not in attributable:
                attributable[rail_id] = []
            attributable[rail_id].append(record)
        elif record.status == "blocked" and record.blocking_rail:
            # Count this blocking_rail as a member of a multi-rail option
            rail_id = record.blocking_rail
            multi_rail_blocked_members[rail_id] = multi_rail_blocked_members.get(rail_id, 0) + 1

    now = datetime.now(timezone.utc).isoformat()
    cat_version = catalog_version()
    summaries = {}

    for rail_id, rail_records in attributable.items():
        tested = len(rail_records)
        blocked = sum(1 for r in rail_records if r.status == "blocked")
        block_rate = blocked / tested if tested > 0 else 0.0
        errors = sum(1 for r in rail_records if r.status == "error")

        latencies = [r.latency_ms for r in rail_records if r.latency_ms is not None]
        mean_latency = sum(latencies) / len(latencies) if latencies else None

        # Breakdown by threat_id
        by_threat: dict[str, dict[str, int | float]] = {}
        for record in rail_records:
            threat = record.attack_features.get("threat_id", "unknown")
            if threat not in by_threat:
                by_threat[threat] = {"tested": 0, "blocked": 0}
            by_threat[threat]["tested"] += 1
            if record.status == "blocked":
                by_threat[threat]["blocked"] += 1
            if by_threat[threat]["tested"] > 0:
                by_threat[threat]["block_rate"] = by_threat[threat]["blocked"] / by_threat[threat]["tested"]

        # Breakdown by signal (from attack_features.signals list)
        by_signal: dict[str, dict[str, int | float]] = {}
        for record in rail_records:
            signals = record.attack_features.get("signals", [])
            for sig_obj in signals:
                # Only essential signals: incidental ones (e.g. an IBAN in the backstory) would mis-credit rails.
                if not isinstance(sig_obj, dict) or sig_obj.get("role") != "essential":
                    continue
                sig = sig_obj.get("signal") or "unknown"
                if sig not in by_signal:
                    by_signal[sig] = {"tested": 0, "blocked": 0}
                by_signal[sig]["tested"] += 1
                if record.status == "blocked":
                    by_signal[sig]["blocked"] += 1
                if by_signal[sig]["tested"] > 0:
                    by_signal[sig]["block_rate"] = by_signal[sig]["blocked"] / by_signal[sig]["tested"]

        # Breakdown by use_case
        by_use_case: dict[str, dict[str, int | float]] = {}
        for record in rail_records:
            uc = record.use_case
            if uc not in by_use_case:
                by_use_case[uc] = {"tested": 0, "blocked": 0}
            by_use_case[uc]["tested"] += 1
            if record.status == "blocked":
                by_use_case[uc]["blocked"] += 1
            if by_use_case[uc]["tested"] > 0:
                by_use_case[uc]["block_rate"] = by_use_case[uc]["blocked"] / by_use_case[uc]["tested"]

        summary = {
            "catalog_version": cat_version,
            "timestamp": now,
            "tested": tested,
            "blocked": blocked,
            "block_rate": block_rate,
            "errors": errors,
            "mean_latency_ms": mean_latency,
            "by_threat_id": by_threat,
            "by_signal": by_signal,
            "by_use_case": by_use_case,
        }

        summaries[rail_id] = summary

        # Write to META_DIR/<rail_id>.yaml
        META_DIR.mkdir(parents=True, exist_ok=True)
        import yaml

        with open(META_DIR / f"{rail_id}.yaml", "w") as f:
            yaml.dump(summary, f, default_flow_style=False)

    # Also record multi-rail blocked members
    if multi_rail_blocked_members:
        for rail_id, count in multi_rail_blocked_members.items():
            if rail_id not in summaries:
                summaries[rail_id] = {
                    "catalog_version": cat_version,
                    "timestamp": now,
                    "blocked_as_member": count,
                }
            else:
                summaries[rail_id]["blocked_as_member"] = count

    return summaries


# TEST EXECUTION: Run tests and collect results


def load_recommendations(run_dir: Path) -> list[Recommendation]:
    """Load recommendations.json from run_dir."""
    path = run_dir / "recommendations.json"
    with open(path) as f:
        recs = json.load(f)
    result = []
    for r in recs:
        # Convert dicts to proper dataclass instances
        signals = [Signal(**s) if isinstance(s, dict) else s for s in r.get("signals", [])]
        options = [Option(**o) if isinstance(o, dict) else o for o in r.get("options", [])]
        r_copy = dict(r)
        r_copy["signals"] = signals
        r_copy["options"] = options
        result.append(Recommendation(**r_copy))
    return result


def load_attacks(run_dir: Path) -> dict[str, AttackRecord]:
    """Load attacks.json and index by attack_id."""
    path = run_dir / "attacks.json"
    with open(path) as f:
        attacks = json.load(f)
    return {a["attack_id"]: AttackRecord(**a) for a in attacks}


def load_request(config_dir: Path, mode: str) -> dict[str, Any]:
    """Load request JSON from config_dir/request_{mode}.json."""
    path = config_dir / f"request_{mode}.json"
    with open(path) as f:
        return json.load(f)


def print_curl_command(request: dict[str, Any], nemo_url: str, run_dir: Path, label: str) -> None:
    """Print a curl command for the request (body via @file)."""
    request_file = run_dir / f"_request_{label}.json"
    with open(request_file, "w") as f:
        json.dump(request, f, indent=2)
    print(f"curl -X POST {nemo_url}/v1/checks -H 'Content-Type: application/json' -d @{request_file}")


def _get_messages_for_mode(attack: AttackRecord, mode: str) -> list[dict[str, Any]]:
    """Get messages based on mode: 'attack' returns only attack turn, 'all' returns all messages.

    Args:
        attack: AttackRecord with adversarial_text and messages.
        mode: "attack" (attack turn only) or "all" (full conversation).

    Returns:
        List of message dicts ready for /v1/checks.

    Raises:
        ValueError: If attack turn cannot be extracted or injection surface is not supported.
    """
    if mode == "attack":
        # Return only the attack turn as a single user message.
        if not attack.adversarial_text:
            raise ValueError(f"Attack {attack.attack_id}: adversarial_text is empty, cannot probe")
        if attack.injection_surface and attack.injection_surface != "user_turn":
            raise ValueError(
                f"Attack {attack.attack_id}: injection_surface={attack.injection_surface} not supported "
                "(only user_turn attacks supported in this version)"
            )
        return [{"role": "user", "content": attack.adversarial_text}]
    elif mode == "all":
        # Return all messages. Note: /v1/checks validates each message independently,
        # so "all" mode also checks the system prompt and benign turns.
        return attack.messages
    else:
        raise ValueError(f"Unknown mode: {mode}")


def test_request(request: dict[str, Any], nemo_url: str, timeout: float) -> tuple[str, str | None, float, str | None]:
    """
    POST a request to /v1/checks.
    Return (status, blocking_rail, latency_ms, error).
    """
    start = time.time()
    try:
        resp = requests.post(f"{nemo_url}/v1/checks", json=request, timeout=timeout)
        latency = (time.time() - start) * 1000
        if resp.status_code != 200:
            return "error", None, latency, f"HTTP {resp.status_code}: {resp.text[:300]}"
        data = resp.json()
        status = data.get("status")
        if status not in ("passed", "modified", "blocked"):
            return "error", None, latency, f"unexpected response: {resp.text[:300]}"
        return status, data.get("rail"), latency, None
    except Exception as e:
        latency = (time.time() - start) * 1000
        return "error", None, latency, str(e)[:300]


def check_nemo_server(nemo_url: str) -> None:
    """GET /v1/rails/configs, print available config ids."""
    try:
        resp = requests.get(f"{nemo_url}/v1/rails/configs", timeout=5)
        if resp.status_code != 200:
            print(f"Error: {resp.status_code}")
            sys.exit(1)
        data = resp.json()
        configs = data.get("configs", [])
        print(f"Available configs ({len(configs)}):")
        for cfg in sorted(configs):
            print(f"  {cfg}")
        sys.exit(0)
    except Exception as e:
        print(f"Connection error: {e}")
        sys.exit(1)


# CLI: Orchestrate test execution


def main(argv: list[str] | None = None) -> None:
    """Test options against /v1/checks."""
    parser = argparse.ArgumentParser(description="Test guardrail options against attacks")
    parser.add_argument("--run-dir", required=True, help="Run directory with recommendations + attacks")
    parser.add_argument(
        "--guard-model", default=DEFAULT_GUARD_MODEL, help="Model for LLM-judged rails (default: %(default)s)"
    )
    parser.add_argument("--nemo-url", help="NeMo server base URL, e.g. http://localhost:8000 (or env NEMO_URL)")
    parser.add_argument("--dry-run", action="store_true", help="Print curl commands, don't POST")
    parser.add_argument("--timeout", type=float, default=30, help="Request timeout (seconds)")
    parser.add_argument("--attack", action="append", help="Filter by attack short_id (repeatable)")
    parser.add_argument("--option", type=int, help="Filter by option rank")
    parser.add_argument(
        "--messages",
        choices=["attack", "all"],
        default="attack",
        help="attack (attack turn only, default) or all (full conversation, each message checked separately)",
    )
    parser.add_argument("--no-store", action="store_true", help="Don't append to efficacy store")
    parser.add_argument("--check-server", action="store_true", help="Check server configs and exit")
    parser.add_argument("--summarize", action="store_true", help="Print efficacy summary and exit")
    parser.add_argument(
        "--records",
        type=Path,
        default=None,
        help="Efficacy records file to summarize (default: output/efficacy/records.jsonl)",
    )

    args = parser.parse_args(argv)
    run_dir = Path(args.run_dir).resolve()
    if not run_dir.exists():
        print(f"Error: run_dir {run_dir} not found")
        sys.exit(1)

    nemo_url = args.nemo_url or os.environ.get("NEMO_URL")
    if args.check_server:
        if not nemo_url:
            print("Error: --nemo-url or NEMO_URL required")
            sys.exit(1)
        check_nemo_server(nemo_url)

    if args.summarize:
        records = None
        if args.records:
            records = []
            with open(args.records) as f:
                for line in f:
                    if line.strip():
                        data = json.loads(line)
                        records.append(EfficacyRecord(**data))
        summaries = summarize(records)
        if not summaries:
            print("No efficacy records found.")
            return
        loaded_records = records if records else load_records()
        print(f"Efficacy Summary ({len(loaded_records)} total records)")
        print(f"Catalog version: {catalog_version()}")
        print("-" * 100)
        print(f"{'Rail ID':<40} {'Tested':<8} {'Blocked':<8} {'Rate':<8} {'Errors':<8} {'Latency (ms)':<12}")
        print("-" * 100)
        for rail_id in sorted(summaries.keys()):
            s = summaries[rail_id]
            tested = s.get("tested", 0)
            blocked = s.get("blocked", 0)
            rate = s.get("block_rate", 0.0)
            errors = s.get("errors", 0)
            latency = s.get("mean_latency_ms")
            latency_str = f"{latency:.1f}" if latency is not None else "—"
            print(f"{rail_id:<40} {tested:<8} {blocked:<8} {rate:>7.1%} {errors:<8} {latency_str:<12}")
        print("-" * 100)
        return

    if not args.dry_run and not nemo_url:
        print("Error: --nemo-url or NEMO_URL required (not --dry-run)")
        sys.exit(1)

    # Load data
    try:
        recommendations = load_recommendations(run_dir)
        attacks_by_id = load_attacks(run_dir)
    except Exception as e:
        print(f"Error loading data: {e}")
        sys.exit(1)

    # Filter attacks
    attack_filter = set(args.attack) if args.attack else None

    # Collect results
    results: list[EfficacyRecord] = []
    cat_version = catalog_version()
    timestamp = datetime.now(timezone.utc).isoformat()
    skipped_gaps = 0
    tested_count = 0
    blocked_count = 0

    for rec in recommendations:
        # Skip gaps
        if rec.status == "gap":
            skipped_gaps += 1
            print(f"Skipped (gap): {rec.short_id}")
            continue

        # Filter by attack
        if attack_filter and rec.short_id not in attack_filter:
            continue

        attack = attacks_by_id.get(rec.attack_id)
        if not attack:
            print(f"Warning: attack {rec.attack_id} not found")
            continue

        # Build attack_features
        signals_list = []
        for s in rec.signals:
            if isinstance(s, dict):
                signals_list.append(s)
            else:
                signals_list.append({"signal": s.signal, "role": s.role})
        attack_features = {
            "threat_id": attack.threat_id,
            "mechanism": attack.mechanism,
            "owasp_ids": attack.owasp_ids,
            "atlas_ids": attack.atlas_ids,
            "use_case": rec.use_case,
            "signals": signals_list,
            "messages_mode": args.messages,
        }

        # Test each option
        for option in rec.options:
            if args.option is not None and option.rank != args.option:
                continue

            # Iterate through test_plan
            for test_entry in option.test_plan:
                tested_count += 1
                test_label = test_entry.get("label", "unknown")
                config_id = test_entry.get("config_id", "")
                rails = test_entry.get("rails", [])

                # Get messages based on mode
                try:
                    test_messages = _get_messages_for_mode(attack, args.messages)
                except ValueError as e:
                    print(f"Warning: {e}")
                    continue

                # One config_id per test: an atomic rail config, or the merged option config for "combined".
                request = {
                    # NeMo uses this as the LLM model for LLM-judged rails (self check input).
                    "model": args.guard_model,
                    "messages": test_messages,
                    "guardrails": {"config_id": config_id},
                }

                # Dry run: print curl
                if args.dry_run:
                    print(f"# {test_label} (messages_mode={args.messages})")
                    print_curl_command(
                        request,
                        nemo_url or "NEMO_URL",
                        run_dir,
                        f"{rec.short_id}_opt{option.rank}_{test_label}",
                    )
                    continue

                # Test
                status, blocking_rail, latency_ms, error = test_request(request, nemo_url, args.timeout)
                if status == "blocked":
                    blocked_count += 1

                record = EfficacyRecord(
                    run_id=run_dir.name,
                    catalog_version=cat_version,
                    attack_id=rec.attack_id,
                    use_case=rec.use_case,
                    attack_features=attack_features,
                    rails=rails,
                    option_rank=option.rank,
                    level="detection",
                    status=status,
                    blocking_rail=blocking_rail if status == "blocked" else None,
                    judge_outcome=None,
                    latency_ms=latency_ms if status != "error" else None,
                    timestamp=timestamp,
                    error=error,
                    test_label=test_label,
                    probe_messages=test_messages,
                )
                results.append(record)

    # Write test_results.json
    if not args.dry_run and results:
        results_path = run_dir / "test_results.json"
        with open(results_path, "w") as f:
            json.dump([to_dict(r) for r in results], f, indent=2)
        print(f"Wrote {results_path}")

        # Append to efficacy store
        if not args.no_store:
            append_records(results)
            print(f"Appended {len(results)} records to efficacy store")

        # Summarize and print
        if not args.no_store:
            summaries = summarize()
            print("\nEfficacy Summary (per-rail, single-rail tests only):")
            print("-" * 80)
            for rail_id in sorted(summaries.keys()):
                s = summaries[rail_id]
                tested = s.get("tested", 0)
                blocked = s.get("blocked", 0)
                rate = s.get("block_rate", 0.0)
                print(f"{rail_id:<40} tested={tested} blocked={blocked} rate={rate:.1%}")

    # Print summary
    print(f"\n{tested_count} test entries executed, {blocked_count} blocked")
    if skipped_gaps:
        print(f"{skipped_gaps} gap recommendations skipped")

    # List attacks where no option blocked
    if not args.dry_run and results:
        attacks_with_no_block = {}
        for rec in recommendations:
            if rec.status == "gap":
                continue
            if attack_filter and rec.short_id not in attack_filter:
                continue
            attack_blocked = any(r.attack_id == rec.attack_id and r.status == "blocked" for r in results)
            if not attack_blocked:
                attacks_with_no_block[rec.short_id] = rec.missing_signals
        if attacks_with_no_block:
            print("\nAttacks with no blocking option:")
            for short_id, missing in sorted(attacks_with_no_block.items()):
                print(f"  {short_id}: missing {missing}")


if __name__ == "__main__":
    main()
