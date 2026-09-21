"""Compile and decompile the complete corpus, then report three outcomes."""
from __future__ import annotations

import argparse
import csv
from concurrent.futures import ThreadPoolExecutor
from collections import Counter
import json
from pathlib import Path
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from decompiler.corpus import compilation_bundle, load_corpus, write_json
from decompiler.service import decompile
from decompiler.toolchain import Toolchain


FLAGS = ("fully_decompiled", "compiler_version_correct", "code_hash_match")


def classify_result(result: dict, metadata_version: str) -> dict:
    """Extract the requested booleans without mistaking primitive asm for raw methods."""
    chosen = result.get("readable") or result
    metrics = chosen.get("decompilation", {})
    ranked = (result.get("debug") or {}).get("compiler_candidates", [])
    best = ranked[0].get("score", 0) if ranked else None
    tied = [row for row in ranked if abs(row.get("score", 0) - best) < 1e-12] if ranked else []
    predicted_versions = sorted({row["version"] for row in tied})
    return {
        # reconstruction_mode is based on function bodies. Generated stdlib
        # primitives may legitimately contain asm declarations.
        "fully_decompiled": bool(result.get("success")) and metrics.get("reconstruction_mode") == "structured",
        "compiler_version_correct": predicted_versions == [metadata_version],
        "code_hash_match": bool(result.get("success")) and bool(metrics.get("recompiles"))
                           and bool(metrics.get("exact_hash_match")),
        "predicted_versions": predicted_versions,
        "compiler_version_in_top_tie": metadata_version in predicted_versions,
        "reconstruction_mode": metrics.get("reconstruction_mode", "failed"),
    }


def summarize(rows: list[dict]) -> dict:
    combinations = Counter(tuple(bool(row.get(flag)) for flag in FLAGS) for row in rows)
    by_version = {}
    for version in sorted({row["metadata_version"] for row in rows}):
        selected = [row for row in rows if row["metadata_version"] == version]
        by_version[version] = {
            "contracts": len(selected),
            "input_compiled": sum(bool(row.get("input_compiled")) for row in selected),
            **{flag: sum(bool(row.get(flag)) for row in selected) for flag in FLAGS},
        }
    return {
        "contracts": len(rows),
        "input_compiled": sum(bool(row.get("input_compiled")) for row in rows),
        "decompilation_succeeded": sum(bool(row.get("decompilation_succeeded")) for row in rows),
        "totals": {flag: sum(bool(row.get(flag)) for row in rows) for flag in FLAGS},
        "combinations": [
            {**dict(zip(FLAGS, values)), "contracts": combinations[values]}
            for values in ((a, b, c) for a in (True, False)
                           for b in (True, False) for c in (True, False))
        ],
        "by_metadata_version": by_version,
        "failures": dict(Counter(row.get("failure_stage", "ok") for row in rows)),
    }


def _percent(value: int, total: int) -> str:
    return f"{100 * value / total:.1f}%" if total else "0.0%"


def render_report(summary: dict) -> str:
    total = summary["contracts"]
    lines = [
        "# All-contract decompilation report", "",
        f"Contracts: {total}; input compilation succeeded: {summary['input_compiled']}/{total}; "
        f"decompilation succeeded: {summary['decompilation_succeeded']}/{total}.", "",
        "A contract is fully decompiled only when every function body is structured; asm declarations "
        "for typed TVM primitives do not count as raw function bodies. Compiler version correctness "
        "requires one uniquely top-ranked version matching `info.json`. Hash matching applies to the "
        "selected readable output, recompiled with the configuration selected by the decompiler.", "",
        "| Outcome | Contracts | Percent |",
        "|---|---:|---:|",
        *[f"| {flag.replace('_', ' ')} | {summary['totals'][flag]} | "
          f"{_percent(summary['totals'][flag], total)} |" for flag in FLAGS],
        "",
        "| Fully decompiled | Compiler version correct | Code hash match | Contracts | Percent |",
        "|---:|---:|---:|---:|---:|",
    ]
    for row in summary["combinations"]:
        values = ["yes" if row[flag] else "no" for flag in FLAGS]
        lines.append(f"| {' | '.join(values)} | {row['contracts']} | {_percent(row['contracts'], total)} |")
    lines += ["", "| Metadata version | Contracts | Compiled | Fully decompiled | Version correct | Hash match |",
              "|---|---:|---:|---:|---:|---:|"]
    for version, row in summary["by_metadata_version"].items():
        lines.append(f"| {version} | {row['contracts']} | {row['input_compiled']} | "
                     f"{row['fully_decompiled']} | {row['compiler_version_correct']} | {row['code_hash_match']} |")
    lines += ["", "Failures: `" + json.dumps(summary["failures"], sort_keys=True) + "`", ""]
    return "\n".join(lines)


def write_outputs(output: Path, rows: list[dict]) -> dict:
    output.mkdir(parents=True, exist_ok=True)
    summary = summarize(rows)
    write_json(output / "results.json", rows)
    write_json(output / "summary.json", summary)
    (output / "REPORT.md").write_text(render_report(summary))
    columns = ("contract", "split", "metadata_version", "input_compiled",
               "decompilation_succeeded", *FLAGS, "predicted_versions",
               "compiler_version_in_top_tie", "reconstruction_mode", "input_code_hash",
               "candidate_code_hash", "runtime_ms", "failure_stage", "error")
    with tempfile.NamedTemporaryFile("w", newline="", dir=output, delete=False) as handle:
        writer = csv.DictWriter(handle, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow({**row, "predicted_versions": ";".join(row.get("predicted_versions", []))})
        temporary = Path(handle.name)
    temporary.replace(output / "results.csv")
    return summary


def run(root: Path, output: Path, budget_ms: int, workers: int, resume: bool = False) -> dict:
    contracts = load_corpus(root)
    toolchain = Toolchain()
    available = {row["version"] for row in toolchain.configs()}
    prior = {}
    if resume and (output / "results.json").exists():
        prior = {row["contract"]: row for row in json.loads((output / "results.json").read_text())}

    def process(contract):
        if contract.name in prior:
            return prior[contract.name]
        started = time.monotonic()
        row = {"contract": contract.name, "split": contract.split,
               "metadata_version": contract.version, "input_compiled": False,
               "decompilation_succeeded": False, **{flag: False for flag in FLAGS}}
        try:
            if contract.error:
                raise ValueError(contract.error)
            if contract.version not in available:
                raise ValueError("metadata compiler version unavailable")
            sources, targets = compilation_bundle(contract)
            # Corpus metadata records no optimizer flag; the verified corpus
            # convention is its recorded compiler version with default -O2.
            compiled = toolchain.compile(sources, version=contract.version,
                                         flags=["-O2"], entrypoints=targets)
            row.update(input_compiled=True, input_code_hash=compiled.code_hash)
            result = decompile(compiled.boc, max_search_time_ms=budget_ms,
                               toolchain=toolchain, debug=True)
            chosen = result.get("readable") or result
            row.update(decompilation_succeeded=bool(result.get("success")),
                       **classify_result(result, contract.version),
                       candidate_code_hash=chosen.get("decompilation", {}).get("candidate_code_hash"))
            if not result.get("success"):
                error = result.get("error", {})
                row.update(failure_stage=error.get("stage", "decompilation"),
                           error=error.get("message", error.get("code", "decompilation failed")))
        except Exception as exc:
            row.update(failure_stage=getattr(exc, "stage", getattr(exc, "code", "input_compilation")),
                       error=str(exc))
        row["runtime_ms"] = round((time.monotonic() - started) * 1000, 1)
        return row

    rows_by_id = dict(prior)
    pending = [contract for contract in contracts if contract.name not in prior]
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for row in pool.map(process, pending):
            rows_by_id[row["contract"]] = row
            ordered = [rows_by_id[c.name] for c in contracts if c.name in rows_by_id]
            write_outputs(output, ordered)
            print(f"{len(ordered)}/{len(contracts)} {row['contract']}: "
                  f"full={row['fully_decompiled']} version={row['compiler_version_correct']} "
                  f"hash={row['code_hash_match']}", flush=True)
    return write_outputs(output, [rows_by_id[c.name] for c in contracts])


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path("orig_func_verified"))
    parser.add_argument("--output", type=Path, default=Path("research/all-300"))
    parser.add_argument("--budget-ms", type=int, default=3000)
    parser.add_argument("--workers", type=int, choices=range(1, 5), default=4)
    parser.add_argument("--resume", action="store_true")
    args = parser.parse_args()
    if not 1 <= args.budget_ms <= 30000:
        parser.error("--budget-ms must be 1..30000")
    print(json.dumps(run(args.root, args.output, args.budget_ms, args.workers, args.resume), indent=2))


if __name__ == "__main__":
    main()
