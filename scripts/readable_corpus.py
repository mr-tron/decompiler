"""Reproducible readable-reconstruction benchmark."""
from __future__ import annotations

import argparse
import base64
from collections import Counter
import json
from pathlib import Path
import re
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from decompiler.boc import code_hash, method_cells
from decompiler.corpus import compilation_bundle, load_corpus, write_json
from decompiler.service import decompile
from decompiler.toolchain import Toolchain


def select_contracts(root: Path, toolchain: Toolchain, count: int = 30,
                     excluded_ids: set[str] | None = None,
                     excluded_groups: set[str] | None = None,
                     splits: tuple[str, ...] = ('train',),
                     allow_variants: bool = False):
    """Freeze first compilable contracts from sorted, explicitly named splits."""
    contracts = [c for c in load_corpus(root) if c.split in splits and not c.error]
    split_order = {split: i for i, split in enumerate(splits)}
    contracts.sort(key=lambda c: (split_order[c.split], c.name))
    selected, groups = [], set(excluded_groups or ())
    excluded_ids = excluded_ids or set()
    versions = {c['version'] for c in toolchain.configs()}
    for contract in contracts:
        if (contract.name in excluded_ids or contract.group in groups
                or contract.version not in versions):
            continue
        try:
            sources, targets = compilation_bundle(contract)
            compiled = toolchain.compile(sources, version=contract.version,
                                         flags=['-O2'], entrypoints=targets)
        except Exception:
            continue
        selected.append((contract, compiled))
        groups.add(contract.group)
        if len(selected) == count:
            return selected
    if not allow_variants:
        raise RuntimeError(f'only {len(selected)} eligible distinct contracts; need {count}')
    # simple: fill deterministic variants only when explicitly requested.
    # Prior cohorts remain excluded by ID and group throughout.
    selected_ids = {contract.name for contract, _ in selected}
    for contract in contracts:
        if len(selected) == count:
            break
        if (contract.name in excluded_ids or contract.group in (excluded_groups or set())
                or contract.name in selected_ids or contract.version not in versions):
            continue
        try:
            sources, targets = compilation_bundle(contract)
            compiled = toolchain.compile(sources, version=contract.version,
                                         flags=['-O2'], entrypoints=targets)
        except Exception:
            continue
        selected.append((contract, compiled))
        selected_ids.add(contract.name)
    if len(selected) == count:
        return selected
    raise RuntimeError(f'only {len(selected)} eligible contracts; need {count}')


def ast_coverage(result: dict, original_boc: bytes):
    selected = result.get('readable') or result
    dec = selected.get('decompilation', {})
    funcs = (result.get('debug') or {}).get('ast', {}).get('functions', [])
    by_name = {f.get('name'): f for f in funcs}
    # The top-level debug AST describes the verified main candidate. When a
    # separate readable view exists, count its structured methods from its
    # explicit metrics and inspect its emitted receiver declaration below.
    structured = dec.get('structured_method_count', 0)
    total = dec.get('method_count') or len(method_cells(original_boc))
    receiver_names = {'recv_internal', 'recv_external', 'run_ticktock'}
    # Count ABI entrypoints from the original BOC. A newly recognized special
    # method can be rendered under a generated name, so the candidate AST is
    # not a stable source of the denominator.
    original_methods = method_cells(original_boc) if original_boc else {}
    receiver_count = sum(k in (0, -1, -2) for k in original_methods) if original_boc else sum(
        name in receiver_names for name in by_name)
    structured_receivers = sum(name in receiver_names and function.get('assembly') is None
                               for name, function in by_name.items())
    if selected is not result:
        # The independent readable view can differ from the debug AST. Its
        # receiver wrapper calls asm_<name> exactly when that receiver is opaque.
        source = selected.get('contract', '')
        if not original_boc:
            receiver_count = len(re.findall(r'\b(?:recv_internal|recv_external|run_ticktock)\s*\(', source))
        structured_receivers = 0
        for name in receiver_names:
            if re.search(r'\b' + name + r'\s*\(', source) and not re.search(
                    r'\b' + name + r'\s*\([^)]*\)[^{]*\{\s*return\s+asm_' + name + r'\s*\(', source):
                structured_receivers += 1
    return max(0, structured - structured_receivers), receiver_count, structured_receivers


def run(root: Path, output: Path, phase: str, budget: int, frozen_cohort: bool = False,
        count: int = 30, exclude_cohort: Path | None = None,
        splits: tuple[str, ...] = ('train',), allow_variants: bool = False):
    toolchain = Toolchain()
    inputs_dir = output / 'inputs'
    readable_dir = output / 'readable'
    inputs_dir.mkdir(parents=True, exist_ok=True)
    readable_dir.mkdir(parents=True, exist_ok=True)
    if phase == 'baseline':
        if frozen_cohort:
            cohort = json.loads((output / 'cohort.json').read_text())
            contracts = {c.name: c for c in load_corpus(root)}
            selected = []
            for row in cohort:
                contract = contracts[row['id']]
                sources, targets = compilation_bundle(contract)
                compiled = toolchain.compile(sources, version=contract.version,
                                             flags=['-O2'], entrypoints=targets)
                if compiled.code_hash != row['input_hash']:
                    raise RuntimeError(f"frozen input changed for {contract.name}")
                selected.append((contract, compiled))
        else:
            excluded_ids, excluded_groups = set(), set()
            if exclude_cohort:
                excluded = json.loads(exclude_cohort.read_text())
                excluded_ids = {str(row['id']) for row in excluded}
                excluded_groups = {row['group'] for row in excluded}
            selected = select_contracts(root, toolchain, count,
                                        excluded_ids, excluded_groups, splits,
                                        allow_variants=allow_variants)
            cohort = [{'id': c.name, 'group': c.group, 'split': c.split,
                       'version': c.version, 'flags': ['-O2'],
                       'input_hash': compiled.code_hash}
                      for c, compiled in selected]
            write_json(output / 'cohort.json', cohort)
        for c, compiled in selected:
            (inputs_dir / f'{c.name}.boc').write_bytes(compiled.boc)
    else:
        cohort = json.loads((output / 'cohort.json').read_text())
        contracts = {c.name: c for c in load_corpus(root)}
        selected = [(contracts[row['id']], None) for row in cohort]

    rows = []
    for contract, compiled in selected:
        boc_path = inputs_dir / f'{contract.name}.boc'
        boc = compiled.boc if compiled else boc_path.read_bytes()
        start = time.monotonic()
        row = {'id': contract.name, 'group': contract.group, 'split': contract.split,
               'version': contract.version, 'input_hash': code_hash(boc)}
        try:
            # Reconstruction consumes only the compiled BOC. Source is used
            # above solely to create the frozen benchmark input.
            result = decompile(boc, max_search_time_ms=budget, toolchain=toolchain, debug=True)
            chosen = result.get('readable') or result
            structured, receiver_count, readable_receivers = ast_coverage(result, boc)
            source = chosen.get('contract', '')
            full_source = chosen.get('func') or ((chosen.get('stdlib', '') + '\n') if chosen.get('stdlib') else '') + source
            destination = readable_dir / f'{contract.name}.fc'
            destination.write_text(full_source)
            recompiles = False
            recompile_error = None
            candidate_hash = None
            if result.get('success') and source:
                try:
                    rebuilt = toolchain.compile(full_source,
                                                 version=chosen.get('compiler', {}).get('selected_version'),
                                                 flags=chosen.get('compiler', {}).get('flags', ['-O2']))
                    recompiles = True
                    candidate_hash = rebuilt.code_hash
                except Exception as exc:
                    recompile_error = str(exc)
            # A structured AST is only a readable result when the emitted
            # source actually passes the compiler for this contract.
            if not recompiles:
                structured = readable_receivers = 0
            original_methods = method_cells(boc)
            row.update(success=bool(result.get('success')),
                       readable_methods=structured,
                       required_methods=len(original_methods) - sum(k in (0, -1, -2) for k in original_methods),
                       readable_receivers=readable_receivers,
                       receiver_count=receiver_count,
                       recompiled=recompiles, recompile_error=recompile_error,
                       candidate_hash=candidate_hash,
                       readable_source_exact_hash=candidate_hash == code_hash(boc),
                       readable_source_exact_asm=bool(chosen.get('decompilation', {}).get('normalized_asm_match')),
                       assembly_preservation_exact_hash=bool(result.get('decompilation', {}).get('exact_hash_match')),
                       assembly_preservation_exact_asm=bool(result.get('decompilation', {}).get('normalized_asm_match')),
                       readable_reconstruction_mode=chosen.get('decompilation', {}).get('reconstruction_mode'),
                       assembly_preservation_mode=result.get('decompilation', {}).get('reconstruction_mode'),
                       unsupported=result.get('decompilation', {}).get('unsupported_instructions', []),
                       reconstruction_diagnostics=[d[:240] for d in result.get('diagnostics', [])
                                                   if not d.startswith('Candidate compilation/comparison failed:')],
                       candidate_compilation_failures=sum(
                           d.startswith('Candidate compilation/comparison failed:')
                           for d in result.get('diagnostics', [])),
                       readable_file=str(destination.relative_to(output.parent)))
            if not result.get('success'):
                error = result.get('error') or {}
                row['failure'] = error.get('stage') or error.get('code') or str(error)
        except Exception as exc:
            methods = method_cells(boc)
            row.update(success=False, readable_methods=0,
                       required_methods=len(methods) - sum(k in (0, -1, -2) for k in methods),
                       readable_receivers=0, receiver_count=sum(k in (0, -1, -2) for k in methods),
                       recompiled=False, readable_source_exact_hash=False, readable_source_exact_asm=False,
                       assembly_preservation_exact_hash=False, assembly_preservation_exact_asm=False,
                       failure=str(exc))
        row['runtime_ms'] = round((time.monotonic() - start) * 1000, 1)
        rows.append(row)
        write_json(output / f'{phase}-results.json', rows)
        print(f"{phase}: {contract.name}: {row['readable_methods']}/{row['required_methods']} methods, receiver={row['readable_receivers']}, exact={row['assembly_preservation_exact_hash']}", flush=True)

    counts = Counter(row.get('failure', 'ok') for row in rows)
    summary = {'phase': phase, 'contracts': len(rows), 'readable_methods': sum(r.get('readable_methods', 0) for r in rows),
               'required_methods': sum(r.get('required_methods', 0) for r in rows),
               'readable_receivers': sum(r.get('readable_receivers', 0) for r in rows),
               'receiver_count': sum(r.get('receiver_count', 0) for r in rows),
               'fully_readable_contracts': sum(
                   r.get('success') and r.get('recompiled') and
                   r.get('readable_methods') == r.get('required_methods') and
                   r.get('readable_receivers') == r.get('receiver_count') for r in rows),
               'recompiled': sum(r.get('recompiled', False) for r in rows),
               'readable_source_exact_hash': sum(r.get('readable_source_exact_hash', False) for r in rows),
               'readable_source_exact_asm': sum(r.get('readable_source_exact_asm', False) for r in rows),
               'assembly_preservation_exact_hash': sum(r.get('assembly_preservation_exact_hash', False) for r in rows),
               'assembly_preservation_exact_asm': sum(r.get('assembly_preservation_exact_asm', False) for r in rows),
               'failures': dict(counts),
               'unsupported_instructions': dict(Counter(x for r in rows for x in r.get('unsupported', [])))}
    write_json(output / f'{phase}-summary.json', summary)
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path('orig_func_verified'))
    parser.add_argument('--output', type=Path, default=Path('research/readable-30'))
    parser.add_argument('--phase', choices=('baseline', 'final'), required=True)
    parser.add_argument('--budget-ms', type=int, default=30000)
    parser.add_argument('--count', type=int, default=30,
                        help='number of contracts to select in baseline phase')
    parser.add_argument('--exclude-cohort', type=Path,
                        help='cohort JSON whose IDs and clone groups are excluded')
    parser.add_argument('--splits', nargs='+', choices=('train', 'validation', 'holdout'),
                        default=('train',),
                        help='source splits eligible for new cohort selection; holdout must be explicit')
    parser.add_argument('--allow-variants', action='store_true',
                        help='fill requested count with clone-group variants after distinct selection')
    parser.add_argument('--frozen-cohort', action='store_true',
                        help='rerun baseline against the existing cohort.json without changing its IDs')
    args = parser.parse_args()
    print(json.dumps(run(args.root, args.output, args.phase, args.budget_ms,
                         args.frozen_cohort, args.count, args.exclude_cohort,
                         tuple(args.splits), args.allow_variants), indent=2))


if __name__ == '__main__':
    main()
