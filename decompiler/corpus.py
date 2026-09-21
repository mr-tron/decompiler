"""Read-only verified corpus adapter and reproducible compiler experiments."""
from __future__ import annotations

from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, asdict
import hashlib
import base64
import json
from pathlib import Path, PurePosixPath
import re
import posixpath
import platform
import shlex
import statistics
import time


@dataclass
class Contract:
    name: str
    sources: dict[str, str]
    targets: list[str]
    version: str
    flags: list[str]
    expected_hash: str | None
    group: str = ""
    split: str = ""
    error: str | None = None


def source_tokens(source: str) -> list[str]:
    """Lex comments, strings and words; comments never change source identity."""
    result, i, depth = [], 0, 0
    token_re = re.compile(r'[A-Za-z_$?][\w$?]*|0x[\da-fA-F]+|\d+|[^\w\s]')
    while i < len(source):
        if source.startswith('{-', i):
            depth += 1
            i += 2
        elif depth and source.startswith('-}', i):
            depth -= 1
            i += 2
        elif depth:
            i += 1
        elif source.startswith(';;', i):
            end = source.find('\n', i)
            i = len(source) if end < 0 else end + 1
        elif source[i].isspace():
            i += 1
        elif source[i] == '"':
            start = i
            i += 1
            while i < len(source):
                if source[i] == '\\':
                    i += 2
                elif source[i] == '"':
                    i += 1
                    break
                else:
                    i += 1
            result.append(source[start:i])
        else:
            match = token_re.match(source, i)
            if match:
                result.append(match.group())
                i += len(match.group())
            else:
                result.append(source[i])
                i += 1
    return result


def load_corpus(root: str | Path) -> list[Contract]:
    contracts = []
    for info_file in sorted(Path(root).glob('*/info.json')):
        info = json.loads(info_file.read_text())
        source_dir = info_file.parent / 'src'
        sources = {p.relative_to(source_dir).as_posix(): p.read_text(errors='replace')
                   for p in sorted(source_dir.rglob('*.fc')) if p.is_file()}
        argv = shlex.split(info.get('funcCmdLine', ''))[1:]
        targets, flags, i = [], [], 0
        while i < len(argv):
            arg = argv[i]
            if arg == '-o':
                i += 2
                continue
            if arg.startswith('-'):
                flags.append(arg)
            else:
                path = PurePosixPath(arg)
                if path.is_absolute() or '..' in path.parts:
                    raise ValueError(f'unsafe corpus target: {arg}')
                targets.append(str(path))
            i += 1
        error = None
        if not targets or any(t not in sources for t in targets):
            error = 'metadata target missing from source bundle'
        contracts.append(Contract(info_file.parent.name, sources, targets,
                                  info.get('funcVersion', 'unknown'), flags,
                                  info.get('codeHash'), error=error))
    assign_splits(contracts)
    return contracts


def assign_splits(contracts: list[Contract]) -> None:
    """Group lexical clones and deployment variants before splitting.

    Literals are erased for grouping only. A conservative near-clone union joins
    bundles with >=90% shared entrypoint token shingles. No holdout rule tuning.
    """
    parents = list(range(len(contracts)))
    def find(i):
        while parents[i] != i:
            parents[i] = parents[parents[i]]
            i = parents[i]
        return i
    signatures, hashes = [], {}
    for i, contract in enumerate(contracts):
        tokens = source_tokens('\n'.join(contract.sources.get(t, '') for t in contract.targets))
        tokens = ['<literal>' if t.startswith('"') or t[0].isdigit() else t for t in tokens]
        shingles = {tuple(tokens[j:j + 5]) for j in range(max(0, len(tokens) - 4))}
        signatures.append(shingles)
        if contract.expected_hash and contract.expected_hash in hashes:
            parents[find(i)] = find(hashes[contract.expected_hash])
        hashes[contract.expected_hash or f'missing:{i}'] = i
        if not shingles:
            continue
        for j, other in enumerate(signatures[:-1]):
            if other and min(len(other), len(shingles)) >= .9 * max(len(other), len(shingles)):
                if len(other & shingles) / len(other | shingles) >= .9:
                    parents[find(i)] = find(j)
    members = defaultdict(list)
    for i, contract in enumerate(contracts):
        identity = '\n'.join(' '.join(s) for s in sorted(signatures[i])) or contract.name
        members[find(i)].append(hashlib.sha256(identity.encode()).hexdigest())
    for i, contract in enumerate(contracts):
        contract.group = min(members[find(i)])
        bucket = int(contract.group[:8], 16) % 10
        contract.split = 'train' if bucket < 6 else 'validation' if bucket < 8 else 'holdout'


def compilation_bundle(contract: Contract) -> tuple[dict[str, str], list[str]]:
    """Restore flattened verifier includes inside a sandbox, without editing sources."""
    def includes(source):
        tokens = source_tokens(source)
        return [tokens[i + 2][1:-1] for i in range(len(tokens) - 2)
                if tokens[i:i + 2] == ['#', 'include'] and tokens[i + 2].startswith('"')]
    missing = any(posixpath.normpath(posixpath.join(posixpath.dirname(name), include)) not in contract.sources
                  for name, text in contract.sources.items() for include in includes(text))
    if not missing:
        return contract.sources, contract.targets
    sources = {'bundle/' + name: text for name, text in contract.sources.items()}
    queue = list(sources)
    for name in queue:
        for include in includes(sources[name]):
            target = posixpath.normpath(posixpath.join(posixpath.dirname(name), include))
            if target in sources:
                continue
            if target.startswith('../') or target.startswith('/'):
                raise ValueError('corpus include escapes compilation sandbox')
            matches = [text for original, text in contract.sources.items()
                       if original == include or original.endswith('/' + include.lstrip('./'))
                       or posixpath.basename(original) == posixpath.basename(include)]
            if len(set(matches)) != 1:
                continue  # The compiler reports the actual unresolved include.
            sources[target] = matches[0]
            queue.append(target)
            if len(queue) > 256:
                raise ValueError('too many reconstructed include aliases')
    return sources, ['bundle/' + name for name in contract.targets]


def write_json(path: str | Path, value) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + '.tmp')
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')
    temporary.replace(path)


def inventory(contracts: list[Contract]) -> dict:
    return {'contracts': len(contracts), 'source_groups': len({c.group for c in contracts}),
            'versions': dict(Counter(c.version for c in contracts)),
            'splits': dict(Counter(c.split for c in contracts)),
            'missing_sources': [c.name for c in contracts if c.error],
            'entries': [{'name': c.name, 'group': c.group, 'split': c.split,
                         'version': c.version, 'flags': c.flags, 'targets': c.targets,
                         'expected_hash': c.expected_hash, 'error': c.error} for c in contracts]}


def generate_microprograms(contracts: list[Contract]) -> dict[str, str]:
    """Use development syntax to select bounded, deterministic lowering probes."""
    observed = set(source_tokens('\n'.join(s for c in contracts if c.split == 'train'
                                          for n, s in c.sources.items() if 'stdlib' not in n)))
    probes = {}
    prefix = '() recv_internal(int value, cell message, slice body) impure { }\n'
    for operator in ('+', '-', '*', '/', '%', '==', '!=', '<', '>', '&', '|', '^'):
        if operator in observed:
            for constant in (-1, 0, 1, 2, 17, 256):
                if operator in ('/', '%') and constant == 0:
                    continue
                name = f'arithmetic_{len(probes):03d}'
                probes[name] = prefix + f'int probe(int arg0) method_id {{ return (arg0 {operator} {constant}); }}\n'
    samples = {
        'if': 'int probe(int arg0) method_id { if (arg0 > 0) { return arg0 + 1; } else { return 0 - arg0; } }',
        'while': 'int probe(int arg0) method_id { int v0 = 0; while (arg0 > 0) { v0 += arg0; arg0 -= 1; } return v0; }',
        'repeat': 'int probe(int arg0) method_id { int v0 = 0; repeat (arg0) { v0 += 3; } return v0; }',
        'inline': 'int helper(int arg0) inline { return arg0 * 3; }\nint probe(int arg0) method_id { return helper(arg0) + 7; }',
        'inline_ref': 'int helper(int arg0) inline_ref { return arg0 * 3; }\nint probe(int arg0) method_id { return helper(arg0) + helper(arg0 + 1); }',
        'throw': 'int probe(int arg0) method_id { throw_unless(71, arg0 > 0); return arg0; }',
        'tuple': 'int probe(int arg0) method_id { var (v0, v1) = (arg0 + 1, arg0 * 2); return v0 - v1; }',
        'cell': 'cell probe(int arg0) method_id { return begin_cell().probe_store_uint(arg0, 32).end_cell(); }',
        'slice': 'int probe(slice arg0) method_id { return arg0~probe_load_uint(32); }',
        'nested': 'int probe(int arg0, int arg1) method_id { if (arg0) { if (arg1 > 3) { return 7; } return arg1; } return arg0 - arg1; }',
        'calls': 'int helper(int arg0) { return arg0 * arg0; }\nint probe(int arg0) method_id { return helper(arg0) - helper(arg0 + 1); }',
        'destructuring': '(int, int) probe(int arg0, int arg1) method_id { var (v0, v1) = (arg1, arg0); return (v0 + v1, v0 - v1); }',
        'stack_sensitive': 'int probe(int arg0, int arg1, int arg2) method_id { return (arg0 - arg1) * (arg2 + arg0) - arg1; }',
        'dictionary': '(slice, int) lookup(cell d, int k) asm(k d) \"32 DICTUGET\" \"NULLSWAPIFNOT\";\nint probe(cell arg0, int arg1) method_id { var (v0, v1) = lookup(arg0, arg1); return v1; }',
    }
    # Standard-library declarations are embedded so probes remain self-contained.
    declarations = 'builder begin_cell() asm "NEWC";\nbuilder probe_store_uint(builder b, int x, int n) asm(x b n) "STUX";\ncell end_cell(builder b) asm "ENDC";\n(slice, int) probe_load_uint(slice s, int n) asm( -> 1 0) "LDUX";\n'
    for keyword, source in samples.items():
        if keyword in observed or keyword in ('tuple', 'nested', 'calls', 'destructuring', 'stack_sensitive', 'dictionary'):
            probes[keyword] = declarations + prefix + source + '\n'
    return probes


def failure_cluster(error: str, code: str = '') -> str:
    text = error.lower()
    if 'does not satisfy condition' in text:
        return 'compiler_version_constraint'
    if 'realpath failed' in text or 'include' in text and 'missing' in text:
        return 'missing_include'
    if 'exotic' in text or 'levelled' in text:
        return 'cell_reference_support'
    if 'timeout' in code.lower() or 'time limit' in text:
        return 'tool_timeout'
    if 'traceback' in text:
        return 'tool_runtime'
    if 'fatal:' in text or 'assertion' in text or 'cannot compile lvalue' in text:
        return 'compiler_internal_error'
    if 'error:' in text:
        return 'source_compilation'
    return code or 'unknown'


def metadata_report(rows: list[dict], contracts: list[Contract]) -> dict:
    by_contract = defaultdict(list)
    for row in rows:
        if row.get('success') and row.get('flags') == ['-O2']:
            by_contract[row['contract']].append(row)
    results = []
    for contract in contracts:
        hashes = sorted({r['code_hash'] for r in by_contract[contract.name] if r['version'] == contract.version})
        expected = base64.b64decode(contract.expected_hash).hex() if contract.expected_hash else None
        results.append({'contract': contract.name, 'compiled_at_recorded_version': bool(hashes),
                        'expected_hash': expected, 'observed_hashes': hashes,
                        'matches_metadata': expected in hashes if expected else None})
    return {'contracts': len(results), 'compiled_at_recorded_version': sum(r['compiled_at_recorded_version'] for r in results),
            'metadata_hash_available': sum(r['expected_hash'] is not None for r in results),
            'metadata_hash_matched': sum(r['matches_metadata'] is True for r in results), 'results': results}


def build_matrix(root: str | Path, output: str | Path = 'research', toolchain=None,
                 splits=('train', 'validation', 'holdout'), include_microprograms=True,
                 optimizations=('-O0', '-O2'), limit=None) -> dict:
    """Compilation cache belongs to Toolchain and keys the pinned binary identity."""
    from .toolchain import Toolchain
    from .fingerprint import Fingerprints, differential_report, evaluate_fingerprints
    toolchain = toolchain or Toolchain()
    contracts = load_corpus(root)
    output = Path(output)
    write_json(output / 'corpus.json', inventory(contracts))
    work = [c for c in contracts if c.split in splits]
    if limit is not None:
        work = work[:limit]
    if include_microprograms:
        for name, source in generate_microprograms(contracts).items():
            work.append(Contract('micro:' + name, {'main.fc': source}, ['main.fc'],
                                 '', [], None, group='micro:' + name, split='train'))
    rows = []
    configs = toolchain.configs()
    write_json(output / 'environment.json', {'python': platform.python_version(),
               'platform': platform.platform(), 'compilers': toolchain.identities(),
               'fift': toolchain.lock['fift'], 'library_hashes': toolchain.lock['library_hashes'],
               'workers': 4, 'optimizations': list(optimizations)})
    with ThreadPoolExecutor(max_workers=4) as pool:
        for contract in work:
            bundle_error = None
            sources, targets = {}, []
            try:
                sources, targets = compilation_bundle(contract)
            except ValueError as exc:
                bundle_error = str(exc)

            def attempt(configuration):
                config, optimization = configuration
                started = time.monotonic()
                row = {'contract': contract.name, 'group': contract.group, 'split': contract.split,
                       'version': config['version'], 'toolchain_id': config['id'],
                       'flags': [optimization], 'success': False}
                try:
                    if contract.error or bundle_error:
                        raise ValueError(contract.error or bundle_error)
                    compiled = toolchain.compile(sources, version=config['id'],
                                                 flags=[optimization], entrypoints=targets)
                    row.update(success=True, asm=compiled.asm, code_hash=compiled.code_hash,
                               expected_hash=contract.expected_hash)
                    target = output / 'bocs' / contract.name.replace(':', '_')
                    target.mkdir(parents=True, exist_ok=True)
                    (target / f"{config['id']}_{optimization[1:]}.boc").write_bytes(compiled.boc)
                except Exception as exc:
                    row.update(error=str(exc), error_code=getattr(exc, 'code', type(exc).__name__))
                    row['failure_cluster'] = failure_cluster(row['error'], row['error_code'])
                row['runtime_ms'] = round((time.monotonic() - started) * 1000, 3)
                return row

            # map preserves deterministic order; no subprocess uses shell interpolation.
            rows.extend(pool.map(attempt, [(config, flag) for config in configs for flag in optimizations]))
            write_json(output / 'matrix.json', rows)
    Fingerprints(rows).save(output / 'fingerprints.json')
    report = differential_report(rows)
    report.update(attempts=len(rows), successes=sum(r['success'] for r in rows),
                  failures=dict(Counter(r.get('error_code') for r in rows if not r['success'])),
                  failure_clusters=dict(Counter(r.get('failure_cluster') for r in rows if not r['success'])),
                  configurations=configs, optimizer_settings=list(optimizations))
    write_json(output / 'differential.json', report)
    write_json(output / 'corpus-verification.json', metadata_report(rows, contracts))
    write_json(output / 'fingerprint-holdout.json', evaluate_fingerprints(rows))
    return report


def evaluate(root: str | Path, output: str | Path = 'research', toolchain=None,
             split='holdout', max_search_time_ms=30000, limit=None, workers=4) -> dict:
    """Final evaluation never reads source to reconstruct; only compile input BOC."""
    from .toolchain import Toolchain
    from .service import decompile
    toolchain = toolchain or Toolchain()
    contracts = [c for c in load_corpus(root) if c.split == split]
    if limit is not None:
        contracts = contracts[:limit]
    rows = []
    available = {c['version'] for c in toolchain.configs()}
    def run_contract(contract):
        started = time.monotonic()
        row = {'contract': contract.name, 'group': contract.group, 'split': contract.split,
               'metadata_version': contract.version, 'metadata_flags': contract.flags,
               'input_compiled': False}
        try:
            if contract.version not in available:
                raise ValueError('metadata compiler version unavailable; refusing relabelled holdout')
            sources, targets = compilation_bundle(contract)
            compiled = toolchain.compile(sources, version=contract.version,
                                         flags=['-O2'], entrypoints=targets)
            row['input_compiled'] = True
            row['verified_input_hash'] = (base64.b64decode(contract.expected_hash).hex() == compiled.code_hash) if contract.expected_hash else None
            result = decompile(compiled.boc, max_search_time_ms=max_search_time_ms, toolchain=toolchain, debug=True)
            metrics = result.get('decompilation', {})
            compiler = result.get('compiler', {})
            debug = result.get('debug', {})
            ranked = debug.get('compiler_candidates', [])
            tied = [c for c in ranked if abs(c.get('score', 0) - ranked[0].get('score', 0)) < 1e-12] if ranked else []
            predicted_versions = {c['version'] for c in tied}
            predicted_flags = {tuple(c['flags']) for c in tied}
            row.update(success=result.get('success', False), result=result,
                       disassembly_success='asm' in debug,
                       parser_success='normalized_asm' in debug,
                       cfg_success='cfg' in debug,
                       cfg_constructed='cfg' in debug,
                       cfg_complete='cfg' in debug and not debug['cfg'].get('unresolved', []),
                       generated_func=bool(debug.get('generated_candidates', 0)),
                       recompiled=bool(debug.get('recompiled_candidates', 0)),
                       exact_hash=bool(metrics.get('exact_hash_match')),
                       exact_asm=bool(metrics.get('normalized_asm_match', False)),
                       instruction_similarity=metrics.get('instruction_match', 0),
                       cfg_similarity=metrics.get('cfg_match', 0),
                       compiler_exact=len(predicted_versions) == 1 and contract.version in predicted_versions,
                       compiler_compatible=contract.version in predicted_versions,
                       flags_exact=predicted_flags == {('-O2',)},
                       oracle_compatible=contract.version in compiler.get('compatible_versions', []),
                       reconstruction_mode=metrics.get('reconstruction_mode', 'unknown'),
                       structured_method_count=metrics.get('structured_method_count', 0),
                       method_count=metrics.get('method_count', 0),
                       search_candidates=result.get('search', {}).get('candidate_count', 0))
            if not result.get('success'):
                row['failure_cluster'] = result.get('error', {}).get('stage', 'unknown')
        except Exception as exc:
            row.update(error=str(exc), failure_cluster=getattr(exc, 'stage', getattr(exc, 'code', 'input_compilation')))
            if getattr(exc, 'stage', '') == 'parser':
                row['disassembly_success'] = True
        row['runtime_ms'] = (time.monotonic() - started) * 1000
        return row

    with ThreadPoolExecutor(max_workers=max(1, min(4, workers))) as pool:
        for row in pool.map(run_contract, contracts):
            rows.append(row)
            write_json(Path(output) / f'{split}-results.json', rows)
    return summarize_evaluation(rows, output, split, max_search_time_ms, workers)


def summarize_evaluation(rows, output='research', split='holdout', max_search_time_ms=30000, workers=4):
    from .asm import parse_asm
    from .ir import build_cfg
    for row in rows:
        debug = row.get('result', {}).get('debug', {})
        if 'asm' in debug:
            debug['cfg'] = asdict(build_cfg(parse_asm(debug['asm']).instructions))
            if 'decompilation' in row.get('result', {}):
                row['result']['decompilation']['cfg_analysis_complete'] = not debug['cfg']['unresolved']
        if not row.get('input_compiled') and row.get('error'):
            row['failure_cluster'] = failure_cluster(row['error'], row.get('failure_cluster', 'input_compilation'))
        row['cfg_constructed'] = 'cfg' in debug
        row['cfg_complete'] = 'cfg' in debug and not debug['cfg'].get('unresolved', [])
    write_json(Path(output) / f'{split}-results.json', rows)
    fields = ('input_compiled', 'disassembly_success', 'parser_success', 'cfg_constructed', 'cfg_complete', 'generated_func',
              'recompiled', 'exact_hash', 'exact_asm', 'compiler_exact', 'compiler_compatible', 'flags_exact')
    times = sorted(r['runtime_ms'] for r in rows)
    decompile_times = sorted(r['result']['search']['runtime_ms'] for r in rows if 'search' in r.get('result', {}))
    summary = {'split': split, 'contracts': len(rows), 'workers': max(1, min(4, workers)),
               'max_search_time_ms': max_search_time_ms,
               'rates': {key: sum(bool(r.get(key)) for r in rows) / len(rows) if rows else 0 for key in fields},
               'median_ms': statistics.median(times) if times else None,
               'median_decompile_ms': statistics.median(decompile_times) if decompile_times else None,
               'p95_decompile_ms': decompile_times[min(len(decompile_times) - 1, int(len(decompile_times) * .95))] if decompile_times else None,
               'p95_ms': times[min(len(times) - 1, int(len(times) * .95))] if times else None,
               'failure_clusters': dict(Counter(r['failure_cluster'] for r in rows if 'failure_cluster' in r)),
               'reconstruction_modes': dict(Counter(r.get('reconstruction_mode', 'failed') for r in rows)),
               'structural_match_at_least_0_95': sum(r.get('instruction_similarity', 0) >= .95 and r.get('cfg_similarity', 0) >= .95 for r in rows),
               'mean_instruction_similarity': statistics.mean(r.get('instruction_similarity', 0) for r in rows) if rows else 0,
               'mean_cfg_similarity': statistics.mean(r.get('cfg_similarity', 0) for r in rows) if rows else 0,
               'search_candidates': sum(r.get('search_candidates', 0) for r in rows),
               'structured_method_count': sum(r.get('structured_method_count', 0) for r in rows),
               'method_count': sum(r.get('method_count', 0) for r in rows),
               'verified_metadata_hashes': sum(r.get('verified_input_hash') is True for r in rows),
               'exact_verified_deployment_hashes': sum(r.get('verified_input_hash') is True and r.get('exact_hash', False) for r in rows),
               'caveat': 'Inputs compiled at recorded version with default -O2. Missing original BOCs; '
                         'metadata code hash is checked separately. Compiler accuracy uses fingerprint ranking, not assembly oracle compatibility. Flag ground truth is metadata default, not independently verified.'}
    write_json(Path(output) / f'{split}-summary.json', summary)
    lines = [f'{split} benchmark: {len(rows)} contracts', '', summary['caveat'], '']
    lines += [f'{key:28s} {value:7.1%}' for key, value in summary['rates'].items()]
    lines += ['', 'Reconstruction modes: ' + json.dumps(summary['reconstruction_modes'], sort_keys=True),
              f"Median / p95 fixture+decompile time: {summary['median_ms']} / {summary['p95_ms']} ms",
              f"Median / p95 decompile time: {summary['median_decompile_ms']} / {summary['p95_decompile_ms']} ms",
              f"Metadata hashes verified: {summary['verified_metadata_hashes']}",
              'Failure clusters: ' + json.dumps(summary['failure_clusters'], sort_keys=True)]
    (Path(output) / f'{split}-summary.txt').write_text('\n'.join(lines) + '\n')
    return summary
