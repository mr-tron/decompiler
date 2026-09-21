"""Reconstruction, bounded AST search, compiler oracle and evidence reporting."""
from dataclasses import asdict, replace
import difflib
from itertools import islice
from pathlib import Path
import time

from .asm import AsmError, normalize_asm, parse_asm, walk
from .boc import BocError, code_hash, method_cells
from .compare import compare, compare_cells
from .errors import DecompilerError
from .fingerprint import Fingerprints
from .func import resolve_references, candidates, reconstruct, reconstruct_partial, render, render_parts, readable_module, fallback, fallback_cells
from .ir import UnsupportedInstruction, build_cfg
from .toolchain import Toolchain, ToolchainError

MAX_ATTEMPTS = 64


def _preserve_changed_methods(module, program, original_cells, compiled_boc):
    """Preserve changed bodies with inferred signatures so callers remain typed."""
    candidate_cells = method_cells(compiled_boc)
    changed = {key for key, cell in original_cells.items()
               if key not in candidate_cells or code_hash(cell) != code_hash(candidate_cells[key])}
    preserved = dict(zip(sorted(original_cells), fallback_cells(program, original_cells).functions))
    functions = []
    for function in module.functions:
        if function.inline_ref:
            functions.append(function)
            continue
        key = function.method_id if function.method_id is not None else {'recv_internal': 0, 'recv_external': -1, 'run_ticktock': -2}[function.name]
        functions.append(replace(function, assembly=preserved[key].assembly,
                                 diagnostic=preserved[key].diagnostic, statements=())
                         if key in changed else function)
    return replace(module, functions=tuple(functions))


def _toolchain_error(exc, stage):
    code = getattr(exc, 'code', 'TOOLCHAIN_ERROR')
    status = 422 if code == 'UNSUPPORTED_INSTRUCTION' else 504 if code == 'TOOLCHAIN_TIMEOUT' else 503
    return DecompilerError(code, str(exc), stage, status)


def _rank(asm, toolchain):
    path = Path(__file__).resolve().parent.parent / 'research' / 'fingerprints.json'
    model = Fingerprints.load(path) if path.exists() else Fingerprints()
    configs = toolchain.configs()
    # A version identifies a family here. Toolchain resolves it to its latest
    # installed pinned binary; the matrix separately compares binary identities.
    available = {(c['version'], flag) for c in configs for flag in c['flags']}
    if not available:
        raise ToolchainError('TOOLCHAIN_UNAVAILABLE', 'Run python3 scripts/bootstrap.py first')
    ranked = [row for row in model.rank(asm, [(version, [flag]) for version, flag in sorted(available)])
              if (row['version'], row['flags'][0]) in available]
    total = sum(row['weight'] for row in ranked)
    for row in ranked:
        row['weight'] = row['weight'] / total if total else 1 / len(ranked)
    return ranked



def detect_compiler(boc, toolchain=None, timeout=10):
    code_hash(boc)
    toolchain = toolchain or Toolchain()
    try:
        asm = toolchain.disassemble(boc, timeout=timeout)
        ranked = _rank(asm, toolchain)
    except ToolchainError as exc:
        raise _toolchain_error(exc, 'disassembly') from exc
    return {'candidates': ranked, 'version': None, 'confidence': 0.0,
            'diagnostics': ['Opcode similarity ranks experiments; it does not establish compiler identity.']}


def verify(boc, source, toolchain=None, version=None, flags=('-O2',), timeout=10, entrypoints=None):
    original_hash = code_hash(boc)
    toolchain = toolchain or Toolchain()
    start = time.monotonic()
    original = toolchain.disassemble(boc, timeout=timeout)
    compiled = toolchain.compile(source, version=version, flags=flags, entrypoints=entrypoints,
                                 timeout=max(.001, timeout - (time.monotonic() - start)))
    metrics = dict(compare(original, compiled.asm), cell_match=compare_cells(boc, compiled.boc))
    metrics.update(recompiles=True, exact_hash_match=compiled.code_hash == original_hash,
                   original_code_hash=original_hash, candidate_code_hash=compiled.code_hash)
    metrics['asm_diff'] = list(difflib.unified_diff(original.splitlines(), compiled.asm.splitlines(),
                                                 fromfile='original', tofile='candidate', n=3))[:2000]
    return metrics


def decompile(boc, max_search_time_ms=30000, toolchain=None, debug=False):
    if type(max_search_time_ms) is not int or not 1 <= max_search_time_ms <= 30000:
        raise DecompilerError('INVALID_REQUEST', 'Search budget must be 1..30000 ms', 'input', 400)
    start = time.monotonic()
    deadline = start + max_search_time_ms / 1000
    try:
        original_hash = code_hash(boc)
    except BocError as exc:
        raise DecompilerError('INVALID_BOC', str(exc), 'boc', 400) from exc
    toolchain = toolchain or Toolchain()

    def remaining():
        return max(.001, deadline - time.monotonic())

    try:
        asm = toolchain.disassemble(boc, timeout=remaining())
        program = resolve_references(parse_asm(asm), boc)
        cfg = build_cfg(program.instructions)
        ranked = _rank(asm, toolchain)
    except ToolchainError as exc:
        raise _toolchain_error(exc, 'disassembly') from exc
    except AsmError as exc:
        raise DecompilerError('UNSUPPORTED_ASM', str(exc), 'parser') from exc
    debug_data = {'asm': asm, 'normalized_asm': normalize_asm(asm),
                  'cfg': asdict(cfg), 'compiler_candidates': ranked, 'ir': {}, 'generated_candidates': 0, 'recompiled_candidates': 0}
    diagnostics, unsupported = [], []
    repaired = None
    literal_methods = set()

    def modules():
        try:
            module = reconstruct(program, debug_ir=debug_data['ir'])
            debug_data['ast'] = asdict(module)
            yield 'structured', module
            if literal_methods:
                yield 'structured', reconstruct(program, preserve_constants=literal_methods)
            if repaired is not None:
                yield 'hybrid', repaired
            mismatches = best['metrics']['mismatching_methods'] if best else None
            for candidate in islice(candidates(module, method_ids=mismatches), 1, 4):
                yield 'structured', candidate
        except UnsupportedInstruction as exc:
            unsupported.append(exc.opcode)
            diagnostics.append(f'Structured reconstruction incomplete: {exc}')
        try:
            module, failures = reconstruct_partial(program, method_cells(boc), debug_ir=debug_data['ir'])
            diagnostics.extend(failures)
            unsupported.extend(value['opcode'] for value in debug_data['ir'].values() if 'opcode' in value)
            if any(function.assembly is None for function in module.functions):
                yield 'hybrid', module
                if literal_methods:
                    variant, _ = reconstruct_partial(program, method_cells(boc), preserve_constants=literal_methods)
                    yield 'hybrid', variant
                if repaired is not None:
                    yield 'hybrid', repaired
        except (UnsupportedInstruction, BocError) as exc:
            diagnostics.append(f'Partial method reconstruction unavailable: {exc}')
        try:
            yield 'assembly', fallback(program)
        except UnsupportedInstruction as exc:
            diagnostics.append(f'Textual assembly fallback unavailable: {exc}')
        try:
            yield 'cell_assembly', fallback_cells(program, method_cells(boc))
        except (UnsupportedInstruction, BocError) as exc:
            diagnostics.append(f'Lossless method fallback unavailable: {exc}')

    best, readable, exact_configs = None, None, []
    attempts, stale = 0, 0
    seen = set()
    for mode, ast in modules():
        source = render(ast)
        debug_data['generated_candidates'] += 1
        if source in seen:
            continue
        seen.add(source)
        improved = False
        # Reserve oracle work for the lossless fallback when lifting is partial.
        for config_index, configuration in enumerate(ranked):
            if best and best['exact'] and time.monotonic() >= start + .8 * max_search_time_ms / 1000:
                break
            if mode != 'cell_assembly' and not (best and best['exact']) and time.monotonic() >= start + .6 * max_search_time_ms / 1000:
                break
            if mode != 'cell_assembly' and config_index >= 4 and not (best and best['exact']):
                break
            if time.monotonic() >= deadline or attempts >= MAX_ATTEMPTS:
                break
            attempts += 1
            try:
                compiled = toolchain.compile(source, version=configuration['version'],
                                             flags=tuple(configuration['flags']), timeout=remaining())
                debug_data['recompiled_candidates'] += 1
                metrics = dict(compare(asm, compiled.asm), cell_match=compare_cells(boc, compiled.boc))
            except (ToolchainError, AsmError) as exc:
                if len(diagnostics) < 12:
                    diagnostics.append(f'Candidate compilation/comparison failed: {str(exc)[:300]}')
                continue
            exact = compiled.code_hash == original_hash
            if mode in {'structured', 'hybrid'}:
                lifted = sum(f.assembly is None and not f.inline_ref for f in ast.functions)
                readable_score = (lifted, int(exact), -len(metrics['mismatching_methods']),
                                  metrics['instruction_match'] + metrics['cfg_match'] + metrics['cell_match'])
                if readable is None or readable_score > readable['score']:
                    readable = {'score': readable_score, 'func': source, 'ast': ast,
                                'compiled': compiled, 'metrics': metrics, 'exact': exact}
            if not exact:
                literal_methods.update(metrics['mismatching_methods'])
            if mode in {'structured', 'hybrid'} and not exact:
                try:
                    candidate = _preserve_changed_methods(ast, program, method_cells(boc), compiled.boc)
                    count = sum(f.assembly is None and not f.inline_ref for f in candidate.functions)
                    if count and (repaired is None or count > sum(f.assembly is None and not f.inline_ref for f in repaired.functions)):
                        repaired = candidate
                except (BocError, UnsupportedInstruction):
                    pass
            # Assembly is a preservation fallback. Never return changed bytecode
            # as a successful opaque reconstruction, however similar it looks.
            if mode != 'structured' and not exact:
                continue
            score = (int(exact), int(metrics['normalized_asm_match']),
                     metrics['instruction_match'] + metrics['cfg_match'] + metrics['cell_match'])
            if best is None or score > best['score']:
                best = {'score': score, 'func': source, 'metrics': metrics, 'compiled': compiled,
                        'ast': ast, 'exact': exact, 'mode': mode}
                exact_configs = []
                improved = True
            if exact and best['func'] == source:
                exact_configs.append({'version': compiled.version, 'flags': list(compiled.flags)})
        stale = 0 if improved else stale + 1
        if best and best['exact'] or time.monotonic() >= deadline or attempts >= MAX_ATTEMPTS:
            break
        # The finite rewrite generator is itself bounded; preserve fallback access.
        if stale >= 3 and mode == 'cell_assembly':
            break
    presentation = readable or best
    if presentation is not None and time.monotonic() < deadline and attempts < MAX_ATTEMPTS:
        cleaned = readable_module(presentation['ast'])
        source = render(cleaned)
        if source != presentation['func']:
            attempts += 1
            try:
                previous = presentation['compiled']
                compiled = toolchain.compile(source, version=previous.version, flags=previous.flags, timeout=remaining())
                debug_data['recompiled_candidates'] += 1
                metrics = dict(compare(asm, compiled.asm), cell_match=compare_cells(boc, compiled.boc))
                cleaned_exact = compiled.code_hash == original_hash
                if cleaned_exact or not presentation['exact']:
                    readable = {'func': source, 'ast': cleaned, 'compiled': compiled, 'metrics': metrics,
                                'exact': cleaned_exact}
            except (ToolchainError, AsmError):
                pass
    elapsed = (time.monotonic() - start) * 1000
    if best is None:
        response = DecompilerError('DECOMPILATION_FAILED', 'No verified reconstruction within the search budget',
                                   'recompilation', diagnostics=diagnostics).response()
    else:
        metrics, exact, mode = best['metrics'], best['exact'], best['mode']
        if exact:
            confidence, quality = 1.0, 'exact'
        else:
            confidence = .35 * metrics['instruction_match'] + .2 * metrics['cfg_match'] + .1 * metrics['cell_match']
            quality = 'medium' if confidence >= .55 else 'low'
            diagnostics.append('Structural similarity is not a proof of semantic equivalence; cell hashes differ.')
        if mode != 'structured':
            diagnostics.append('Exact binary preservation uses FunC asm. High-level stack/types/control-flow reconstruction is incomplete; exact confidence measures bytecode fidelity only.')
            lifted = sum(f.assembly is None and not f.inline_ref for f in best['ast'].functions)
            diagnostics.append(f'{lifted}/{sum(not f.inline_ref for f in best["ast"].functions)} methods retained as verified high-level FunC; other methods use assembly because lifting is unsupported or did not reproduce their exact code cells.')
        compatible = sorted({c['version'] for c in exact_configs})
        if len(exact_configs) > 1:
            diagnostics.append('Several compiler/flag configurations reproduce the returned source; the original configuration is ambiguous.')
        if time.monotonic() >= deadline or attempts >= MAX_ATTEMPTS:
            diagnostics.append('Search budget exhausted; untested configurations may also be compatible.')
        diagnostics.append('Recompilation compatibility does not prove historical compiler identity. Flags shown are the verified candidate settings.')
        response = {'success': True, 'func': best['func'], **render_parts(best['ast']),
                    'compiler': {'version': None, 'confidence': 0.0,
                                 'compatible_versions': compatible,
                                 'flags': list(best['compiled'].flags),
                                 'compatible_configurations': exact_configs,
                                 'selected_version': best['compiled'].version,
                                 'candidates': ranked},
                    'decompilation': {'confidence': confidence, 'quality': quality, 'recompiles': True,
                                      'exact_hash_match': exact, **metrics,
                                      'reconstruction_mode': mode,
                                      'stack_analysis_complete': mode == 'structured',
                                      'cfg_analysis_complete': not cfg.unresolved,
                                      'structured_method_count': sum(f.assembly is None and not f.inline_ref for f in best['ast'].functions),
                                      'method_count': sum(not f.inline_ref for f in best['ast'].functions),
                                      'unsupported_instructions': sorted(set(unsupported))},
                    'diagnostics': diagnostics}
        if readable is not None and readable['func'] != best['func']:
            candidate = readable['compiled']
            response['readable'] = {
                'func': readable['func'], **render_parts(readable['ast']),
                'compiler': {'version': None, 'selected_version': candidate.version,
                             'flags': list(candidate.flags)},
                'decompilation': {'recompiles': True, 'exact_hash_match': readable['exact'],
                                  'quality': 'exact' if readable['exact'] else 'unverified',
                                  'reconstruction_mode': 'hybrid' if any(f.assembly is not None for f in readable['ast'].functions) else 'structured',
                                  'structured_method_count': sum(f.assembly is None and not f.inline_ref for f in readable['ast'].functions),
                                  'method_count': sum(not f.inline_ref for f in readable['ast'].functions),
                                  'original_code_hash': original_hash,
                                  'candidate_code_hash': candidate.code_hash, **readable['metrics']},
                'diagnostics': [] if readable['exact'] else ['This readable reconstruction compiles, but its code hash differs from the original. '
                                'Semantic equivalence has not been established. Verification details apply separately to each source view.']
            }
        # Presentation syntax is separate from the source whose compilation was verified.
        display_program = parse_asm(asm)
        for view, ast in [(response, best['ast']), *([(response['readable'], readable['ast'])] if 'readable' in response else [])]:
            if any(f.assembly is not None for f in ast.functions):
                view['display_contract'] = render_parts(ast, display_program=display_program)['contract']
                view['display_format'] = 'func-fift-pseudocode'
        debug_data['ast'] = asdict(best['ast'])
    response['search'] = {'candidate_count': attempts, 'runtime_ms': elapsed}
    if debug:
        response['debug'] = debug_data
    return response
