"""Developer CLI; JSON output makes experiments scriptable."""
import argparse
import json
import os
from pathlib import Path
import sys

from .errors import DecompilerError


def source_bundle(source):
    """Copy only reachable local includes; unrelated contracts are not compiler input."""
    from .corpus import source_tokens
    source = source.resolve()
    pending, files, total = [source], {}, 0
    while pending:
        path = pending.pop()
        if path in files:
            continue
        if len(files) >= 256 or path.stat().st_size + total > 8 * 1024 ** 2:
            raise ValueError('Source bundle exceeds 256 files or 8 MiB')
        text = path.read_text()
        total += len(text.encode())
        files[path] = text
        tokens = source_tokens(text)
        for index in range(len(tokens) - 2):
            if tokens[index:index + 2] == ['#', 'include'] and tokens[index + 2].startswith('"'):
                include = Path(tokens[index + 2][1:-1])
                if include.is_absolute():
                    raise ValueError('Absolute includes are not portable compiler inputs')
                pending.append((path.parent / include).resolve())
    root = Path(os.path.commonpath([str(path.parent) for path in files]))
    return {path.relative_to(root).as_posix(): text for path, text in files.items()}, [source.relative_to(root).as_posix()]


def main(argv=None):
    parser = argparse.ArgumentParser(prog='decompiler')
    commands = parser.add_subparsers(dest='command', required=True)
    for name in ('decompile', 'disasm', 'detect-compiler'):
        command = commands.add_parser(name)
        command.add_argument('boc', type=Path)
        command.add_argument('--max-search-time-ms', type=int, default=30000)
        if name == 'decompile':
            command.add_argument('--debug', action='store_true')
    command = commands.add_parser('verify')
    command.add_argument('boc', type=Path)
    command.add_argument('source', type=Path)
    command.add_argument('--version')
    command.add_argument('--optimization', choices=('0', '1', '2', '3'), default='2')
    command = commands.add_parser('serve')
    command.add_argument('--host', default='127.0.0.1')
    command.add_argument('--port', type=int, default=8080)
    command = commands.add_parser('bootstrap')
    command.add_argument('--root', type=Path)
    command.add_argument('--releases-only', action='store_true')
    command.add_argument('--jobs', type=int, default=4)
    corpus = commands.add_parser('corpus').add_subparsers(dest='operation', required=True)
    for name in ('build', 'evaluate', 'inventory'):
        command = corpus.add_parser(name)
        command.add_argument('root', type=Path)
        command.add_argument('--output', type=Path, default=Path('research'))
        command.add_argument('--limit', type=int)
        if name == 'evaluate':
            command.add_argument('--split', choices=('train', 'validation', 'holdout'), default='holdout')
            command.add_argument('--workers', type=int, choices=range(1, 5), default=4)
            command.add_argument('--max-search-time-ms', type=int, default=30000)
    command = commands.add_parser('compiler-diff')
    command.add_argument('source', type=Path)
    args = parser.parse_args(argv)
    if getattr(args, 'limit', None) is not None and args.limit < 1:
        parser.error('--limit must be positive')
    if hasattr(args, 'max_search_time_ms') and not 1 <= args.max_search_time_ms <= 30000:
        parser.error('--max-search-time-ms must be 1..30000')
    try:
        if args.command == 'serve':
            from .api import serve
            serve(args.host, args.port)
            return 0
        if args.command == 'bootstrap':
            import subprocess
            script = Path(__file__).resolve().parent.parent / 'scripts' / 'bootstrap.py'
            return subprocess.call([sys.executable, str(script), '--jobs', str(args.jobs)]
                                   + (['--root', str(args.root)] if args.root else [])
                                   + (['--releases-only'] if args.releases_only else []))
        if args.command == 'corpus':
            from .corpus import build_matrix, evaluate, inventory, load_corpus
            if args.operation == 'build':
                result = build_matrix(args.root, args.output, limit=args.limit)
            elif args.operation == 'evaluate':
                result = evaluate(args.root, args.output, split=args.split,
                                  max_search_time_ms=args.max_search_time_ms, limit=args.limit, workers=args.workers)
            else:
                result = inventory(load_corpus(args.root))
        else:
            from .toolchain import Toolchain
            tooling = Toolchain()
            if args.command == 'compiler-diff':
                from .fingerprint import differential_report
                rows = []
                for config in tooling.configs():
                    for flag in ('-O0', '-O2'):
                        row = {'contract': args.source.name, 'version': config['version'], 'flags': [flag]}
                        try:
                            # CLI is a trusted local boundary. Explicit includes
                            # are supplied from the source's own directory.
                            sources, entrypoints = source_bundle(args.source)
                            compiled = tooling.compile(sources, version=config['version'], flags=[flag],
                                                       entrypoints=entrypoints)
                            row.update(success=True, asm=compiled.asm, code_hash=compiled.code_hash)
                        except Exception as exc:
                            row.update(success=False, error=str(exc))
                        rows.append(row)
                result = {'experiments': rows, 'differential': differential_report(rows)}
            else:
                from .boc import parse_boc
                boc = args.boc.read_bytes()
                parse_boc(boc)
                if args.command == 'disasm':
                    print(tooling.disassemble(boc))
                    return 0
                from .service import decompile, detect_compiler, verify
                if args.command == 'decompile':
                    result = decompile(boc, args.max_search_time_ms, tooling, debug=args.debug)
                elif args.command == 'detect-compiler':
                    result = detect_compiler(boc, tooling, timeout=args.max_search_time_ms / 1000)
                else:
                    sources, entrypoints = source_bundle(args.source)
                    result = verify(boc, sources, tooling, version=args.version,
                                    flags=[f'-O{args.optimization}'], entrypoints=entrypoints)
        print(json.dumps(result, indent=2, default=str, allow_nan=False))
        return 0 if result.get('success', True) else 1
    except DecompilerError as exc:
        print(json.dumps(exc.response(), indent=2), file=sys.stderr)
        return 1
    except (ValueError, OSError, RuntimeError) as exc:
        print(json.dumps({'success': False, 'error': {'code': getattr(exc, 'code', type(exc).__name__),
                                                     'message': str(exc), 'stage': args.command}}), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
