"""Pinned official TON tools, bounded subprocesses, and content-addressed caches."""
from __future__ import annotations
import base64
from dataclasses import dataclass
import hashlib
import fcntl
import json
import math
import os
from pathlib import Path, PurePosixPath
import signal
import subprocess
import sys
import tempfile
import threading
import time
from .boc import code_hash

PROJECT = Path(__file__).resolve().parent.parent

class ToolchainError(RuntimeError):
    def __init__(self, code, message):
        self.code = code
        super().__init__(message)

@dataclass
class Compilation:
    boc: bytes
    asm: str
    code_hash: str
    version: str
    flags: tuple[str, ...]


def _run(argv, cwd, timeout=10):
    # Apply limits in a fresh interpreter: preexec_fn is unsafe in threaded servers.
    runner = PROJECT / 'scripts' / 'limited_exec.py'
    with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
        own_session = os.environ.get('TON_WORKER') != '1'
        process = subprocess.Popen([sys.executable, str(runner), str(max(1, math.ceil(timeout))), *map(str, argv)], cwd=cwd,
                                   stdin=subprocess.DEVNULL, stdout=out, stderr=err, start_new_session=own_session,
                                   env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'TON_PARENT_PID': str(os.getpid())})
        try:
            process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL) if own_session else process.kill()
            process.wait()
            raise ToolchainError('TOOLCHAIN_TIMEOUT', 'Compiler/disassembler time limit exceeded')
        out.seek(0); err.seek(0)
        stdout, stderr = out.read(4 * 1024 * 1024), err.read(65536)
        if process.returncode:
            raise ToolchainError('TOOLCHAIN_FAILED', stderr.decode('utf-8', 'replace')[-4000:] or f'Tool exited {process.returncode}')
        return stdout.decode('utf-8', 'replace')


class Toolchain:
    def __init__(self, root=None):
        self.root = Path(root or os.environ.get('TON_TOOLCHAIN_ROOT', PROJECT / '.toolchains')).resolve()
        self.lock = json.loads((PROJECT / 'toolchains.lock.json').read_text())
        self.cache = Path(os.environ.get('TON_CACHE_DIR', self.root / 'cache')).resolve()
        self.cache.mkdir(parents=True, exist_ok=True)
        self.cache_max_bytes = max(0, int(os.environ.get("TON_CACHE_MAX_BYTES", 512 * 1024**2)))
        self._verified = set()
        self._mutex = threading.Lock()

    def configs(self):
        return [dict(id=c['id'], version=c['version'], flags=['-O0', '-O1', '-O2', '-O3'])
                for c in self.lock['compilers'] if (self.root / c['id'] / 'func').is_file()]

    def identities(self):
        records = []
        for config in self.configs():
            pin, binary = self._compiler(config['id'])
            records.append(dict(config, revision=pin['revision'],
                                sha256=hashlib.sha256(binary.read_bytes()).hexdigest()))
        return records

    def versions(self):
        return sorted({c['version'] for c in self.configs()})

    def _compiler(self, version):
        available = self.configs()
        if not available:
            raise ToolchainError('TOOLCHAIN_UNAVAILABLE', 'Run python3 scripts/bootstrap.py first')
        wanted = version or max(available, key=lambda c: (tuple(map(int, c['version'].split('.'))), c['id']))['id']
        for item in reversed(self.lock['compilers']):
            if wanted in (item['id'], item['version']):
                path = self.root / item['id'] / 'func'
                if wanted == item['version'] and not path.is_file():
                    continue
                if 'source_build' in item:
                    try:
                        build = json.loads((path.parent / 'build.json').read_text())
                        if build['revision'] != item['revision']:
                            raise ValueError('Source revision mismatch')
                        item = dict(item, sha256=build['sha256'])
                    except (OSError, ValueError, KeyError) as exc:
                        raise ToolchainError('TOOLCHAIN_INTEGRITY', 'Missing or mismatched source-build manifest') from exc
                self._check(path, item['sha256'])
                if 'native_sha256' in item:
                    native = self.root / item['id'] / 'squashfs-root/usr/bin/func'
                    self._check(native, item['native_sha256'])
                    path = native
                return item, path
        raise ToolchainError('COMPILER_UNAVAILABLE', f'Compiler {wanted} is not installed')

    def _check(self, path, expected):
        with self._mutex:
            if path in self._verified:
                return
            if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != expected:
                raise ToolchainError('TOOLCHAIN_INTEGRITY', f'Missing or modified pinned tool: {path.name}')
            self._verified.add(path)

    def _fift(self):
        item = self.lock['fift']
        path = self.root / item['id'] / 'fift'
        self._check(path, item['sha256'])
        libs = self.root / item['id'] / 'lib'
        for name, digest in self.lock['library_hashes'].items():
            self._check(libs / name, digest)
        # Prefer extracted executable, also hash-pinned; avoids repeated AppImage extraction.
        native = self.root / item['id'] / 'squashfs-root/usr/bin/fift'
        self._check(native, item['native_sha256'])
        path = native
        return path, libs

    def _store(self, path, payload):
        payload['asm_sha256'] = hashlib.sha256(payload['asm'].encode()).hexdigest()
        encoded = json.dumps(payload).encode()
        if len(encoded) > self.cache_max_bytes:
            return
        # simple: one cache lock and O(n) oldest-write eviction; use SQLite for very large caches.
        with (self.cache / '.lock').open('a') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            entries = [(p.stat().st_mtime_ns, p.stat().st_size, p) for p in self.cache.glob('*.json')]
            total = sum(size for _, size, _ in entries)
            for _, size, old in sorted(entries):
                if total + len(encoded) <= self.cache_max_bytes:
                    break
                old.unlink(missing_ok=True)
                total -= size
            with tempfile.NamedTemporaryFile(dir=self.cache, suffix='.json', delete=False) as f:
                tmp = Path(f.name)
                f.write(encoded)
            tmp.replace(path)

    def _load(self, path):
        try:
            value = json.loads(path.read_text())
            if isinstance(value, dict) and hashlib.sha256(value['asm'].encode()).hexdigest() == value.get('asm_sha256'):
                return value
        except (OSError, ValueError, KeyError, TypeError, AttributeError):
            pass
        return None

    def disassemble(self, boc, timeout=10):
        code_hash(boc)
        fift, libs = self._fift()
        key = hashlib.sha256(b'disasm-v1' + boc + json.dumps(self.lock['fift'], sort_keys=True).encode()
                             + json.dumps(self.lock['library_hashes'], sort_keys=True).encode()).hexdigest()
        cache = self.cache / (key + '.json')
        cached = self._load(cache)
        if cached is not None:
            return cached['asm']
        with tempfile.TemporaryDirectory(prefix='ton-disasm-') as td:
            p = Path(td)
            (p / 'input.boc').write_bytes(boc)
            (p / 'run.fif').write_text('"Disasm.fif" include\n"input.boc" file>B B>boc <s disasm\n')
            asm = _run([fift, '-I', libs, '-s', 'run.fif'], td, timeout)
        if any(line.lstrip().startswith('Cannot disassemble:') for line in asm.splitlines()):
            raise ToolchainError('UNSUPPORTED_INSTRUCTION', 'Official TON disassembler could not decode all code bits')
        self._store(cache, {'asm': asm})
        return asm

    def compile(self, source, version=None, flags=('-O2',), entrypoints=None, timeout=10):
        deadline = time.monotonic() + timeout
        def remaining():
            value = deadline - time.monotonic()
            if value <= 0:
                raise ToolchainError('TOOLCHAIN_TIMEOUT', 'Compilation deadline exceeded')
            return value
        item, binary = self._compiler(version)
        flags = tuple(flags)
        if any(flag not in ('-O0', '-O1', '-O2', '-O3', '-S', '-P', '-A', '-SPA', '-PS', '-APS') for flag in flags):
            raise ToolchainError('INVALID_FLAGS', 'Only optimizer levels 0..3 and standard output flags are supported')
        optimization = [f for f in flags if f.startswith('-O')]
        if len(optimization) > 1:
            raise ToolchainError('INVALID_FLAGS', 'Specify one optimization level')
        flags = tuple(optimization or ['-O2'])
        sources = {'candidate.fc': source} if isinstance(source, str) else dict(source)
        if not sources or sum(len(v.encode()) for v in sources.values()) > 8 * 1024 * 1024:
            raise ToolchainError('INVALID_SOURCE', 'Source set is empty or larger than 8 MiB')
        for name in sources:
            path = PurePosixPath(name)
            if path.is_absolute() or '..' in path.parts or '\\' in name or '\x00' in name or not name.endswith('.fc'):
                raise ToolchainError('INVALID_SOURCE_PATH', 'Source paths must be relative .fc paths')
        entrypoints = list(entrypoints or [next(iter(sources))])
        if any(name not in sources for name in entrypoints):
            raise ToolchainError('INVALID_SOURCE_PATH', 'Entrypoints must belong to supplied sources')
        fift, libs = self._fift()
        key = hashlib.sha256(json.dumps([sources, entrypoints, item['sha256'], flags, self.lock['fift'],
                                         self.lock['library_hashes']], sort_keys=True).encode()).hexdigest()
        cache = self.cache / (key + '.json')
        result = self._load(cache)
        if result is not None:
            try:
                cached_boc = base64.b64decode(result['boc'], validate=True)
                if code_hash(cached_boc) == result['code_hash']:
                    return Compilation(cached_boc, result['asm'], result['code_hash'], item['version'], flags)
            except (ValueError, KeyError):
                pass
            # Recompute incomplete/corrupt cache entries rather than report evidence from them.
        with tempfile.TemporaryDirectory(prefix='ton-compile-') as td:
            p = Path(td)
            for name, text in sources.items():
                target = p / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(text)
            _run([binary, '-SPA', *flags, '-o', 'output.fif', *('./' + name for name in entrypoints)], td, remaining())
            (p / 'run.fif').write_text('"output.fif" include\n2 boc+>B "output.boc" B>file\n')
            _run([fift, '-I', libs, '-s', 'run.fif'], td, remaining())
            boc = (p / 'output.boc').read_bytes()
        result = Compilation(boc, self.disassemble(boc, remaining()), code_hash(boc), item['version'], flags)
        self._store(cache, dict(boc=base64.b64encode(boc).decode(), asm=result.asm, code_hash=result.code_hash))
        return result
