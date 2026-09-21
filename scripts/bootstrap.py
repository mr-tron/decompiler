#!/usr/bin/env python3
"""Install hash-pinned official TON release tools (Linux x86_64)."""
import argparse
import hashlib
import json
from pathlib import Path
import platform
import subprocess
import tempfile
import tarfile
import shutil
import os
import time
import urllib.error
import urllib.request
import zipfile

PROJECT = Path(__file__).resolve().parent.parent

def download(url, target, digest):
    if target.exists() and hashlib.sha256(target.read_bytes()).hexdigest() == digest:
        return
    target.parent.mkdir(parents=True, exist_ok=True)
    for attempt in range(5):
        try:
            with urllib.request.urlopen(url, timeout=120) as response:
                data = response.read(64 * 1024 * 1024 + 1)
            break
        except urllib.error.HTTPError as error:
            retryable = error.code in (408, 429) or 500 <= error.code < 600
            if not retryable or attempt == 4:
                raise
            error.close()
        except urllib.error.URLError:
            if attempt == 4:
                raise
        delay = 2 ** attempt
        print(f'Download failed, retrying in {delay}s: {url}')
        time.sleep(delay)
    if hashlib.sha256(data).hexdigest() != digest:
        raise ValueError('Downloaded asset checksum mismatch: ' + url)
    target.write_bytes(data)


def source_build(compiler, root, jobs):
    target = root / compiler['id'] / 'func'
    manifest = target.parent / 'build.json'
    if target.exists() and manifest.exists():
        value = json.loads(manifest.read_text())
        if value.get('revision') == compiler['revision'] and hashlib.sha256(target.read_bytes()).hexdigest() == value.get('sha256'):
            return
    for command in ('cmake', 'g++'):
        if not shutil.which(command):
            raise SystemExit('Historical builds require cmake, g++, libssl-dev, zlib1g-dev; install them or use --releases-only')
    spec = compiler['source_build']
    archive = root / 'sources' / (compiler['id'] + '.tar.gz')
    download(spec['url'], archive, spec['sha256'])
    crc = spec['crc32c']
    crc_archive = root / 'sources' / 'crc32c.tar.gz'
    download(crc['url'], crc_archive, crc['sha256'])
    with tempfile.TemporaryDirectory(prefix='ton-build-') as td:
        directory = Path(td)
        with tarfile.open(archive) as tar:
            tar.extractall(directory, filter='data')
        source = next(directory.glob('ton-*'))
        with tarfile.open(crc_archive) as tar:
            tar.extractall(directory, filter='data')
        shutil.copytree(next(directory.glob('crc32c-*')), source / 'third-party/crc32c', dirs_exist_ok=True)
        build = directory / 'build'
        subprocess.run(['cmake', '-S', str(source), '-B', str(build),
                        '-DCMAKE_POLICY_VERSION_MINIMUM=3.5', '-DCMAKE_BUILD_TYPE=Release',
                        '-DTON_USE_ROCKSDB=OFF', '-DTON_USE_ABSEIL=OFF', '-DTON_ONLY_TONLIB=ON'], check=True)
        subprocess.run(['cmake', '--build', str(build), '--target', 'func', '-j', str(jobs)], check=True)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(build / 'crypto/func', target)
    manifest.write_text(json.dumps({'revision': compiler['revision'],
        'sha256': hashlib.sha256(target.read_bytes()).hexdigest(),
        'environment': {'compiler': subprocess.check_output(['g++', '--version'], text=True).splitlines()[0],
                        'platform': platform.platform()}}, indent=2) + '\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=PROJECT / '.toolchains')
    parser.add_argument('--releases-only', action='store_true', help='Skip historical source builds')
    parser.add_argument('--jobs', type=int, default=4)
    args = parser.parse_args()
    if not 1 <= args.jobs <= 64:
        parser.error('--jobs must be 1..64')
    if platform.system() != 'Linux' or platform.machine() != 'x86_64':
        parser.error('Pinned release assets currently target Linux x86_64')
    root = args.root.resolve()
    lock = json.loads((PROJECT / 'toolchains.lock.json').read_text())
    for compiler in lock['compilers']:
        if 'source_build' in compiler:
            if not args.releases_only:
                source_build(compiler, root, args.jobs)
            continue
        target = root / compiler['id'] / 'func'
        download(compiler['url'], target, compiler['sha256'])
        target.chmod(0o755)
        if 'native_sha256' in compiler:
            native = target.parent / 'squashfs-root/usr/bin/func'
            if not native.exists():
                subprocess.run([str(target), '--appimage-extract'], cwd=target.parent, check=True, timeout=60)
            if hashlib.sha256(native.read_bytes()).hexdigest() != compiler['native_sha256']:
                raise ValueError('Extracted compiler checksum mismatch')
    fift = lock['fift']
    directory = root / fift['id']
    binary = directory / 'fift'
    download(fift['url'], binary, fift['sha256'])
    binary.chmod(0o755)
    archive = directory / 'smartcont_lib.zip'
    download(lock['libraries']['url'], archive, lock['libraries']['sha256'])
    with zipfile.ZipFile(archive) as z:
        for member in z.infolist():
            if not (directory / member.filename).resolve().is_relative_to(directory):
                raise ValueError('Unsafe archive path')
        z.extractall(directory)
    native = directory / 'squashfs-root/usr/bin/fift'
    if not native.exists():
        subprocess.run([str(binary), '--appimage-extract'], cwd=directory, check=True, timeout=60)
    if not native.exists() or hashlib.sha256(native.read_bytes()).hexdigest() != fift['native_sha256']:
        raise ValueError('Extracted Fift checksum mismatch')
    print(f'Installed {sum((root / c["id"] / "func").exists() for c in lock["compilers"])} pinned compiler binaries and official Disasm.fif in {root}')

if __name__ == '__main__':
    main()
