#!/usr/bin/env python3
"""Check out the release's public dependency pins in SOURCE_ROOT.

Run from the product checkout already at SOURCE_ROOT/ps5-proton/ps5-wow:
    python3 ps5/release/fetch-sources.py SOURCE_ROOT
No recursive Proton checkout or private build history is needed.

SELF-HEALING: a dependency checkout left at another revision (e.g. by an
earlier release build on a persistent self-hosted runner, or after a re-pin)
is replaced with a fresh shallow checkout at the pinned commit, never trusted.
"""
import argparse
import json
import os
import re
import shutil
import stat
import subprocess
from pathlib import Path, PurePosixPath


def git(path, *arguments, capture=False):
    result = subprocess.run(['git', '-C', str(path), *arguments], check=True,
                            stdout=subprocess.PIPE if capture else None, text=True)
    return result.stdout.strip() if capture else None


def _chmod_writable(function, path, _error):
    try:
        os.chmod(path, stat.S_IWRITE)
    except OSError:
        pass
    function(path)


def erase_checkout(destination: Path) -> None:
    """Drop a stale dependency checkout; Windows keeps .git objects read-only."""
    callback = _chmod_writable
    try:
        shutil.rmtree(destination, onexc=callback)   # Python >= 3.12
    except TypeError:
        shutil.rmtree(destination, onerror=callback)  # Python <= 3.11


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source_root', type=Path)
    args = parser.parse_args()
    root = args.source_root.resolve()
    manifest = json.loads(Path(__file__).with_name('deps.json').read_text())
    # Parent repositories must exist before their nested submodule checkouts.
    for source in sorted(manifest['sources'], key=lambda entry: len(PurePosixPath(entry['path']).parts)):
        relative = PurePosixPath(source['path'])
        if relative.is_absolute() or '..' in relative.parts:
            raise SystemExit(f'unsafe dependency path: {relative}')
        destination = root / relative
        if not destination.resolve().is_relative_to(root):
            raise SystemExit(f'dependency path escapes source root: {relative}')
        revision = source['commit']
        url = source['url']
        if not re.fullmatch(r'[0-9a-f]{40}', revision):
            raise SystemExit(f"{source['name']}: expected a full commit ID")
        if not url.startswith('https://github.com/') or '@' in url:
            raise SystemExit(f"{source['name']}: expected a public GitHub HTTPS URL")
        if (destination / '.git').exists():
            at = git(destination, 'rev-parse', 'HEAD', capture=True)
            if at == revision:
                print(f'CHECKOUT {source["name"]} {revision} existing', flush=True)
                continue
            print(f'REPIN {source["name"]} {at} -> {revision}; replacing the checkout',
                  flush=True)
            erase_checkout(destination)
        if destination.exists() and any(destination.iterdir()):
            raise SystemExit(f'{relative}: nonempty directory is not a dependency checkout')
        destination.mkdir(parents=True, exist_ok=True)
        git(destination, 'init', '--quiet')
        git(destination, 'remote', 'add', 'origin', url)
        git(destination, 'fetch', '--quiet', '--depth=1', 'origin', revision)
        git(destination, '-c', 'advice.detachedHead=false', 'checkout', '--quiet', '--detach', 'FETCH_HEAD')
        if git(destination, 'rev-parse', 'HEAD', capture=True) != revision:
            raise SystemExit(f'{relative}: fetched revision does not match the pin')
        print(f'CHECKOUT {source["name"]} {revision}', flush=True)


if __name__ == '__main__':
    main()
