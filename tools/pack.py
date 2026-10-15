#!/usr/bin/env python3
"""Create an AERA Host API runtime payload from a staging directory."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import tempfile

def digest(source):
    result = hashlib.sha256()
    while block := source.read(1024 * 1024):
        result.update(block)
    return result.hexdigest()

def safe(path):
    return path and len(path.encode()) < 240 and not path.startswith('/') and all(
        part not in ('', '.', '..') for part in path.split('/'))

def main(root, output):
    output.mkdir(parents=True, exist_ok=True)
    files = sorted(path for path in root.rglob('*') if path.is_file())
    if not files or len(files) > 4096:
        raise ValueError('invalid runtime member count')
    with tempfile.TemporaryFile() as expanded:
        expanded.write(b'AERAWEB1' + struct.pack('<I', len(files)))
        for path in files:
            name = path.relative_to(root).as_posix()
            if not safe(name):
                raise ValueError(f'unsafe runtime path: {name}')
            data = path.read_bytes()
            mode = 0o755 if path.stat().st_mode & 0o111 else 0o644
            encoded = name.encode()
            expanded.write(struct.pack('<HHQ', len(encoded), mode, len(data)))
            expanded.write(encoded)
            expanded.write(b'\0' * (-expanded.tell() % 4))
            expanded.write(data)
        expanded_size = expanded.tell()
        expanded.seek(0)
        expanded_sha256 = digest(expanded)
        expanded.seek(0)
        with (output / 'runtime.xz').open('wb') as target:
            subprocess.run(['xz', '-c', '--threads=1', '--check=crc32', '--arm64',
                            '--lzma2=preset=9e,lc=2,lp=2'], stdin=expanded,
                           stdout=target, check=True)
    payload = output / 'runtime.xz'
    with payload.open('rb') as source:
        payload_sha256 = digest(source)
    metadata = {'compressed': payload.stat().st_size,
                'expanded': expanded_size,
                'sha256': payload_sha256,
                'expanded_sha256': expanded_sha256,
                'files': len(files)}
    (output / 'metadata.json').write_text(json.dumps(metadata, indent=2) + '\n')
    print(json.dumps(metadata, indent=2))

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('root', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    main(args.root.resolve(strict=True), args.output)
