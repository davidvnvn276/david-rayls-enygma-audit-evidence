#!/usr/bin/env python3
"""Verify every packaged file, then reproduce the saved evidence offline."""
import argparse
import hashlib
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import sys

ROOT=Path(__file__).resolve().parent
MANIFEST='SHA256SUMS.txt'


def content_files(root):
    found={}
    for folder, dirs, files in os.walk(root):
        at=Path(folder)
        dirs[:]=[n for n in dirs if n!='__pycache__' and not (at==root and n=='.git')]
        for d in dirs:
            if (at/d).is_symlink():raise ValueError(f'Unexpected symlink: {at/d}')
        for n in files:
            p=at/n; rel=p.relative_to(root).as_posix()
            if rel in (MANIFEST,'.git'):continue
            if not p.is_file() or p.is_symlink():raise ValueError(f'Not a regular file: {rel}')
            found[rel]=p
    return found


def validate(root=ROOT):
    wanted={}
    lines=(root/MANIFEST).read_bytes().decode('utf-8').splitlines()
    for line in lines:
        m=re.fullmatch(r'([0-9a-f]{64})  (.+)',line)
        if not m:raise ValueError(f'Malformed manifest line: {line}')
        checksum,name=m.groups(); path=PurePosixPath(name)
        if path.is_absolute() or '..' in path.parts or name!=path.as_posix() or '\\' in name or name in wanted:
            raise ValueError(f'Invalid or duplicate manifest path: {name}')
        wanted[name]=checksum
    got=content_files(root)
    if wanted.keys()!=got.keys():
        missing=sorted(wanted.keys()-got.keys()); extra=sorted(got.keys()-wanted.keys())
        raise ValueError(f'Manifest coverage mismatch: missing={missing}; extra={extra}')
    for name,path in got.items():
        if hashlib.sha256(path.read_bytes()).hexdigest()!=wanted[name]:
            raise ValueError(f'SHA-256 mismatch: {name}')
    return len(got)


def main():
    cli=argparse.ArgumentParser(description=__doc__)
    cli.add_argument('--python-only',action='store_true',help='Skip only the separate synthetic envelope test in Node.js')
    args=cli.parse_args()
    print(f'PASS: SHA-256 and coverage for {validate()} payload files.',flush=True)
    for command in [['verify.py'],['verify_extensions.py'],['-m','unittest','-v','test_evidence'],['tools/make_visuals.py','--check']]:
        subprocess.run([sys.executable,'-B',*command],cwd=ROOT,check=True)
    if args.python_only:
        print('SKIP: only the separate Node.js synthetic-envelope demo was skipped.')
    else:
        node=shutil.which('node')
        if node is None: raise SystemExit('Install Node.js 24.22.3 or use --python-only for a partial replay.')
        subprocess.run([node,'audit_envelope.cjs'],cwd=ROOT,check=True)
    print(f'PASS: {"Python-only" if args.python_only else "complete"} offline replay.')


if __name__=='__main__':main()
