#!/usr/bin/env python3

import hashlib
from pathlib import Path
import stat
import sys
import os
from collections.abc import Callable
import functools


def hash_md5(c: bytes) -> bytes:
    return hashlib.md5(c).digest()


def hash_sha1(c: bytes) -> bytes:
    return hashlib.sha1(c).digest()


def hash_sha256(c: bytes) -> bytes:
    return hashlib.sha256(c).digest()


def printHash16(c: bytes) -> str:
    return c.hex()


def printHash32(c: bytes) -> str:
    digits32 = '0123456789abcdfghijklmnpqrsvwxyz'

    n = len(c) * 8 // 5
    print(n)

    x = int.from_bytes(c, 'little')
    s = ''
    while n >= 0:
        s += digits32[x // 32 ** n % 32]
        n -= 1

    return s


def truncate(s: int, c: bytes) -> bytes:
    n = bytearray(s)

    for j in range(len(c)):
        i = j % s
        n[i] ^= c[j]

    return n


def nar_serialize(fso: Path) -> bytes:
    return nar_str(b'nix-archive-1') + nar_serialize2(fso)


def nar_serialize2(fso: Path) -> bytes:
    return nar_str(b'(') + nar_serialize3(fso) + nar_str(b')')


def nar_serialize3(fso: Path) -> bytes:
    if fso.is_symlink():
        return nar_str(b'type') + nar_str(b'symlink') \
            + nar_str(b'target') + nar_str(str(fso.readlink()).encode('ascii'))

    if fso.is_file():
        return nar_str(b'type') \
            + nar_str(b'regular') \
            + ((nar_str(b'executable') + nar_str(b''))
               if fso.stat().st_mode & stat.S_IXUSR else b'') \
            + nar_str(b'contents') \
            + nar_str(fso.read_bytes())

    if fso.is_dir():
        return nar_str(b'type') + nar_str(b'directory') \
            + nar_concatMap(nar_serializeEntry,
                            nar_sortEntries(list(fso.iterdir())))

    raise Exception(
        f'Error! FSO {fso} is not a regular file, symlink, or directory!')


def nar_sortEntries(fsos: list[Path]) -> list[Path]:
    return sorted(fsos, key=lambda fso: fso.name)


def nar_concatMap(f: Callable[[Path], bytes], fsos: list[Path]) -> bytes:
    return functools.reduce(lambda a_bytes, fso: a_bytes + f(fso), fsos, b'')


def nar_serializeEntry(fso: Path) -> bytes:
    return nar_str(b'entry') + nar_str(b'(') \
        + nar_str(b'name') + nar_str(fso.name.encode('ascii')) \
        + nar_str(b'node') + nar_serialize2(fso) \
        + nar_str(b')')


def nar_str(s: bytes) -> bytes:
    return nar_int(len(s)) + nar_pad(s)


def nar_int(n: int) -> bytes:
    return n.to_bytes(8, 'little')


def nar_pad(s: bytes) -> bytes:
    return s + (b'\x00' * ((8 - (len(s) & 7)) & 7))


if len(sys.argv) != 2:
    print(f'Usage: {sys.argv[0]} <file|symlink|directory>', file=sys.stderr)
    sys.exit(1)
else:
    target_path = Path(sys.argv[1])
    out_path = Path(target_path.name + '_serialization.nar')
    with open(out_path, 'wb') as fp:
        fp.write(nar_serialize(target_path))
    print(f'Wrote {out_path} with the NAR serialization of {target_path}')
