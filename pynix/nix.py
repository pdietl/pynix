import hashlib
from pathlib import Path
import stat
from collections.abc import Callable
import functools

NIX_STORE = b'/nix/store'


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

    n = (len(c) * 8 - 1) // 5 + 1

    x = int.from_bytes(c, 'little')
    s = ''
    for n in range(n - 1, -1, -1):
        s += digits32[x // 32 ** n % 32]

    return s


def truncate(s: int, c: bytes) -> bytes:
    n = bytearray(s)

    for j in range(len(c)):
        i = j % s
        n[i] ^= c[j]

    return n


def nar_serialize(fso: Path) -> bytes:
    return _nar_str(b'nix-archive-1') + _nar_serialize2(fso)


def _nar_serialize2(fso: Path) -> bytes:
    return _nar_str(b'(') + _nar_serialize3(fso) + _nar_str(b')')


def _nar_serialize3(fso: Path) -> bytes:
    if fso.is_symlink():
        return _nar_str(b'type') + _nar_str(b'symlink') \
            + _nar_str(b'target') + \
            _nar_str(str(fso.readlink()).encode('ascii'))

    if fso.is_file():
        return _nar_str(b'type') \
            + _nar_str(b'regular') \
            + ((_nar_str(b'executable') + _nar_str(b''))
               if fso.stat().st_mode & stat.S_IXUSR else b'') \
            + _nar_str(b'contents') \
            + _nar_str(fso.read_bytes())

    if fso.is_dir():
        return _nar_str(b'type') + _nar_str(b'directory') \
            + _nar_concatMap(_nar_serializeEntry,
                             _nar_sortEntries(list(fso.iterdir())))

    raise Exception(
        f'Error! FSO {fso} is not a regular file, symlink, or directory!')


def _nar_sortEntries(fsos: list[Path]) -> list[Path]:
    return sorted(fsos, key=lambda fso: fso.name)


def _nar_concatMap(f: Callable[[Path], bytes], fsos: list[Path]) -> bytes:
    return functools.reduce(lambda a_bytes, fso: a_bytes + f(fso), fsos, b'')


def _nar_serializeEntry(fso: Path) -> bytes:
    return _nar_str(b'entry') + _nar_str(b'(') \
        + _nar_str(b'name') + _nar_str(fso.name.encode('ascii')) \
        + _nar_str(b'node') + _nar_serialize2(fso) \
        + _nar_str(b')')


def _nar_str(s: bytes) -> bytes:
    return _nar_int(len(s)) + _nar_pad(s)


def _nar_int(n: int) -> bytes:
    return n.to_bytes(8, 'little')


def _nar_pad(s: bytes) -> bytes:
    return s + (b'\x00' * ((8 - (len(s) & 7)) & 7))


def makePath(path_type: str, descr: str, name: str) -> Path:
    assert path_type in {'source'}

    s = path_type.encode('ascii') + b':sha256:' + descr.encode() + \
        b':' + NIX_STORE + b':' + name.encode('ascii')
    return Path(NIX_STORE.decode()) / \
        Path(printHash32(truncate(20, hash_sha256(s))) +
             '-' + name)


def addToStore(fso: Path, name: str, refs: list[Path] = []) -> Path:
    c = nar_serialize(fso)
    h = hash_sha256(c)
    p = makePath('source', printHash16(h), name)
    return p
