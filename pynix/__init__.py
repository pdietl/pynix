#!/usr/bin/env python3

import sys
from pathlib import Path
from base64 import b64encode
from pynix.nix import printHash16, printHash32, hash_sha256, nar_serialize

import click


@click.group()
def cli() -> None:
    '''A Python implementation of some `nix` commands'''
    pass


@cli.group()
def hash() -> None:
    '''compute and convert cryptographic hashes'''
    pass


@hash.command()
@click.option('--base16', is_flag=True)
@click.option('--base32', is_flag=True)
@click.argument('paths', type=click.File('rb'), nargs=-1)
def file(paths, base16: bool, base32: bool) -> None:
    '''print cryptographic hash of a regular file'''
    h = hash_sha256(paths[0].read())
    if base16:
        click.echo(printHash16(h))
    elif base32:
        click.echo(printHash32(h))
    else:
        click.echo((b'SHA256-' + b64encode(h)).decode())


@cli.group()
def nar():
    '''create or inspect NAR files'''
    pass


@nar.command()
@click.argument('path')
def pack(path):
    '''serialize a path to stdout in NAR format'''
    target_path = Path(path)
    if not target_path.exists:
        click.echo(f'Path {target_path} does not exist!', err=True)
        sys.exit(1)

    sys.stdout.buffer.write(nar_serialize(target_path))


if __name__ == '__main__':
    cli()
