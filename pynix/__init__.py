#!/usr/bin/env python3

import sys
from pathlib import Path
from base64 import b64encode
from pynix.nix import printHash16, printHash32, hash_sha256, nar_serialize, addToStore

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
@click.argument('paths', type=click.Path(exists=True, path_type=Path), nargs=-1)
def file(paths, base16: bool, base32: bool) -> None:
    '''print cryptographic hash of a regular file'''
    for p in paths:
        h = hash_sha256(p.read_bytes())
        if base16:
            click.echo(printHash16(h))
        elif base32:
            click.echo(printHash32(h))
        else:
            click.echo((b'sha256-' + b64encode(h)).decode())


@hash.command()
@click.option('--base16', is_flag=True)
@click.option('--base32', is_flag=True)
@click.argument('paths', type=click.Path(exists=True, path_type=Path), nargs=-1)
def path(paths, base16: bool, base32: bool) -> None:
    '''print cryptographic hash of the NAR serialization of a path'''
    for p in paths:
        h = hash_sha256(nar_serialize(p))
        if base16:
            click.echo(printHash16(h))
        elif base32:
            click.echo(printHash32(h))
        else:
            click.echo((b'sha256-' + b64encode(h)).decode())


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


@cli.group()
def store():
    '''manipulate a Nix store'''
    pass


@store.command()
@click.argument('path')
def add(path):
    '''
        Add a file or directory to the Nix addToStore
        (This is just a dry-run operation)
    '''

    target_path = Path(path)
    if not target_path.exists:
        click.echo(f'Path {target_path} does not exist!', err=True)
        sys.exit(1)

    print(addToStore(target_path, target_path.name))


if __name__ == '__main__':
    cli()
