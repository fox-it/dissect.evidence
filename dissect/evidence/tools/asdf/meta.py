from __future__ import annotations

import argparse
import datetime
import hashlib
import io
import shutil
import stat
import sys
from pathlib import Path
from typing import TYPE_CHECKING, BinaryIO

from dissect.evidence.asdf import asdf

if TYPE_CHECKING:
    from collections.abc import Iterator


def iterfileobj(src: BinaryIO) -> Iterator[bytes]:
    buf = src.read(io.DEFAULT_BUFFER_SIZE)
    while buf:
        yield buf
        buf = src.read(io.DEFAULT_BUFFER_SIZE)


def hashfileobj(src: BinaryIO, alg: str = "sha256") -> str:
    ctx = hashlib.new(alg)
    for buf in iterfileobj(src):
        ctx.update(buf)
    return ctx.hexdigest()


def handle_ls(snapshot: asdf.AsdfSnapshot, args: argparse.Namespace) -> None:
    for member in snapshot.metadata.members():
        mtime = datetime.datetime.fromtimestamp(member.mtime, datetime.timezone.utc).isoformat()

        print(f"{stat.filemode(member.mode)} {member.size:9d} {mtime} {member.name}")


def handle_cat(snapshot: asdf.AsdfSnapshot, args: argparse.Namespace) -> None:
    try:
        fh = snapshot.metadata.open(args.name)
    except Exception:
        print(f"file doesn't exist: {args.name}")

    stdout = sys.stdout.buffer if hasattr(sys.stdout, "buffer") else sys.stdout
    try:
        shutil.copyfileobj(fh, stdout)
    except BrokenPipeError:
        pass


def handle_hash(snapshot: asdf.AsdfSnapshot, args: argparse.Namespace) -> None:
    for name in snapshot.metadata.names():
        print(f"{hashfileobj(snapshot.metadata.open(name))}  {name}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Utility to work with ASDF metadata")
    parser.add_argument("file", metavar="ASDF", help="ASDF file to verify")
    subparsers = parser.add_subparsers(help="metadata command")
    parser_ls = subparsers.add_parser("ls", help="list metadata contents")
    parser_ls.set_defaults(handler=handle_ls)

    parser_cat = subparsers.add_parser("cat", help="cat metadata contents")
    parser_cat.add_argument("name", help="file to cat")
    parser_cat.set_defaults(handler=handle_cat)

    parser_hash = subparsers.add_parser("hash", help="hash metadata contents")
    parser_hash.set_defaults(handler=handle_hash)
    args = parser.parse_args()

    if not hasattr(args, "handler"):
        parser.print_help()
        return 1

    with Path(args.file).open("rb") as fh:
        snapshot = asdf.AsdfSnapshot(fh)
        args.handler(snapshot, args)

    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        pass
