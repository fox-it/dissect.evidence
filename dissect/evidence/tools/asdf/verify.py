from __future__ import annotations

import argparse
import hashlib
import io
import sys
import traceback
from contextlib import contextmanager
from pathlib import Path
from typing import TYPE_CHECKING, BinaryIO
from zlib import crc32

from dissect.util.stream import RangeStream

from dissect.evidence.asdf import asdf

if TYPE_CHECKING:
    from collections.abc import Iterator


def iter_fileobj(src: BinaryIO) -> Iterator[bytes]:
    buf = src.read(io.DEFAULT_BUFFER_SIZE)
    while buf:
        yield buf
        buf = src.read(io.DEFAULT_BUFFER_SIZE)


def hash_fileobj(src: BinaryIO, alg: str = "sha256") -> bytes:
    ctx = hashlib.new(alg)
    for buf in iter_fileobj(src):
        ctx.update(buf)
    return ctx.digest()


def crc32_filobj(src: BinaryIO) -> int:
    crc = 0
    for buf in iter_fileobj(src):
        crc = crc32(buf, crc) & 0xFFFFFFFF
    return crc


@contextmanager
def status(line: str, verbose: bool = False) -> Iterator:
    TEMPLATE = "[{}] {:<50}{}"
    try:
        print(TEMPLATE.format("*", line, ""), end="\n")
        sys.stdout.flush()
        yield
    except Exception as e:
        if verbose:
            traceback.print_exc()
        print(f"[!] {e}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Utility to verify ASDF files")
    parser.add_argument("file", metavar="ASDF", help="ASDF file to verify")
    parser.add_argument("--skip-hash", action="store_true", help="skip file hash")
    parser.add_argument("--skip-blocks", action="store_true", help="skip block checking")
    parser.add_argument("-v", "--verbose", action="store_true", help="increase verbosity")
    args = parser.parse_args()

    with Path(args.file).open("rb") as fh:
        header = None
        footer = None
        footer_offset = 0

        with status("Checking header", args.verbose):
            header = asdf.c_asdf.header(fh)
            if header.magic != asdf.FILE_MAGIC:
                print("[!] Invalid header magic")
                return 1

        with status("Checking footer", args.verbose):
            fh.seek(-len(asdf.c_asdf.footer), io.SEEK_END)
            footer_offset = fh.tell()
            footer = asdf.c_asdf.footer(fh)
            if footer.magic != asdf.FOOTER_MAGIC:
                footer = None
                print("[!] Invalid footer magic, please run asdf-repair")
                return 1

        if not args.skip_hash and footer:
            with status("Checking file hash", args.verbose):
                hashstream = RangeStream(fh, 0, footer_offset)
                res = hash_fileobj(hashstream)
                if res != footer.sha256:
                    print(f"[!] File hash doesn't match. Expected {footer.sha256.hex()}, got {res.hex()}")
                    return 1
        else:
            print("[@] Skipping file hash")

        if not args.skip_blocks and footer:
            with status("Checking blocks", args.verbose):
                table_size = (footer_offset - footer.table_offset) // len(asdf.c_asdf.table_entry)
                fh.seek(footer.table_offset)
                table = asdf.c_asdf.table_entry[table_size](fh)
                for i, entry in enumerate(table):
                    if not entry.flags & asdf.c_asdf.BLOCK_FLAG.CRC32:
                        continue

                    fh.seek(entry.file_offset)
                    block_header = asdf.c_asdf.block(fh)
                    if block_header.magic != asdf.BLOCK_MAGIC:
                        print(f"[!] Block {i} has invalid block magic")

                    data_offset = fh.tell()
                    fh.seek(entry.file_size - 4, io.SEEK_CUR)
                    target_crc = asdf.c_asdf.uint32(fh)

                    block_fh = RangeStream(fh, data_offset, entry.file_size - 4)
                    crc = crc32_filobj(block_fh)
                    if crc != target_crc:
                        print(f"[!] Block {i} crc32 doesn't match. Expected 0x{target_crc:x}, got 0x{crc:x}")

        else:
            print("[@] Skipping block check")

    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        pass
