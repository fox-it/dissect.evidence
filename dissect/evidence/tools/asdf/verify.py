from __future__ import print_function
import io
import sys
import hashlib
import argparse
import traceback
from zlib import crc32
from contextlib import contextmanager

from dissect.util.stream import RangeStream

from dissect.evidence.asdf import asdf


def iterfileobj(src):
    buf = src.read(io.DEFAULT_BUFFER_SIZE)
    while buf:
        yield buf
        buf = src.read(io.DEFAULT_BUFFER_SIZE)


def hashfileobj(src, alg="sha256"):
    ctx = hashlib.new(alg)
    for buf in iterfileobj(src):
        ctx.update(buf)
    return ctx.digest()


def crc32filobj(src):
    crc = 0
    for buf in iterfileobj(src):
        crc = crc32(buf, crc) & 0xFFFFFFFF
    return crc


@contextmanager
def status(line):
    TEMPLATE = "[{}] {:<50}{}"
    try:
        print(TEMPLATE.format("*", line, ""), end="\n")
        sys.stdout.flush()
        yield
        # print(TEMPLATE.format('*', line, '[OK]'), end='\n')
    except Exception as e:
        traceback.print_exc()
        # print(TEMPLATE.format('!', line, '[ERR]'), end='\n')
        print(f"[!] {e}")


def main():
    parser = argparse.ArgumentParser(description="Utility to verify ASDF files")
    parser.add_argument("file", metavar="ASDF", help="ASDF file to verify")
    parser.add_argument("--skip-hash", action="store_true", help="skip file hash")
    parser.add_argument("--skip-blocks", action="store_true", help="skip block checking")
    parser.add_argument("-v", "--verbose", action="store_true", help="increase verbosity")
    args = parser.parse_args()

    with open(args.file, "rb") as fh:
        header = None
        footer = None
        footer_offset = 0

        with status("Checking header"):
            header = asdf.c_asdf.header(fh)
            if header.magic != asdf.MAGIC:
                raise Exception("invalid header magic")

        with status("Checking footer"):
            fh.seek(-len(asdf.c_asdf.footer), io.SEEK_END)
            footer_offset = fh.tell()
            footer = asdf.c_asdf.footer(fh)
            if footer.magic != asdf.FOOTER_MAGIC:
                raise Exception("invalid footer magic")

        if not args.skip_hash:
            with status("Checking file hash"):
                hashstream = RangeStream(fh, 0, footer_offset)
                res = hashfileobj(hashstream)
                if res != footer.sha256:
                    raise Exception("file hash doesn't match")
        else:
            print("[!] Skipping file hash")

        if not args.skip_blocks:
            with status("Checking blocks"):
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
                    crc = crc32filobj(block_fh)
                    if crc != target_crc:
                        print(f"[!] Block {i} crc32 doesn't match. Expected 0x{target_crc:x}, got 0x{crc:x}")

        else:
            print("[!] Skipping block check")


if __name__ == "__main__":
    main()
