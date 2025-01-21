from __future__ import annotations

import argparse
import io
import shutil
import sys
from contextlib import nullcontext
from pathlib import Path

from dissect.evidence.asdf import asdf
from dissect.evidence.asdf.streams import HashedStream


def main() -> int:
    parser = argparse.ArgumentParser(description="Utility to repair block tables of ASDF files")
    parser.add_argument("file", metavar="ASDF", help="ASDF file to repair")
    parser.add_argument("-w", "--writer", default="-", help="file to write to, default is stdout")
    args = parser.parse_args()

    with Path(args.file).open("rb") as fh:
        header = asdf.c_asdf.header(fh)
        if header.magic != asdf.FILE_MAGIC:
            parser.exit(1, "invalid header magic, is this an ASDF file?")

        fh.seek(-len(asdf.c_asdf.footer), io.SEEK_END)
        footer = asdf.c_asdf.footer(fh)
        if footer.magic == asdf.FOOTER_MAGIC:
            parser.exit(1, "ASDF file already has a valid footer, no repair necessary")

        fh.seek(len(asdf.c_asdf.header))

        table = []
        prev_entry = None
        for block, file_offset in asdf.scrape_blocks(fh):
            entry = asdf.c_asdf.table_entry(
                flags=block.flags,
                idx=block.idx,
                offset=block.offset,
                size=block.size,
                file_offset=file_offset,
                file_size=0,  # Filled in later
            )
            table.append(entry)

            if prev_entry:
                prev_entry.file_size = (file_offset - prev_entry.file_offset) - len(asdf.c_asdf.block)

            prev_entry = entry

        if prev_entry:
            prev_entry.file_size = (fh.seek(0, io.SEEK_END) - prev_entry.file_offset) - len(asdf.c_asdf.block)

        print(f"[*] Recovered {len(table)} blocks", file=sys.stderr)

        ctx = nullcontext(getattr(sys.stdout, "buffer", sys.stdout)) if args.writer == "-" else None
        with ctx or Path(args.writer).open("wb") as fhout:
            try:
                print(f"[*] Writing to {args.writer}", file=sys.stderr)
                # Copy the original file
                fh.seek(0)
                fhout = HashedStream(fhout)
                shutil.copyfileobj(fh, fhout)

                print("[*] Writing block table", file=sys.stderr)
                # Write the block table
                table_offset = fh.tell()  # fhout might be stdout which we can't tell() on
                for entry in table:
                    entry.write(fhout)

                print("[*] Writing footer", file=sys.stderr)
                # Write the footer
                asdf.c_asdf.footer(
                    magic=asdf.FOOTER_MAGIC,
                    table_offset=table_offset,
                    sha256=fhout.digest(),
                ).write(fhout)

                print("[*] All done, use asdf-verify to check file", file=sys.stderr)
            except BrokenPipeError:
                pass

    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        pass
