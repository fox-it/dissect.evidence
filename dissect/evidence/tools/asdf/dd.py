import argparse
import io
import sys
from contextlib import nullcontext
from pathlib import Path
from typing import BinaryIO

from dissect.evidence.asdf import asdf

try:
    from tqdm import tqdm  # type: ignore

    HAS_TQDM = True
except ImportError:
    HAS_TQDM = False


class Progress:
    def __init__(self, size: int):
        self.size = size
        if HAS_TQDM:
            self.t = tqdm(total=size, unit="B", unit_scale=True)

    def update(self, offset: int) -> None:
        if HAS_TQDM:
            self.t.update(offset - self.t.n)
        else:
            sys.stderr.write(f"\r{offset / float(self.size) * 100:0.2f}%")
            sys.stderr.flush()

    def close(self) -> None:
        if HAS_TQDM:
            self.t.close()


def copy_stream(fhin: BinaryIO, fhout: BinaryIO, length: int) -> None:
    n, remain = divmod(length, io.DEFAULT_BUFFER_SIZE)
    for _ in range(n):
        fhout.write(fhin.read(io.DEFAULT_BUFFER_SIZE))
    fhout.write(fhin.read(remain))


def fill_zero(fhout: BinaryIO, length: int) -> None:
    n, remain = divmod(length, io.DEFAULT_BUFFER_SIZE)
    for _ in range(n):
        fhout.write(b"\x00" * io.DEFAULT_BUFFER_SIZE)
    fhout.write(b"\x00" * remain)


def main() -> int:
    parser = argparse.ArgumentParser(description="Utility to dump ASDF streams")
    parser.add_argument("file", metavar="ASDF", help="ASDF file to dd")
    parser.add_argument("-w", "--writer", default="-", help="file to write to, default is stdout")
    parser.add_argument("-s", "--stream", type=int, default=0, help="stream index to dump (0-255)")
    parser.add_argument("--no-tqdm", action="store_true", default=False, help="disable tqdm progress bar")
    args = parser.parse_args()

    if args.no_tqdm:
        global HAS_TQDM
        HAS_TQDM = False

    with Path(args.file).open("rb") as fh:
        snapshot = asdf.AsdfSnapshot(fh)

        if args.stream > 255 or not snapshot.contains(args.stream):
            parser.print_help()
            print(file=sys.stderr)

            valid_keys = ", ".join(str(i) for i in snapshot.table)
            parser.exit(1, f"invalid stream index, must be one of {valid_keys}")

        stream = snapshot.open(args.stream)
        progress = Progress(stream.size)

        ctx = nullcontext(getattr(sys.stdout, "buffer", sys.stdout)) if args.writer == "-" else None
        with ctx or Path(args.writer).open("wb") as fhout:
            try:
                prev_offset = 0
                for offset, size, _, data_offset in stream.table:
                    stream.fh.seek(data_offset)
                    if fhout.seekable():
                        fhout.seek(offset)
                    else:
                        fill_zero(fhout, offset - prev_offset)
                    copy_stream(stream.fh, fhout, size)

                    progress.update(offset)
                    prev_offset = offset
            except BrokenPipeError:
                pass
            finally:
                progress.close()

    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        pass
