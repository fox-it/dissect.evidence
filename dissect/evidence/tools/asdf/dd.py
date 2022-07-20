import io
import sys
import argparse

from dissect.evidence.asdf import asdf

try:
    from tqdm import tqdm

    HAS_TQDM = True
except ImportError:
    HAS_TQDM = False


class Progress:
    def __init__(self, size):
        self.size = size
        if HAS_TQDM:
            self.t = tqdm(total=size, unit="B", unit_scale=True)

    def update(self, offset):
        if HAS_TQDM:
            self.t.update(offset - self.t.n)
        else:
            sys.stderr.write(f"\r{offset / float(self.size) * 100:0.2f}%")
            sys.stderr.flush()

    def close(self):
        if HAS_TQDM:
            self.t.close()


def copystream(fhin, fhout, length):
    n, remain = divmod(length, io.DEFAULT_BUFFER_SIZE)
    for _ in range(n):
        fhout.write(fhin.read(io.DEFAULT_BUFFER_SIZE))
    fhout.write(fhin.read(remain))


def main():
    parser = argparse.ArgumentParser(description="Utility to dump ASDF streams")
    parser.add_argument("file", metavar="ASDF", help="ASDF file to dd")
    parser.add_argument("-w", "--writer", default="-", help="file to write to, default is stdout")
    parser.add_argument("-s", "--stream", type=int, default=0, help="stream index to dump (0-255)")
    parser.add_argument(
        "--fast", action="store_true", default=False, help="dump fast, fill sparse with null bytes instead"
    )
    parser.add_argument("--no-tqdm", action="store_true", default=False, help="disable tqdm progress bar")
    args = parser.parse_args()

    if args.fast and args.writer == "-":
        parser.exit("--fast is not supported when writing to stdout")

    if args.no_tqdm:
        global HAS_TQDM
        HAS_TQDM = False

    with open(args.file, "rb") as fh:
        snapshot = asdf.AsdfSnapshot(fh)

        if args.stream > 255 or not snapshot.contains(args.stream):
            parser.print_help()
            print()

            valid_keys = ", ".join(str(i) for i in snapshot.table.keys())
            parser.exit(f"invalid stream index, must be one of {valid_keys}")

        stream = snapshot.open(args.stream)
        progress = Progress(stream.size)

        if args.writer == "-":
            fhout = sys.stdout.buffer if hasattr(sys.stdout, "buffer") else sys.stdout
        else:
            fhout = open(args.writer, "wb")

        try:
            if args.fast:
                for entry in stream.table:
                    stream.fh.seek(entry.file_offset + 24)
                    fhout.seek(entry.offset)
                    copystream(stream.fh, fhout, entry.size)

                    progress.update(entry.offset)
            else:
                offset = 0
                while True:
                    buf = stream.read(io.DEFAULT_BUFFER_SIZE * 8)
                    if not buf:
                        break
                    fhout.write(buf)
                    progress.update(offset)
                    offset += len(buf)
        except BrokenPipeError:
            pass
        finally:
            progress.close()
            if args.writer != "-":
                fhout.close()


if __name__ == "__main__":
    main()
