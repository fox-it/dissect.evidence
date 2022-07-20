import io
import sys
import stat
import shutil
import hashlib
import datetime
import argparse

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
    return ctx.hexdigest()


def stat_modestr(mode):
    """Helper method for generating a mode string from a numerical mode value."""
    is_dir = "d" if stat.S_ISDIR(mode) else "-"
    dic = {"7": "rwx", "6": "rw-", "5": "r-x", "4": "r--", "0": "---"}
    perm = str(oct(mode)[-3:])
    return is_dir + "".join(dic.get(x, x) for x in perm)


def handle_ls(snapshot, args):
    for member in snapshot.metadata.members():
        mtime = datetime.datetime.utcfromtimestamp(member.mtime).isoformat()
        print(f"{stat_modestr(member.mode)} {member.size:9d} {mtime} {member.name}")


def handle_cat(snapshot, args):
    try:
        fh = snapshot.metadata.open(args.name)
    except Exception:
        print(f"file doesn't exist: {args.name}")

    stdout = sys.stdout.buffer if hasattr(sys.stdout, "buffer") else sys.stdout
    try:
        shutil.copyfileobj(fh, stdout)
    except BrokenPipeError:
        pass


def handle_hash(snapshot, args):
    for name in snapshot.metadata.names():
        print(f"{hashfileobj(snapshot.metadata.open(name))}  {name}")


def main():
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
        parser.exit(1)

    with open(args.file, "rb") as fh:
        snapshot = asdf.AsdfSnapshot(fh)
        args.handler(snapshot, args)


if __name__ == "__main__":
    main()
