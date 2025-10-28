from __future__ import annotations

import argparse
import logging
from pathlib import Path

from dissect.evidence.ad1.ad1 import find_files as find_ad1_files
from dissect.evidence.adcrypt.adcrypt import ADCrypt
from dissect.evidence.ewf.ewf import find_files as find_ewf_files
from dissect.evidence.tools.util import catch_sigpipe

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s]\t%(message)s")
log = logging.getLogger(__name__)


@catch_sigpipe
def main() -> None:
    help_formatter = argparse.ArgumentDefaultsHelpFormatter
    parser = argparse.ArgumentParser(
        prog="adcrypt",
        description="Decrypt E01 or AD1 ADCRYPT encrypted segment files.",
        fromfile_prefix_chars="@",
        formatter_class=help_formatter,
    )

    parser.add_argument("input", type=Path, help="path to encrypted file")
    parser.add_argument("-p", "--passphrase", type=str, help="user passphrase or certificate passphrase")
    parser.add_argument("-c", "--certificate", type=Path, help="user certificate")
    parser.add_argument("-o", "--output", type=Path, required=True, help="path to output file")

    args = parser.parse_args()

    in_path = args.input.resolve()
    out_path = args.output.resolve()

    if not in_path.exists():
        parser.exit(f"Input file doesn't exist: {in_path}")

    if not out_path.is_dir():
        parser.exit(f"Output dir does not exist: {out_path}")

    if in_path.parent == out_path:
        parser.exit("Output dir cannot be same as parent of input file")

    if not args.passphrase and not args.certificate:
        parser.exit("No passphrase or certificate provided")

    segment_paths = find_ad1_files(in_path) if in_path.suffix.lower() == ".ad1" else find_ewf_files(in_path)

    adcrypt = ADCrypt([path.open("rb") for path in segment_paths])

    try:
        adcrypt.decrypt(passphrase=args.passphrase, private_key=args.certificate)
    except (ValueError, TypeError) as e:
        log.exception(e, exc_info=False)  # noqa: TRY401
        parser.exit(1)

    log.info("Calculated decryption keys for %s segment files (%r)", len(segment_paths), segment_paths[0].name)

    for i, segment in enumerate(adcrypt.segments):
        with out_path.joinpath(segment_paths[i].name).open("wb") as fh:
            size = segment_paths[i].lstat().st_size // 1024 // 1024
            log.info("Decrypting segment file %r (%s MB) ..", segment_paths[i].name, size)
            fh.write(segment.read())

    log.info("Finished decrypting file(s), result saved to %s", out_path)
