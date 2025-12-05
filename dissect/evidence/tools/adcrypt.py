from __future__ import annotations

import argparse
import logging
import shutil
from pathlib import Path

from dissect.evidence.ad1.ad1 import find_files as find_ad1_files
from dissect.evidence.adcrypt.adcrypt import ADCrypt, is_adcrypt
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
    parser.add_argument("-o", "--output", type=Path, required=True, help="path to output directory")

    args = parser.parse_args()

    in_path: Path = args.input.resolve()
    out_path: Path = args.output.resolve()

    if not in_path.exists():
        parser.exit(f"Input file does not exist: {in_path}")

    if not out_path.is_dir():
        parser.exit(f"Output directory does not exist: {out_path}")

    if in_path.parent == out_path:
        parser.exit("Output directory cannot be the same as the input file directory")

    if not args.passphrase and not args.certificate:
        parser.exit("No passphrase or certificate provided")

    segments = find_ad1_files(in_path) if in_path.suffix.lower() == ".ad1" else find_ewf_files(in_path)
    if not segments:
        parser.exit(f"No AD1 or E01 segment files found at: {in_path}")

    with segments[0].open("rb") as fh:
        if not is_adcrypt(fh):
            parser.exit(f"File is not an ADCRYPT container: {segments[0]}")

        adcrypt = ADCrypt(fh)

    try:
        adcrypt.unlock(passphrase=args.passphrase, private_key=args.certificate)
    except (ValueError, TypeError) as e:
        log.exception(e, exc_info=False)  # noqa: TRY401
        parser.exit(1)

    for i, segment in enumerate(segments):
        with segment.open("rb") as fh_in, out_path.joinpath(segment.name).open("wb") as fh_out:
            fh_crypt = adcrypt.wrap(fh_in, index=i)
            log.info("Decrypting segment file %r (%s MB) ..", segment.name, fh_crypt.size // 1024 // 1024)
            shutil.copyfileobj(fh_crypt, fh_out)

    log.info("Finished decrypting file(s), result saved to %s", out_path)
