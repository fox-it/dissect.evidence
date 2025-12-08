from __future__ import annotations

import hashlib
import logging
from typing import TYPE_CHECKING

from dissect.evidence.ad1.ad1 import find_files
from dissect.evidence.tools import adcrypt
from tests._utils import absolute_path

if TYPE_CHECKING:
    from pathlib import Path

    import pytest


def test_adcrypt_passphrase(tmp_path: Path, caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch) -> None:
    """Test if we can decrypt ADCRYPT AD1 images using the adcrypt tool."""

    with caplog.at_level(logging.DEBUG, adcrypt.log.name), monkeypatch.context() as m:
        m.setattr(
            "sys.argv",
            [
                "adcrypt",
                str(absolute_path("_data/ad1/encrypted-passphrase/encrypted.ad1")),
                "-p",
                "password",
                "-o",
                str(tmp_path),
            ],
        )

        adcrypt.main()

        for i in range(1, 14):
            assert f"Decrypting segment file 'encrypted.ad{i}'" in caplog.text

        assert tmp_path.joinpath("encrypted.ad1").exists()

        ctx = hashlib.sha1()
        for path in find_files(tmp_path.joinpath("encrypted.ad1")):
            ctx.update(path.read_bytes())

        assert ctx.hexdigest() == "3b7449fd09e5803006ce1b3aba5bb4c48c083f12"


def test_adcrypt_certificate(tmp_path: Path, caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch) -> None:
    """Test if we can decrypt ADCRYPT AD1 images using the adcrypt tool."""

    with caplog.at_level(logging.DEBUG, adcrypt.log.name), monkeypatch.context() as m:
        m.setattr(
            "sys.argv",
            [
                "adcrypt",
                str(absolute_path("_data/ad1/encrypted-certificate/encrypted.ad1")),
                "-c",
                str(absolute_path("_data/ad1/encrypted-certificate/key")),
                "-o",
                str(tmp_path),
            ],
        )

        adcrypt.main()

        for i in range(1, 8):
            assert f"Decrypting segment file 'encrypted.ad{i}'" in caplog.text

        assert tmp_path.joinpath("encrypted.ad1").exists()

        ctx = hashlib.sha1()
        for path in find_files(tmp_path.joinpath("encrypted.ad1")):
            ctx.update(path.read_bytes())

        assert ctx.hexdigest() == "23cdf7c35327d5b24c81ff48b483ae805c27df6a"
