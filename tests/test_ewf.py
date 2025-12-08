from __future__ import annotations

from typing import TYPE_CHECKING, BinaryIO

import pytest

from dissect.evidence.ewf import ewf
from tests._utils import absolute_path

if TYPE_CHECKING:
    from pathlib import Path


def test_ewf(ewf_single: BinaryIO) -> None:
    e = ewf.EWF(ewf_single)

    assert e.size == (4 * 1024 * 1024) + 16
    _assert_pattern(e.open(), e.size)

    with pytest.raises(IndexError, match="Chunk 1337 out of range"):
        e.read_chunk(1337)


def test_ewf_segmented(ewf_segmented: list[Path]) -> None:
    e = ewf.EWF(ewf_segmented)

    assert e.size == (4 * 1024 * 1024) + 16
    _assert_pattern(e.open(), e.size)


def _assert_pattern(fh: BinaryIO, size: int) -> None:
    for i in range(size // 4096):
        expected = bytes([i % 256] * 4096)
        assert fh.read(4096) == expected, f"Mismatch at offset {i * 4096:#x}"

    if size % 4096:
        assert fh.read() == b"kusjes van SRT<3"


def test_ewf_segment_lru(ewf_segmented: list[Path], monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ewf, "MAX_OPEN_SEGMENTS", 2)

    e = ewf.EWF(ewf_segmented)
    assert e._segment_lru == [3, 4]

    e.segment(0)
    assert e._segment_lru == [4, 0]

    e.segment(1)
    assert e._segment_lru == [0, 1]


def test_adcrypt_passphrase(ewf_encrypted_passphrase: BinaryIO) -> None:
    """Test if we can decrypt ADCRYPT EWF images, in this example a single segment EWF image."""
    e = ewf.EWF(ewf_encrypted_passphrase)

    assert e.is_adcrypt()
    assert e.is_locked()

    with pytest.raises(ValueError, match="EWF container is locked by ADCRYPT"):
        e.open()

    with pytest.raises(ValueError, match="Unable to unlock: HMAC verification of passphrase failed"):
        e.unlock(passphrase="asdf")

    e.unlock(passphrase="password")

    # FTK Imager strips our non-aligned footer...
    assert e.size == (4 * 1024 * 1024)
    _assert_pattern(e.open(), e.size)


def test_adcrypt_certificate(ewf_encrypted_certificate: BinaryIO) -> None:
    """Test if we can decrypt ADCRYPT EWF images, in this example a single segment EWF image."""
    e = ewf.EWF(ewf_encrypted_certificate)

    assert e.is_adcrypt()
    assert e.is_locked()

    with pytest.raises(ValueError, match="EWF container is locked by ADCRYPT"):
        e.open()

    with pytest.raises(ValueError, match="Unable to unlock: HMAC verification of passphrase failed"):
        e.unlock(passphrase="asdf")

    e.unlock(private_key=absolute_path("_data/ewf/encrypted-certificate/key"))

    # FTK Imager strips our non-aligned footer...
    assert e.size == (4 * 1024 * 1024)
    _assert_pattern(e.open(), e.size)
