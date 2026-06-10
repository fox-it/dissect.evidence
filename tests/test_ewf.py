from __future__ import annotations

from typing import TYPE_CHECKING, BinaryIO

import pytest

from dissect.evidence.ewf import ewf
from tests._utils import absolute_path

if TYPE_CHECKING:
    from pathlib import Path


def _assert_pattern(fh: BinaryIO, size: int) -> None:
    for i in range(size // 4096):
        expected = bytes([i % 256] * 4096)
        assert fh.read(4096) == expected, f"Mismatch at offset {i * 4096:#x}"

    if size % 4096:
        assert fh.read() == b"kusjes van SRT<3"


def test_ewf(ewf_single: BinaryIO) -> None:
    """Test reading from a single segment EWF image."""
    e = ewf.EWF(ewf_single)

    assert e.size == (4 * 1024 * 1024) + 16
    _assert_pattern(e.open(), e.size)

    with pytest.raises(IndexError, match="Chunk 1337 out of range"):
        e.read_chunk(1337)


def test_ewf_segmented(ewf_segmented: list[Path]) -> None:
    """Test reading from a segmented EWF image."""
    e = ewf.EWF(ewf_segmented)

    assert e.size == (4 * 1024 * 1024) + 16
    _assert_pattern(e.open(), e.size)


def test_ewf_segmented_find_files(ewf_segmented: list[Path]) -> None:
    """Test that providing a single segment file finds all segments in the same directory."""
    e = ewf.EWF(ewf_segmented[0])

    assert e.fh == ewf_segmented
    assert e.size == (4 * 1024 * 1024) + 16
    _assert_pattern(e.open(), e.size)


def test_ewf_segment_lru(ewf_segmented: list[Path], monkeypatch: pytest.MonkeyPatch) -> None:
    """Test that the LRU cache for open segments works as expected."""
    monkeypatch.setattr(ewf, "MAX_OPEN_SEGMENTS", 2)

    e = ewf.EWF(ewf_segmented)
    assert e._segment_lru == [3, 4]

    e.segment(0)
    assert e._segment_lru == [4, 0]

    e.segment(1)
    assert e._segment_lru == [0, 1]


def test_ewf_close_with_fh(ewf_single: BinaryIO) -> None:
    """Verify that EWF does not close file-like objects passed to it."""
    e = ewf.EWF(ewf_single)
    assert len(e._segments) == 1
    assert e._segment_lru == [0]

    e.close()
    assert e._segments == {}
    assert e._segment_lru == []

    # The file-like object passed to EWF should not be closed by EWF
    assert not ewf_single.closed


def test_ewf_close_with_paths(ewf_segmented: list[Path]) -> None:
    """Verify that EWF closes file handles opened from paths."""
    e = ewf.EWF(ewf_segmented)

    num_segments = len(e._segments)
    assert num_segments > 0

    # Store references to all file handles
    fhs = [e._segments[idx].fh for idx in range(num_segments)]

    e.close()

    # Verify all file handles are closed
    for fh in fhs:
        assert fh.closed
    assert e._segments == {}
    assert e._segment_lru == []


def test_ewf_context_manager_with_fh(ewf_single: BinaryIO) -> None:
    """Verify context manager closes EWF but not the file-like object passed to it."""
    with ewf.EWF(ewf_single) as e:
        assert isinstance(e, ewf.EWF)

    assert e._segments == {}
    assert e._segment_lru == []

    # The file-like object should not be closed by EWF's context manager
    assert not ewf_single.closed


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
