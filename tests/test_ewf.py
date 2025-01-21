from __future__ import annotations

from typing import TYPE_CHECKING, BinaryIO
from unittest.mock import MagicMock, patch

from dissect.evidence import ewf

if TYPE_CHECKING:
    import pytest


def test_ewf(ewf_data: BinaryIO) -> None:
    e = ewf.EWF(ewf_data)

    assert e.size == 4097
    assert e.open().read(4097) == (b"\xde\xad\xbe\xef" * 1024) + b"\n"


@patch("dissect.evidence.ewf.Segment")
def test_ewf_open_segment(MockSegment: MagicMock, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ewf, "MAX_OPEN_SEGMENTS", 2)

    mock_segment = MockSegment.return_value
    mock_segment.volume.sector_size = 512
    mock_segment.sector_count = 2

    mock_fh = [MagicMock(), MagicMock(), MagicMock(), MagicMock()]
    e = ewf.EWF(mock_fh)

    assert e._segment_offsets == [2, 4, 6]
    assert e._segment_lru == [2, 3]

    tmp = e.open_segment(0)
    assert tmp.offset == 0
    assert tmp.sector_offset == 0
    assert e._segment_lru == [3, 0]

    tmp = e.open_segment(1)
    assert tmp.offset == 1024
    assert tmp.sector_offset == 2
    assert e._segment_lru == [0, 1]
