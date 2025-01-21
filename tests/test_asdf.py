from __future__ import annotations

import zlib
from io import BytesIO

import pytest

from dissect.evidence.asdf.asdf import AsdfSnapshot, AsdfWriter
from dissect.evidence.asdf.streams import CompressedStream, Crc32Stream, HashedStream
from dissect.evidence.exceptions import InvalidSnapshot


def test_asdf(asdf_writer: AsdfWriter) -> None:
    asdf_writer.add_bytes(b"\x00" * 0x1000, idx=0, base=0)
    asdf_writer.add_bytes(b"\x02" * 0x1000, idx=0, base=0x4000)
    asdf_writer.add_bytes(b"\x04" * 0x1000, idx=0, base=0x8000)
    asdf_writer.add_bytes(b"\x06" * 0x1000, idx=0, base=0x10000)
    asdf_writer.add_bytes(b"\xff" * 0x1000, idx=0, base=0x14000)

    asdf_writer.add_bytes(b"\x08" * 0x1000, idx=1, base=0x2000)
    asdf_writer.add_bytes(b"\x10" * 0x1000, idx=1, base=0x5000)
    asdf_writer.add_bytes(b"\x12" * 0x1000, idx=1, base=0x8000)
    asdf_writer.add_bytes(b"\x14" * 0x1000, idx=1, base=0xB000)
    asdf_writer.add_bytes(b"\xff" * 0x1000, idx=1, base=0xE000)

    asdf_writer.close()
    asdf_writer._fh.seek(0)

    reader = AsdfSnapshot(asdf_writer._fh)
    stream_0 = reader.open(0)
    assert [(run_start, run_size) for run_start, run_size, _, _ in stream_0.table] == [
        (0, 0x1000),
        (0x4000, 0x1000),
        (0x8000, 0x1000),
        (0x10000, 0x1000),
        (0x14000, 0x1000),
    ]

    assert stream_0.read(0x1000) == b"\x00" * 0x1000
    assert stream_0.read(0x1000) == (b"\xa5\xdf" * (0x1000 // 2))
    assert stream_0.read(0x4000) == (b"\xa5\xdf" * (0x2000 // 2)) + (b"\x02" * 0x1000) + (b"\xa5\xdf" * (0x1000 // 2))

    stream_0.seek(0)
    assert stream_0.read() == b"".join(
        [
            (b"\x00" * 0x1000),
            (b"\xa5\xdf" * (0x3000 // 2)),
            (b"\x02" * 0x1000),
            (b"\xa5\xdf" * (0x3000 // 2)),
            (b"\x04" * 0x1000),
            (b"\xa5\xdf" * (0x7000 // 2)),
            (b"\x06" * 0x1000),
            (b"\xa5\xdf" * (0x3000 // 2)),
            (b"\xff" * 0x1000),
        ]
    )

    stream_1 = reader.open(1)
    assert stream_1.read(0x4000) == (b"\xa5\xdf" * (0x2000 // 2)) + (b"\x08" * 0x1000) + (b"\xa5\xdf" * (0x1000 // 2))


def test_asdf_overlap(asdf_writer: AsdfWriter) -> None:
    asdf_writer.add_bytes(b"\x01" * 100, base=0)
    asdf_writer.add_bytes(b"\x02" * 100, base=200)
    assert asdf_writer._table_lookup[0] == [0, 200]

    asdf_writer.add_bytes(b"\x03" * 100, base=50)
    assert asdf_writer._table_lookup[0] == [0, 100, 200]

    asdf_writer.add_bytes(b"\x04" * 150, base=100)
    assert asdf_writer._table_lookup[0] == [0, 100, 150, 200]

    asdf_writer.add_bytes(b"\x05" * 50, base=25)
    assert asdf_writer._table_lookup[0] == [0, 100, 150, 200]

    asdf_writer.close()
    asdf_writer._fh.seek(0)

    reader = AsdfSnapshot(asdf_writer._fh)
    stream = reader.open(0)

    assert [(run_start, run_size) for run_start, run_size, _, _ in stream.table] == [
        (0, 100),
        (100, 50),
        (150, 50),
        (200, 100),
    ]
    assert stream.read() == (b"\x01" * 100) + (b"\x03" * 50) + (b"\x04" * 50) + (b"\x02" * 100)


def test_asdf_overlap_all(asdf_writer: AsdfWriter) -> None:
    asdf_writer.add_bytes(b"\x01" * 100, base=0)
    asdf_writer.add_bytes(b"\x02" * 100, base=200)
    asdf_writer.add_bytes(b"\x03" * 100, base=50)
    asdf_writer.add_bytes(b"\x04" * 150, base=100)
    assert asdf_writer._table_lookup[0] == [0, 100, 150, 200]
    asdf_writer.add_bytes(b"\x06" * 400, base=0)
    assert asdf_writer._table_lookup[0] == [0, 100]

    asdf_writer.close()
    asdf_writer._fh.seek(0)

    reader = AsdfSnapshot(asdf_writer._fh)
    stream = reader.open(0)

    assert [(run_start, run_size) for run_start, run_size, _, _ in stream.table] == [
        (0, 100),
        (100, 300),
    ]
    assert stream.read() == (b"\x01" * 100) + (b"\x06" * 300)


def test_asdf_overlap_contiguous(asdf_writer: AsdfWriter) -> None:
    asdf_writer.add_bytes(b"\x01" * 100, base=0)
    asdf_writer.add_bytes(b"\x02" * 100, base=100)
    assert asdf_writer._table_lookup[0] == [0, 100]

    asdf_writer.add_bytes(b"\x03" * 75, base=50)
    assert asdf_writer._table_lookup[0] == [0, 100]

    asdf_writer.close()
    asdf_writer._fh.seek(0)

    reader = AsdfSnapshot(asdf_writer._fh)
    stream = reader.open(0)

    assert [(run_start, run_size) for run_start, run_size, _, _ in stream.table] == [
        (0, 100),
        (100, 100),
    ]
    assert stream.read() == (b"\x01" * 100) + (b"\x02" * 100)


def test_asdf_overlap_seek(asdf_writer: AsdfWriter) -> None:
    asdf_writer.add_bytes(b"\x00" * 100, base=0)
    asdf_writer.add_bytes(b"\x00" * 100, base=200)
    asdf_writer.add_bytes(bytes(range(200)), base=50)
    assert asdf_writer._table_lookup[0] == [0, 100, 200]

    asdf_writer.close()
    asdf_writer._fh.seek(0)

    reader = AsdfSnapshot(asdf_writer._fh)
    stream = reader.open(0)

    assert [(run_start, run_size) for run_start, run_size, _, _ in stream.table] == [
        (0, 100),
        (100, 100),
        (200, 100),
    ]
    assert stream.read() == (b"\x00" * 100) + bytes(range(50, 150)) + (b"\x00" * 100)


def test_asdf_mid_run(asdf_writer: AsdfWriter) -> None:
    asdf_writer.add_bytes(bytes([v & 0xFF for v in range(4096)]), base=0)

    asdf_writer.close()
    asdf_writer._fh.seek(0)

    reader = AsdfSnapshot(asdf_writer._fh)
    stream = reader.open(0)
    stream.align = 512

    stream.seek(1100)
    assert stream.read(512) == bytes([v & 0xFF for v in range(1100, 1100 + 512)])


def test_asdf_metadata(asdf_writer: AsdfWriter) -> None:
    asdf_writer.add_metadata_file("file", BytesIO(b"content"))
    asdf_writer.add_metadata_file("dir/file", BytesIO(b"content here too"))

    asdf_writer.close()
    asdf_writer._fh.seek(0)

    reader = AsdfSnapshot(asdf_writer._fh)

    assert reader.metadata.names() == ["file", "dir/file"]
    assert reader.metadata.open("file").read() == b"content"
    assert reader.metadata.open("dir/file").read() == b"content here too"

    with pytest.raises(KeyError):
        reader.metadata.open("nonexistent")


def test_asdf_stream_crc32() -> None:
    fh = BytesIO()
    stream = Crc32Stream(fh)
    stream.write(b"srt was here")
    stream.finalize()

    assert fh.getvalue() == b"srt was here\x2f\x0e\x60\xa4"


def test_asdf_stream_compressed() -> None:
    fh = BytesIO()
    stream = CompressedStream(fh)
    stream.write(b"srt was here" * 100)
    stream.finalize()

    assert zlib.decompress(fh.getvalue()) == b"srt was here" * 100


def test_asdf_stream_hashed() -> None:
    fh = BytesIO()
    stream = HashedStream(fh)
    stream.write(b"srt was here")
    assert stream.hexdigest() == "cd7bd850d261f8fa39a41d0963b42dae5f303615db19ac79e5044586d0825b7b"


def test_asdf_stream_combined() -> None:
    fh = BytesIO()
    stream = Crc32Stream(fh)
    stream = CompressedStream(stream)
    stream = HashedStream(stream)

    stream.write(b"srt was here" * 100)
    stream.finalize()

    assert stream.hexdigest() == "ba40ab3ee826d6aa0f085dfccbb72d8feefa72548015c4456c1fd741d0266a94"
    assert fh.getvalue() == bytes.fromhex("789c2b2e2a51284f2c56c8482d4a2d1e658fb247d9a3ec41cc06004445c530665f35fc")


def test_asdf_scrape(asdf_writer: AsdfWriter) -> None:
    asdf_writer.add_bytes(b"\x00" * 0x1000, idx=0, base=0)
    asdf_writer.add_bytes(b"\x02" * 0x1000, idx=0, base=0x4000)
    asdf_writer.add_bytes(b"\x04" * 0x1000, idx=0, base=0x8000)
    asdf_writer.add_bytes(b"\x06" * 0x1000, idx=0, base=0x10000)
    asdf_writer.add_bytes(b"\xff" * 0x1000, idx=0, base=0x14000)

    # Don't close so we don't have a footer and block table
    asdf_writer._fh.seek(0)

    with pytest.raises(InvalidSnapshot):
        AsdfSnapshot(asdf_writer._fh)

    asdf_writer._fh.seek(0)
    reader = AsdfSnapshot(asdf_writer._fh, recover=True)
    stream = reader.open(0)

    assert [(run_start, run_size) for run_start, run_size, _, _ in stream.table] == [
        (0, 0x1000),
        (0x4000, 0x1000),
        (0x8000, 0x1000),
        (0x10000, 0x1000),
        (0x14000, 0x1000),
    ]

    assert stream.read() == b"".join(
        [
            (b"\x00" * 0x1000),
            (b"\xa5\xdf" * (0x3000 // 2)),
            (b"\x02" * 0x1000),
            (b"\xa5\xdf" * (0x3000 // 2)),
            (b"\x04" * 0x1000),
            (b"\xa5\xdf" * (0x7000 // 2)),
            (b"\x06" * 0x1000),
            (b"\xa5\xdf" * (0x3000 // 2)),
            (b"\xff" * 0x1000),
        ]
    )
