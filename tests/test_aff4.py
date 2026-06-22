from __future__ import annotations

import hashlib

from dissect.evidence.aff4.aff4 import AFF4
from dissect.evidence.aff4.metadata import APFSContainerImage, DiscontiguousImage, ImageStream, Map
from dissect.evidence.aff4.util import CompressionMethod
from tests.conftest import absolute_path


def test_aff4_linear() -> None:
    aff4 = AFF4(absolute_path("_data/aff4/Base-Linear.aff4"))

    segment = aff4.segment(0)
    assert segment.uri == "aff4://685e15cc-d0fb-4dbc-ba47-48117fc77044"
    assert segment.version == {"major": "1", "minor": "0", "tool": "Evimetry 2.2.0"}

    assert len(aff4.images()) == 1

    image = aff4.images()[0]
    map_stream = image.data_stream.open()

    assert hashlib.sha1(map_stream.streams[0].read()).hexdigest() == "fbac22cca549310bc5df03b7560afcf490995fbb"

    map_stream.seek(32768)
    assert map_stream.read(32768) == b"\x00" * 32768


def test_aff4_allocated() -> None:
    aff4 = AFF4(absolute_path("_data/aff4/Base-Allocated.aff4"))
    assert len(aff4.images()) == 1

    image = aff4.images()[0]
    stream = image.open()

    assert stream.read(32) == bytes.fromhex("33c08ed0bc007c8ec08ed8be007cbf0006b90002fcf3a450681c06cbfbb90400")
    stream.seek(32326 * 512)
    assert stream.read(32) == bytes.fromhex("4dd98b8ce23944586ba2a8db041c6d368141368b90a716c25e9a0ca6e6d90b7e")

    # Test map stream boundaries
    stream.seek(17825792)
    assert stream.read(518) == b"UNKNOWN" * 74
    stream.seek(82836992)
    assert stream.read(512) == (b"NKNOWNU" * (512 // 7)) + b"N"
    assert stream.read(8) == b"\x00" * 8


def test_aff4_read_error() -> None:
    aff4 = AFF4(absolute_path("_data/aff4/Base-Linear-ReadError.aff4"))
    assert len(aff4.images()) == 1

    image = aff4.images()[0]
    stream = image.open()

    stream.seek(15728640)
    assert stream.read(65536) == b"UNREADABLEDATA" * (65536 // 14) + b"UN"


def test_aff4_exabyte_sparse() -> None:
    aff4 = AFF4(absolute_path("_data/aff4/Base-ExabyteSparse.aff4"))
    assert len(aff4.images()) == 1

    image = aff4.images()[0]
    stream = image.open()

    stream.seek(1048576)
    assert stream.read(512) == b"\x00" * 512

    stream.seek(4611686018427387648)
    assert stream.read(512)[-2:] == b"\x55\xaa"


def test_aff4_discontiguous() -> None:
    aff4 = AFF4(absolute_path("_data/aff4/Base-Discontiguous.aff4"))

    # A DiscontiguousImage is not a DiskImage, but it is an Image, so images() surfaces it.
    assert len(aff4.images()) == 1

    image = aff4.images()[0]
    assert isinstance(image, DiscontiguousImage)
    assert image.size == 65536
    assert image.block_size == 4096

    # The image maps onto a Map data stream backed by an lz4 bevy ImageStream.
    assert isinstance(image.data_stream, Map)
    assert image.data_stream.size == 65536

    (stream_obj,) = aff4.information.find("ImageStream")
    assert stream_obj.chunk_size == 32768
    assert stream_obj.compression_method is CompressionMethod.LZ4

    stream = image.open()

    # Leading sparse region falls back to the Zero gap stream.
    stream.seek(0)
    assert stream.read(512) == b"\x00" * 512

    # Populated block, read from the bevy ImageStream.
    stream.seek(32768)
    chunk = stream.read(32768)
    assert hashlib.sha1(chunk).hexdigest() == "250cc926052d2c85c867ae6482b824464190a5fe"
    assert hashlib.md5(chunk).hexdigest() == "8bccb0aff9d7ac4a617e66d64af8ed5b"

    # The ImageStream declares aff4:hash over its reconstructed content (SHA1, then MD5); they match.
    assert stream_obj.hash == [hashlib.sha1(chunk).hexdigest(), hashlib.md5(chunk).hexdigest()]

    # A read spanning the gap/data boundary stitches both together.
    stream.seek(32256)
    assert stream.read(1024) == (b"\x00" * 512) + chunk[:512]


def test_aff4_apfs_container_image() -> None:
    aff4 = AFF4(absolute_path("_data/aff4/Base-Discontiguous.aff4"))

    image = aff4.images()[0]

    # The bbt:APFSContainerImage type wins (longest MRO) so the object is the vendor subclass,
    # while still being a DiscontiguousImage.
    assert isinstance(image, APFSContainerImage)
    assert isinstance(image, DiscontiguousImage)

    # Vendor (BlackBag) bbt: metadata.
    assert image.apfs_container_type == "https://blackbagtech.com/aff4/Schema#APFST2ContainerType"
    assert image.contains_extents is True
    assert image.contains_unallocated is True

    # integrityStream resolves to the backing bevy ImageStream.
    integrity = image.integrity_stream
    assert isinstance(integrity, ImageStream)
    assert integrity.chunk_size == 32768
    assert integrity.size == 32768


def test_aff4_striped() -> None:
    aff4 = AFF4(
        [
            absolute_path("_data/aff4/striped/Base-Linear_1.aff4"),
            absolute_path("_data/aff4/striped/Base-Linear_2.aff4"),
        ]
    )
    assert len(aff4.images()) == 1

    image = aff4.images()[0]
    stream = image.open()

    stream.seek(0)
    assert hashlib.sha1(stream.read(512)).hexdigest() == "341427eedd4172fa61d85af7c8cf3c8d5a8656d5"

    stream.seek(15335424)
    assert hashlib.sha1(stream.read(512)).hexdigest() == "54cc2127dc9f536ead23c9bc898ffb73d528c7ed"


def test_aff4_close_with_fh() -> None:
    """Verify that AFF4 does not close file-like objects passed to it."""
    path = absolute_path("_data/aff4/Base-Linear.aff4")
    with path.open("rb") as fh:
        aff4 = AFF4(fh)
        assert len(aff4._segments) == 1
        assert aff4._segment_lru == [0]

        aff4.close()
        assert aff4._segments == {}
        assert aff4._segment_lru == []

        # The file-like object passed to AD1 should not be closed by AD1
        assert not fh.closed


def test_aff4_close_with_paths() -> None:
    """Verify that AFF4 closes file handles opened from paths."""
    aff4 = AFF4(
        [
            absolute_path("_data/aff4/striped/Base-Linear_1.aff4"),
            absolute_path("_data/aff4/striped/Base-Linear_2.aff4"),
        ]
    )

    num_segments = len(aff4._segments)
    assert num_segments > 0

    # Store references to all file handles
    fhs = [aff4._segments[idx].fh for idx in range(num_segments)]

    aff4.close()

    # Verify all file handles are closed
    for fh in fhs:
        assert fh.closed
    assert aff4._segments == {}
    assert aff4._segment_lru == []


def test_aff4_context_manager_with_fh() -> None:
    """Verify context manager closes AFF4 but not the file-like object passed to it."""
    path = absolute_path("_data/aff4/Base-Linear.aff4")
    with path.open("rb") as fh:
        with AFF4(fh) as aff4:
            assert isinstance(aff4, AFF4)

        assert aff4._segments == {}
        assert aff4._segment_lru == []

        # The file-like object should not be closed by AFF4's context manager
        assert not fh.closed
