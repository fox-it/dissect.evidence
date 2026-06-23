from __future__ import annotations

import struct
import zlib
from bisect import bisect_right
from functools import lru_cache
from typing import TYPE_CHECKING, BinaryIO

from dissect.util.compression import lz4, snappy
from dissect.util.stream import AlignedStream

from dissect.evidence.aff4.util import NS_AFF4, CompressionMethod

if TYPE_CHECKING:
    from dissect.evidence.aff4.metadata import ImageStream, Information, Map


def _open_stream(ctx: Information, id: str) -> BinaryIO:
    """Open a stream by its AFF4 ID."""
    if id == f"{NS_AFF4}Zero":
        stream = SymbolicStream(b"\x00")
    elif id == f"{NS_AFF4}UnknownData":
        stream = SymbolicStream(b"UNKNOWN")
    elif id == f"{NS_AFF4}UnreadableData":
        stream = SymbolicStream(b"UNREADABLEDATA")
    elif id.startswith(f"{NS_AFF4}SymbolicStream"):
        stream = SymbolicStream(bytes.fromhex(id[-2:]))
    else:
        stream = ctx.aff4.information.get(id).open()

    if stream is None:
        raise ValueError(f"Could not open stream {id}")

    return stream


class MapStream(AlignedStream):
    """AFF4 stream implementation for ``Map`` objects implementation."""

    def __init__(self, map: Map):
        self.map = map

        self.default_gap_stream = _open_stream(self.map.ctx, self.map.map_gap_default_stream)
        self.streams = [_open_stream(self.map.ctx, entry) for entry in self.map.index]
        self.stream_map = self.map.map
        # Map entries are keyed by their end offset. ``_read`` binary searches this with ``bisect_right``,
        # which requires the keys to be sorted ascending. The on-disk map is not guaranteed to be ordered.
        self._lookup = sorted(self.stream_map.keys())

        super().__init__(self.map.size)

    def _read(self, offset: int, length: int) -> bytes:
        result = []

        idx = bisect_right(self._lookup, offset)
        while length > 0:
            mapped_offset, mapped_length, target_offset, stream_idx = self.stream_map[self._lookup[idx]]

            if offset < mapped_offset:
                # Hole
                read_size = min(length, mapped_offset - offset)
                result.append(self.default_gap_stream.read(read_size))
            else:
                offset_in_mapping = offset - mapped_offset
                read_size = min(length, mapped_length - offset_in_mapping)

                stream = self.streams[stream_idx]
                stream.seek(target_offset + offset_in_mapping)
                result.append(stream.read(read_size))

                idx += 1

            offset += read_size
            length -= read_size

        return b"".join(result)

    def close(self) -> None:
        for stream in self.streams:
            stream.close()
        super().close()


class SymbolicStream(AlignedStream):
    """AFF4 stream that returns a repeating pattern."""

    def __init__(self, pattern: bytes):
        self.pattern = pattern
        super().__init__(None)

    def _read(self, offset: int, length: int) -> bytes:
        mult, rem = divmod(length, len(self.pattern))
        return (self.pattern * mult) + self.pattern[:rem]


class BevyStream(AlignedStream):
    """AFF4 stream implementation for bevy stored ``ImageStream`` objects."""

    _ENTRY = struct.Struct("<QI")

    def __init__(self, stream: ImageStream):
        self.stream = stream
        self.segment = self.stream.ctx.aff4.segment(self.stream.stored.id)
        self.path = self.segment.get(self.stream.id)

        self.compression_method = self.stream.compression_method

        self._open_bevy = lru_cache(maxsize=8)(self._open_bevy)
        self._read_chunk = lru_cache(maxsize=512)(self._read_chunk)

        super().__init__(self.stream.size, self.stream.chunk_size)

    def _open_bevy(self, bevy_idx: int) -> tuple[BinaryIO, list[tuple[int, int]]]:
        bevy_path = self.path.joinpath(f"{bevy_idx:08d}")
        index_path = self.path.joinpath(f"{bevy_idx:08d}.index")

        if not bevy_path.exists() or not index_path.exists():
            raise ValueError(f"Bevy {bevy_idx} does not exist for stream {self.stream.id}")

        index = []
        with index_path.open("rb") as fh:
            while buf := fh.read(self._ENTRY.size):
                index.append(self._ENTRY.unpack(buf))

        return bevy_path.open("rb"), index

    def _read_chunk(self, bevy_idx: int, chunk_idx: int) -> bytes:
        bevy_idx = chunk_idx // self.stream.chunks_in_segment
        bevy_fh, index = self._open_bevy(bevy_idx)

        offset, size = index[chunk_idx % self.stream.chunks_in_segment]
        bevy_fh.seek(offset)
        buf = bevy_fh.read(size)

        if size == self.stream.chunk_size:
            return buf

        if self.compression_method == CompressionMethod.ZLIB:
            return zlib.decompress(buf)

        if self.compression_method == CompressionMethod.DEFLATE:
            return zlib.decompress(buf, -zlib.MAX_WBITS)

        if self.compression_method == CompressionMethod.LZ4:
            return lz4.decompress(buf)

        if self.compression_method in (CompressionMethod.SNAPPY, CompressionMethod.SNAPPY2):
            return snappy.decompress(buf)

        raise ValueError(f"Unsupported compression method {self.compression_method} for stream {self.stream.id}")

    def _read(self, offset: int, length: int) -> bytes:
        result = []

        chunk_idx, offset_in_chunk = divmod(offset, self.stream.chunk_size)

        while length > 0:
            chunk = self._read_chunk(chunk_idx, chunk_idx)
            read_size = min(length, self.stream.chunk_size - offset_in_chunk)

            result.append(chunk[offset_in_chunk : offset_in_chunk + read_size])

            offset += read_size
            length -= read_size
            chunk_idx += 1
            offset_in_chunk = 0

        return b"".join(result)
