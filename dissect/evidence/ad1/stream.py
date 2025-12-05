from __future__ import annotations

import zlib
from bisect import bisect_right
from typing import TYPE_CHECKING

from dissect.util.stream import AlignedStream

from dissect.evidence.ad1.c_ad1 import c_ad1

if TYPE_CHECKING:
    from dissect.evidence.ad1.ad1 import AD1, FileEntry


class AD1Stream(AlignedStream):
    """Provide a stitched stream over all AD1 segments."""

    def __init__(self, ad1: AD1):
        self.ad1 = ad1
        super().__init__(self.ad1.size)

    def _read(self, offset: int, length: int) -> bytes:
        result = []

        idx = bisect_right(self.ad1._segment_offsets, offset)
        while length > 0:
            if idx > len(self.ad1._segment_offsets) - 1:
                break

            segment = self.ad1.segment(idx)
            segment_offset = 0 if idx == 0 else self.ad1._segment_offsets[idx - 1]
            offset_in_segment = offset - segment_offset
            read_size = min(length, segment.size - offset_in_segment)

            segment.fh.seek(512 + offset_in_segment)  # Skip segment header
            result.append(segment.fh.read(read_size))

            offset += read_size
            length -= read_size
            idx += 1

        return b"".join(result)


class FileStream(AlignedStream):
    """Custom stream implementation for AD1 :class:`FileEntry` file contents."""

    def __init__(self, entry: FileEntry):
        self.entry = entry
        self.stream = self.entry.ad1.stream
        self.chunk_size = self.entry.ad1.logical_image.chunk_size

        self.stream.seek(self.entry.entry.zlib_meta)
        self.chunks = [*c_ad1.FileEntryChunks(self.stream).chunks, self.entry.entry.meta]

        super().__init__(self.entry.size, self.chunk_size)

    def _read(self, offset: int, length: int) -> bytes:
        result = []

        chunk, offset_in_chunk = divmod(offset, self.chunk_size)
        chunk_count = (length + self.chunk_size - 1) // self.chunk_size
        chunk_offsets = self.chunks[chunk : chunk + chunk_count + 1]

        for i, chunk_offset in enumerate(chunk_offsets[:-1]):
            compressed_chunk_size = chunk_offsets[i + 1] - chunk_offset

            self.stream.seek(chunk_offset)
            buf = zlib.decompress(self.stream.read(compressed_chunk_size))

            read_size = min(length, self.chunk_size - offset_in_chunk)
            result.append(buf[offset_in_chunk : offset_in_chunk + read_size])

            offset += read_size
            length -= read_size
            offset_in_chunk = 0

        return b"".join(result)
