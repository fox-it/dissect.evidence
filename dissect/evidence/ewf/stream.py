from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.util.stream import AlignedStream

if TYPE_CHECKING:
    from dissect.evidence.ewf.ewf import EWF


class EWFStream(AlignedStream):
    """Provide a stitched stream over all EWF segments."""

    def __init__(self, ewf: EWF):
        self.ewf = ewf
        super().__init__(ewf.size, ewf.chunk_size)

    def _read(self, offset: int, length: int) -> bytes:
        result = []

        chunk, offset_in_chunk = divmod(offset, self.ewf.chunk_size)

        while length > 0:
            buf = self.ewf.read_chunk(chunk)
            read_size = min(length, self.ewf.chunk_size - offset_in_chunk)
            result.append(buf[offset_in_chunk : offset_in_chunk + read_size])

            offset_in_chunk = 0
            offset += read_size
            length -= read_size
            chunk += 1

        return b"".join(result)
