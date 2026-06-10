from __future__ import annotations

import codecs
import zlib
from bisect import bisect_right
from functools import cached_property, lru_cache
from pathlib import Path
from typing import TYPE_CHECKING, BinaryIO

from dissect.evidence.adcrypt.adcrypt import ADCrypt, is_adcrypt
from dissect.evidence.ewf import c_ewf
from dissect.evidence.ewf.stream import EWFStream

if TYPE_CHECKING:
    from types import TracebackType

    from typing_extensions import Self

MAX_OPEN_SEGMENTS = 128


def find_files(path: str | Path) -> list[Path]:
    """Find all related EWF files from the given path."""
    if not isinstance(path, Path):
        path = Path(path)

    path = path.resolve()
    ext = path.suffix

    if ext[1].upper() not in "ELS":
        raise ValueError(f"Invalid EWF file: {path}")

    ewfglob = f"[{ext[1]}-{'Z' if ext[1].isupper() else 'z'}]" if len(ext) == 4 else f"{ext[1]}[x-z]"

    return sorted(path.parent.glob(f"{path.stem}.{ewfglob}[0-9A-Za-z][0-9A-Za-z]"))


class EWF:
    """Expert Witness Disk Image Format.

    Args:
        fh: A file handle, list of file handles, path or list of paths to the EWF segment files.
            If a path is provided, all related segment files will be automatically discovered.
    """

    def __init__(self, fh: BinaryIO | list[BinaryIO] | Path | list[Path]):
        fhs = find_files(fh) if isinstance(fh, Path) else [fh] if not isinstance(fh, list) else fh

        self.fh = fhs
        self.header: HeaderSection | None = None
        self.volume: VolumeSection | None = None

        self.chunk_size = 0
        self.size = 0

        self._segments: dict[int, Segment] = {}
        self._segment_lru: list[int] = []

        self._chunk_lookup: list[int] = []
        self._chunk_map: list[tuple[int, int]] = []

        if not self.fh:
            raise ValueError("No segment files provided for EWF container")

        self.adcrypt = None

        first_segment = self.segment(0)
        if is_adcrypt(first_segment.fh):
            self.adcrypt = ADCrypt(first_segment.fh)
        else:
            self._open_ewf()

        self.read_chunk = lru_cache(128)(self.read_chunk)

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self, exc_type: type[BaseException] | None, exc_value: BaseException | None, traceback: TracebackType | None
    ) -> None:
        self.close()

    def is_adcrypt(self) -> bool:
        """Return whether the EWF container is ADCRYPT encrypted."""
        return self.adcrypt is not None

    def is_locked(self) -> bool:
        """Return whether the ADCRYPT container is locked."""
        return self.is_adcrypt() and self.adcrypt.is_locked()

    def segment(self, idx: int) -> Segment:
        """Open a segment by index.

        Implements a simple LRU cache to limit the number of open segments.

        Args:
            idx: Index of the segment to open.
        """
        # Poor mans LRU
        if idx in self._segments:
            self._segment_lru.remove(idx)
            self._segment_lru.append(idx)
            return self._segments[idx]

        if len(self._segment_lru) >= MAX_OPEN_SEGMENTS:
            oldest_idx = self._segment_lru.pop(0)
            oldest_segment = self._segments.pop(oldest_idx)

            # Only close file handles that we opened ourselves
            if isinstance(self.fh[oldest_idx], Path):
                oldest_segment.fh.close()

            del oldest_segment

        fh = self.fh[idx]
        if isinstance(fh, Path):
            fh = fh.open("rb")

        if self.is_adcrypt() and not self.is_locked():
            fh = self.adcrypt.wrap(fh, idx)

        segment = Segment(fh)
        self._segments[idx] = segment
        self._segment_lru.append(idx)

        return segment

    def unlock(self, *, passphrase: str | bytes | None = None, private_key: Path | bytes | None = None) -> None:
        """Unlock the ADCRYPT container with a given passphrase or private key.

        Args:
            passphrase: The passphrase to unlock the container.
            private_key: The private key to unlock the container.

        Raises:
            RuntimeError: If required dependencies are missing.
            ValueError: If unlocking failed.
        """
        self.adcrypt.unlock(passphrase=passphrase, private_key=private_key)

        # Reset LRU
        self._segments = {}
        self._segment_lru = []

        # Open the EWF
        self._open_ewf()

    def _open_ewf(self) -> None:
        """Open the EWF container and initialize the volume and chunk information."""
        self.volume = None

        chunk = 0
        for i in range(len(self.fh)):
            segment = self.segment(i)
            if segment.header.signature not in (b"EVF\x09\x0d\x0a\xff\x00", b"LVF\x09\x0d\x0a\xff\x00"):
                raise ValueError(f"Invalid EWF signature in segment {i}, got {segment.header.signature!r}")

            if segment.number != i + 1:
                raise ValueError(f"Invalid EWF segment number in segment {i}, got {segment.number}, expected {i + 1}")

            if not self.volume and segment.volume:
                self.volume = segment.volume
                self.chunk_size = self.volume.sectors_per_chunk * self.volume.sector_size
            elif not self.volume and not segment.volume:
                raise ValueError("Missing expected volume section in first segment")

            for j, table in enumerate(segment.tables):
                chunk += table.number_of_entries
                self._chunk_lookup.append(chunk)
                self._chunk_map.append((i, j))

        max_size = self.volume.number_of_chunks * self.chunk_size
        last_chunk = self.read_chunk(self.volume.number_of_chunks - 1)

        self.size = max_size - (self.chunk_size - len(last_chunk))

    def read_chunk(self, chunk: int) -> bytes:
        """Read a chunk of data from the EWF container.

        Args:
            chunk: The chunk index to read.
        """
        lookup_idx = bisect_right(self._chunk_lookup, chunk)
        if lookup_idx >= len(self._chunk_map):
            raise IndexError(f"Chunk {chunk} out of range")

        segment_idx, table_idx = self._chunk_map[lookup_idx]

        segment = self.segment(segment_idx)
        table = segment.tables[table_idx]

        chunk_offset = 0 if lookup_idx == 0 else self._chunk_lookup[lookup_idx - 1]
        relative_chunk = chunk - chunk_offset

        entry = table.entries[relative_chunk]
        offset_of_chunk = table.base_offset + (entry & 0x7FFFFFFF)
        compressed = entry >> 31 == 1

        # We don't know the chunk size, so try to determine it using the offset of the next chunk
        # When it's the last chunk in the table though, this becomes trickier
        # We have to check if the chunk data is preceding the table, or if it's contained within the table section
        if relative_chunk == table.number_of_entries - 1:
            # The chunk data is stored before the table section (probably in a sectors section)
            if offset_of_chunk < table.descriptor.offset:
                end_of_chunk = table.descriptor.offset

            # The chunk data is stored within the table section
            elif offset_of_chunk < table.descriptor.offset + table.descriptor.raw_size:
                end_of_chunk = table.descriptor.offset + table.descriptor.raw_size

            else:
                raise ValueError("Unknown size of last chunk")
        else:
            end_of_chunk = table.base_offset + (table.entries[relative_chunk + 1] & 0x7FFFFFFF)

        size_of_chunk = end_of_chunk - offset_of_chunk

        # Uncompressed chunks have a 4 byte checksum at the end
        if not compressed:
            size_of_chunk -= 4

        segment.fh.seek(offset_of_chunk)
        buf = segment.fh.read(size_of_chunk)
        if compressed:
            buf = zlib.decompress(buf)

        return buf

    def open(self) -> BinaryIO:
        """Open a stream to read the EWF container contents."""
        if self.is_locked():
            raise ValueError("EWF container is locked by ADCRYPT")

        return EWFStream(self)

    def close(self) -> None:
        """Close all segment file handles that we opened ourselves and clear the segment cache."""
        for idx, segment in self._segments.items():
            if isinstance(self.fh[idx], Path):
                segment.fh.close()

        self._segments = {}
        self._segment_lru = []


class Segment:
    """EWF segment."""

    def __init__(self, fh: BinaryIO):
        self.fh = fh

        self.fh.seek(0)
        self.header = c_ewf.SegmentHeader(fh)
        self.number = self.header.segment_number

    @cached_property
    def sections(self) -> list[Section]:
        """Return all sections in this segment."""
        result = []

        offset = len(c_ewf.SegmentHeader)
        while True:
            self.fh.seek(offset)
            section = Section.from_fh(self.fh)
            result.append(section)

            if section.descriptor.next == offset or section.descriptor.type == b"done":
                break

            offset = section.descriptor.next

        return result

    @cached_property
    def headers(self) -> list[HeaderSection]:
        """Return all header sections in this segment."""
        return [section for section in self.sections if isinstance(section, HeaderSection)]

    @cached_property
    def tables(self) -> list[TableSection]:
        """Return all table sections in this segment."""
        return [section for section in self.sections if type(section) is TableSection]  # Ignore Table2Section

    @cached_property
    def volume(self) -> VolumeSection | None:
        """Return the volume section in this segment, if present."""
        for section in self.sections:
            if isinstance(section, VolumeSection):
                return section
        return None


class SectionDescriptor:
    """EWF section descriptor."""

    def __init__(self, fh: BinaryIO):
        self.fh = fh

        self.offset = fh.tell()
        self.descriptor = c_ewf.SectionDescriptor(fh)

    def __repr__(self) -> str:
        return (
            f"<SectionDescriptor "
            f"type={self.type!r} size={self.size:#x} offset={self.offset:#x} checksum={self.checksum:#x}>"
        )

    @property
    def type(self) -> str:
        """The type of the section."""
        return self.descriptor.type.rstrip(b"\x00").decode()

    @property
    def next(self) -> int:
        """The offset of the next section."""
        return self.descriptor.next

    @property
    def raw_size(self) -> int:
        """The raw size of the section, including the descriptor."""
        return self.descriptor.size

    @property
    def size(self) -> int:
        """The size of the section data."""
        return (self.descriptor.size - len(c_ewf.SectionDescriptor)) if self.descriptor.size else 0

    @property
    def data(self) -> bytes:
        """The raw data of the section."""
        self.fh.seek(self.offset + len(c_ewf.SectionDescriptor))
        return self.fh.read(self.size)

    @property
    def checksum(self) -> int:
        """The checksum of the section data."""
        return self.descriptor.checksum


class Section:
    """EWF section."""

    def __init__(self, descriptor: SectionDescriptor):
        self.descriptor = descriptor

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} type={self.descriptor.type!r} size={self.descriptor.size:#x}>"

    @classmethod
    def from_fh(
        cls, fh: BinaryIO
    ) -> Section | HeaderSection | VolumeSection | DataSection | TableSection | Table2Section | HashSection:
        """Open a section from a file-like object."""
        descriptor = SectionDescriptor(fh)

        if descriptor.type in ("header", "header2"):
            return HeaderSection(descriptor)

        if descriptor.type in ("disk", "volume"):
            return VolumeSection(descriptor)

        if descriptor.type == "data":
            return DataSection(descriptor)

        if descriptor.type == "table":
            return TableSection(descriptor)

        if descriptor.type == "table2":
            return Table2Section(descriptor)

        if descriptor.type == "hash":
            return HashSection(descriptor)

        return Section(descriptor)

    @property
    def type(self) -> str:
        """The type of the section."""
        return self.descriptor.type

    @cached_property
    def data(self) -> bytes:
        """The raw data of the section."""
        return self.descriptor.data


class HeaderSection(Section):
    """EWF header section."""

    @cached_property
    def data(self) -> str:
        """The header data."""
        data = zlib.decompress(self.descriptor.data)
        return data.decode("utf16") if data[:2] in (codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE) else data.decode()


class VolumeSection(Section):
    """EWF volume section."""

    @cached_property
    def data(self) -> c_ewf.VolumeSection | c_ewf.VolumeSectionSmart:
        """The volume data."""
        return (c_ewf.VolumeSection if self.descriptor.size == len(c_ewf.VolumeSection) else c_ewf.VolumeSectionSmart)(
            self.descriptor.data
        )

    @property
    def number_of_chunks(self) -> int:
        """The number of chunks in the volume."""
        return self.data.number_of_chunks

    @property
    def sectors_per_chunk(self) -> int:
        """The number of sectors per chunk."""
        return self.data.sectors_per_chunk

    @property
    def sector_size(self) -> int:
        """The size of a sector in bytes."""
        return self.data.bytes_per_sector


class DataSection(Section):
    """EWF data section."""

    @cached_property
    def data(self) -> c_ewf.DataSection:
        """The data section."""
        return c_ewf.DataSection(self.descriptor.data)


class TableSection(Section):
    """EWF table section."""

    def __repr__(self) -> str:
        return (
            f"<{self.__class__.__name__} "
            f"type={self.descriptor.type!r} size={self.descriptor.size:#x} "
            f"number_of_entries={self.number_of_entries} base_offset={self.base_offset:#x}>"
        )

    @cached_property
    def data(self) -> c_ewf.TableSection:
        """The table section."""
        self.descriptor.fh.seek(self.descriptor.offset + len(c_ewf.SectionDescriptor))
        return c_ewf.TableSection(self.descriptor.fh)

    @cached_property
    def entries(self) -> list[int]:
        """The table entries."""
        self.descriptor.fh.seek(self.descriptor.offset + len(c_ewf.SectionDescriptor) + len(c_ewf.TableSection))
        return c_ewf.uint32[self.number_of_entries](self.descriptor.fh)

    @property
    def number_of_entries(self) -> int:
        """The number of entries in the table."""
        return self.data.number_of_entries

    @property
    def base_offset(self) -> int:
        """The base offset of the table."""
        return self.data.base_offset


class Table2Section(TableSection):
    """EWF table2 section."""


class HashSection(Section):
    """EWF hash section."""

    @cached_property
    def data(self) -> c_ewf.HashSection:
        """The hash section."""
        return c_ewf.HashSection(self.descriptor.data)

    @property
    def md5(self) -> str:
        """The MD5 hash of the section."""
        return self.data.md5.hex()
