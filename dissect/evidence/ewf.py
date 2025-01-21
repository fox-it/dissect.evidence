from __future__ import annotations

import logging
import os
import zlib
from bisect import bisect_right
from functools import lru_cache
from pathlib import Path
from typing import BinaryIO

from dissect.cstruct import cstruct
from dissect.util.stream import AlignedStream

from dissect.evidence.exceptions import EWFError

log = logging.getLogger(__name__)
log.setLevel(os.getenv("DISSECT_LOG_EWF", "CRITICAL"))

ewf_def = """
enum MediaType : uint8 {
    Removable   = 0x00,
    Fixed       = 0x01,
    Optical     = 0x03,
    Logical     = 0x0e,
    RAM         = 0x10
};

enum MediaFlags : uint8 {
    Image       = 0x01,
    Physical    = 0x02,
    Fastbloc    = 0x04,
    Tablaeu     = 0x08
};

enum CompressionLevel : uint8 {
    None        = 0x00,
    Good        = 0x01,
    Best        = 0x02
};

typedef struct {
    char        signature[8];
    uint8       fields_start;
    uint16      segment_number;
    uint16      fields_end;
} EWFHeader;

typedef struct {
    char    type[16];
    uint64  next;
    uint64  size;
    uint8   pad[40];
    uint32  checksum;
} EWFSectionDescriptor;

typedef struct {
    uint32  reserved_1;
    uint32  chunk_count;
    uint32  sector_count;
    uint32  sector_size;
    uint32  total_sector_count;
    uint8   reserved[20];
    uint8   pad[45];
    char    signature[5];
    uint32  checksum;
} EWFVolumeSectionSpec;

typedef struct {
    MediaType           media_type;
    uint8               reserved_1[3];
    uint32              chunk_count;
    uint32              sector_count;
    uint32              sector_size;
    uint64              total_sector_count;
    uint32              num_cylinders;
    uint32              num_heads;
    uint32              num_sectors;
    uint8               media_flags;
    uint8               unknown_1[3];
    uint32              palm_start_sector;
    uint32              unknown_2;
    uint32              smart_start_sector;
    CompressionLevel    compression_level;
    uint8               unknown_3[3];
    uint32              error_granularity;
    uint32              unknown_4;
    uint8               uuid[16];
    uint8               pad[963];
    char                signature[5];
    uint32              checksum;
} EWFVolumeSection;

typedef struct {
    uint32  num_entries;
    uint32  _;
    uint64  base_offset;
    uint32  _;
    uint32  checksum;
    uint32  entries[num_entries];
} EWFTableSection;
"""

c_ewf = cstruct().load(ewf_def)

MAX_OPEN_SEGMENTS = 128


def find_files(path: str | Path) -> list[Path]:
    """Find all related EWF files from the given path."""
    if not isinstance(path, Path):
        path = Path(path)

    path = path.resolve()
    ext = path.suffix

    if ext[1].upper() not in "ELS":
        raise EWFError(f"Invalid EWF file: {path}")

    ewfglob = f"[{ext[1]}-{'Z' if ext[1].isupper() else 'z'}]" if len(ext) == 4 else f"{ext[1]}[x-z]"

    return sorted(path.parent.glob(f"{path.stem}.{ewfglob}[0-9A-Za-z][0-9A-Za-z]"))


class EWF:
    """Expert Witness Disk Image Format."""

    def __init__(self, fh: BinaryIO | list[BinaryIO]):
        fhs = [fh] if not isinstance(fh, list) else fh

        self.fh = fhs
        self.header: HeaderSection = None
        self.volume: VolumeSection = None
        self._segments: dict[str, Segment] = {}
        self._segment_offsets = []
        self._segment_lru = []

        segment_offset = 0

        for i in range(len(fhs)):
            try:
                segment = self.open_segment(i)
            except Exception:
                log.exception("Failed to parse as EWF file: %s", fh)
                continue

            if segment.header and not self.header:
                self.header = segment.header

            if segment.volume and not self.volume:
                self.volume = segment.volume

            if segment_offset != 0:
                self._segment_offsets.append(segment_offset)

            segment.offset = segment_offset * self.volume.sector_size
            segment.sector_offset = segment_offset
            segment_offset += segment.sector_count

        if not self.header or not self.volume:
            raise EWFError(f"Failed to load EWF: {fh}")

        self.chunk_size = self.volume.sector_count * self.volume.sector_size

        max_size = self.volume.chunk_count * self.volume.sector_count * self.volume.sector_size
        last_table = self.open_segment(len(self.fh) - 1).tables[-1]
        last_chunk_size = len(last_table.read_chunk(last_table.num_entries - 1))

        self.size = max_size - (self.chunk_size - last_chunk_size)

    def open_segment(self, idx: int) -> Segment:
        # Poor mans LRU
        if idx in self._segments:
            self._segment_lru.remove(idx)
            self._segment_lru.append(idx)
            return self._segments[idx]

        if len(self._segment_lru) >= MAX_OPEN_SEGMENTS:
            oldest_idx = self._segment_lru.pop(0)
            oldest_segment = self._segments.pop(oldest_idx)

            # Don't close it if we received it as a file-like object
            if not hasattr(self.fh[oldest_idx], "read"):
                oldest_segment.fh.close()

            del oldest_segment

        fh = self.fh[idx]
        if not hasattr(fh, "read"):
            fh = fh.open("rb") if isinstance(fh, Path) else Path(fh).open("rb")  # noqa: SIM115

        segment = Segment(self, fh)
        if self.volume and 0 < idx <= len(self._segment_offsets):
            # We already have a known segment offset for this segment, so set it back
            segment_offset = self._segment_offsets[idx - 1]
            segment.offset = segment_offset * self.volume.sector_size
            segment.sector_offset = segment_offset
        else:
            # Otherwise we're in the initialization loop (or we're idx == 0)
            segment.offset = 0
            segment.sector_offset = 0

        self._segments[idx] = segment
        self._segment_lru.append(idx)

        return segment

    def open(self) -> BinaryIO:
        return EWFStream(self)


class EWFStream(AlignedStream):
    def __init__(self, ewf: EWF):
        self.ewf = ewf
        self.sector_size = self.ewf.volume.sector_size
        super().__init__(ewf.size)

    def _read(self, offset: int, length: int) -> bytes:
        result = []

        sector_offset = offset // self.sector_size
        sector_count = (length + self.sector_size - 1) // self.sector_size

        segment_idx = bisect_right(self.ewf._segment_offsets, sector_offset)

        while sector_count > 0:
            if segment_idx > len(self.ewf._segment_offsets):
                raise EWFError(f"Missing EWF file for segment index: {segment_idx}")

            segment = self.ewf.open_segment(segment_idx)

            segment_remaining_sectors = segment.sector_count - (sector_offset - segment.sector_offset)
            segment_sectors = min(segment_remaining_sectors, sector_count)

            result.append(segment.read_sectors(sector_offset, segment_sectors))
            sector_offset += segment_sectors
            sector_count -= segment_sectors

            segment_idx += 1

        return b"".join(result)


class Segment:
    def __init__(self, ewf: EWF, fh: BinaryIO):
        self.ewf = ewf
        self.fh = fh

        fh.seek(0)
        self.ewfheader = c_ewf.EWFHeader(fh)
        self.header = ewf.header
        self.volume = ewf.volume

        if self.ewfheader.signature not in (b"EVF\x09\x0d\x0a\xff\x00", b"LVF\x09\x0d\x0a\xff\x00"):
            raise EWFError(f"Invalid signature, got {self.ewfheader.signature!r}")

        self.sections: list[SectionDescriptor] = []
        self.tables: list[TableSection] = []
        self.table_offsets = []

        offset = 0
        sector_offset = 0

        while True:
            section = SectionDescriptor(fh)
            self.sections.append(section)

            if section.type in (b"header", b"header2") and not self.header:
                self.header = HeaderSection(self, section)

            if section.type in (b"disk", b"volume") and not self.volume:
                self.volume = VolumeSection(self, section)

            if section.type == b"table":
                table = TableSection(self, section)

                if sector_offset != 0:
                    self.table_offsets.append(sector_offset)

                table.offset = sector_offset * self.volume.sector_size
                table.sector_offset = sector_offset
                sector_offset += table.sector_count

                self.tables.append(table)

            if section.next == offset or section.type == b"done":
                break

            offset = section.next
            fh.seek(offset)

        self.chunk_count = sum([t.num_entries for t in self.tables])
        self.sector_count = self.chunk_count * self.volume.sector_count
        self.size = self.chunk_count * self.volume.sector_count * self.volume.sector_size
        self.sector_offset = None  # Set later
        self.offset = None  # Set later

    def read_sectors(self, sector: int, count: int) -> bytes:
        log.debug("Segment::read_sectors(0x%x, 0x%x)", sector, count)
        segment_sector = sector - self.sector_offset
        r = []

        table_idx = bisect_right(self.table_offsets, segment_sector)
        while count > 0:
            table = self.tables[table_idx]

            table_remaining_sectors = table.sector_count - (segment_sector - table.sector_offset)
            table_sectors = min(table_remaining_sectors, count)

            r.append(table.read_sectors(segment_sector, table_sectors))
            segment_sector += table_sectors
            count -= table_sectors

            table_idx += 1

        return b"".join(r)


class HeaderSection:
    def __init__(self, segment: Segment, section: SectionDescriptor):
        self.segment = segment
        self.section = section

        fh = segment.fh
        fh.seek(section.data_offset)
        self.data = zlib.decompress(fh.read(section.size))

        if self.data[0] in (b"\xff", b"\xfe"):
            self.data = self.data.decode("utf16")

    def __repr__(self) -> str:
        return f"<HeaderSection categories={int(self.data[0])}>"


class VolumeSection:
    def __init__(self, segment: Segment, section: SectionDescriptor):
        self.segment = segment
        self.section = section

        fh = segment.fh
        fh.seek(section.data_offset)
        data = c_ewf.EWFVolumeSection(fh) if section.size == 1052 else c_ewf.EWFVolumeSectionSpec(fh)

        self.volume = data
        self.chunk_count = data.chunk_count
        self.sector_count = data.sector_count
        self.sector_size = data.sector_size


class TableSection:
    def __init__(self, segment: Segment, section: SectionDescriptor):
        self.segment = segment
        self.section = section

        fh = segment.fh
        fh.seek(section.data_offset)

        self.header = c_ewf.EWFTableSection(fh)
        self.num_entries = self.header.num_entries
        self.base_offset = self.header.base_offset
        self.entries = self.header.entries

        self.sector_count = self.num_entries * self.segment.volume.sector_count
        self.size = self.sector_count * self.segment.volume.sector_size
        self.sector_offset = None  # Set later
        self.offset = None  # Set later

        self.read_chunk = lru_cache(1024)(self.read_chunk)

    def read_chunk(self, chunk: int) -> bytes:
        log.debug("TableSection::read_chunk(0x%x)", chunk)

        chunk_entry = self.entries[chunk]
        chunk_offset = self.base_offset + (chunk_entry & 0x7FFFFFFF)
        compressed = chunk_entry >> 31 == 1

        # EWF sucks
        # We don't know the chunk size, so try to determine it using the offset of the next chunk
        # When it's the last chunk in the table though, this becomes trickier.
        # We have to check if the chunk data is preceding the table, or if it's contained within the table section
        # Then we can calculate the chunk size using these offsets
        if chunk + 1 == self.num_entries:
            # The chunk data is stored before the table section
            if chunk_offset < self.section.offset:
                chunk_size = self.section.offset - chunk_offset
            # The chunk data is stored within the table section
            elif chunk_offset < self.section.offset + self.section.size:
                chunk_size = self.section.offset + self.section.size - chunk_offset
            else:
                raise EWFError("Unknown size of last chunk")
        else:
            chunk_size = self.base_offset + (self.entries[chunk + 1] & 0x7FFFFFFF) - chunk_offset

        # Non compressed chunks have a 4 byte checksum
        if not compressed:
            chunk_size -= 4

        self.segment.fh.seek(chunk_offset)
        buf = self.segment.fh.read(chunk_size)

        if compressed:
            buf = zlib.decompress(buf)

        return buf

    def read_sectors(self, sector: int, count: int) -> bytes:
        log.debug("TableSection::read_sectors(0x%x, 0x%x)", sector, count)
        result = []

        chunk_sector_count = self.segment.volume.sector_count
        sector_size = self.segment.volume.sector_size

        table_sector = sector - self.sector_offset
        table_chunk = table_sector // chunk_sector_count

        while count > 0:
            table_sector_offset = table_sector % chunk_sector_count
            chunk_remaining_sectors = chunk_sector_count - table_sector_offset
            table_sectors = min(chunk_remaining_sectors, count)

            chunk_pos = table_sector_offset * sector_size
            chunk_end = chunk_pos + (table_sectors * sector_size)

            buf = self.read_chunk(table_chunk)
            if chunk_pos != 0 or table_sectors != chunk_sector_count:
                buf = buf[chunk_pos:chunk_end]
            result.append(buf)

            count -= table_sectors
            table_sector += table_sectors
            table_chunk += 1

        return b"".join(result)


class SectionDescriptor:
    def __init__(self, fh: BinaryIO):
        self.fh = fh

        self.offset = fh.tell()
        descriptor = c_ewf.EWFSectionDescriptor(fh)
        self.type = descriptor.type.rstrip(b"\x00")
        self.next = descriptor.next
        self.size = descriptor.size - len(c_ewf.EWFSectionDescriptor)
        self.checksum = descriptor.checksum
        self.data_offset = fh.tell()

    def __repr__(self) -> str:
        return (
            f"<SectionDescriptor "
            f"type={self.type} size={self.size:#x} offset={self.offset:#x} checksum={self.checksum:#x}>"
        )
