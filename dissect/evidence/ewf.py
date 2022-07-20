from __future__ import print_function

import os
import zlib
import logging
from pathlib import Path
from bisect import bisect_right
from functools import lru_cache

from dissect import cstruct
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
    uint32  pad;
    uint64  base_offset;
    uint32  pad;
    uint32  checksum;
    uint32  entries[num_entries];
} EWFTableSection;
"""

c_ewf = cstruct.cstruct()
c_ewf.load(ewf_def)


def find_files(path):
    """
    Finds EWF files in the given path and returns a sorted list of the files.
    It used outside the module, in dissect.target containers
    """
    if not isinstance(path, Path):
        path = Path(path)

    path = path.resolve()
    ext = path.suffix

    if ext[1].upper() not in "ELS":
        raise EWFError(f"Invalid EWF file: {path}")

    if len(ext) == 4:
        ewfglob = f"[{ext[1]}-{'Z' if ext[1].isupper() else 'z'}]"
    else:
        ewfglob = f"{ext[1]}[x-z]"

    return sorted(path.parent.glob(f"{path.stem}.{ewfglob}[0-9A-Za-z][0-9A-Za-z]"))


class EWF(AlignedStream):
    """Expert Witness disk image Format"""

    def __init__(self, fh):
        fhs = [fh] if not isinstance(fh, list) else fh

        self.segments = []
        self.segment_offsets = []
        self.header = None
        self.volume = None

        segment_offset = 0

        for fh in fhs:
            try:
                segment = EWFSegment(fh, self)
            except Exception:
                log.exception("Failed to parse as EWF file: %s", fh)
                continue

            if segment.header and not self.header:
                self.header = segment.header

            if segment.volume and not self.volume:
                self.volume = segment.volume

            if segment_offset != 0:
                self.segment_offsets.append(segment_offset)

            segment.offset = segment_offset * self.volume.sector_size
            segment.sector_offset = segment_offset
            segment_offset += segment.sector_count

            self.segments.append(segment)

        if not self.header or not self.volume or not self.segments:
            raise EWFError(f"Failed to load EWF: {fh}")

        self.chunk_size = self.volume.sector_count * self.volume.sector_size

        max_size = self.volume.chunk_count * self.volume.sector_count * self.volume.sector_size
        last_table = self.segments[-1].tables[-1]
        last_chunk_size = len(last_table.read_chunk(last_table.header.num_entries - 1))

        self.size = max_size - (self.chunk_size - last_chunk_size)
        super().__init__(self.size)

    def read_sectors(self, sector, count):
        log.debug("EWF::read_sectors(0x%x, 0x%x)", sector, count)
        r = []

        segment_idx = bisect_right(self.segment_offsets, sector)
        while count > 0:
            segment = self.segments[segment_idx]

            segment_remaining_sectors = segment.sector_count - (sector - segment.sector_offset)
            segment_sectors = min(segment_remaining_sectors, count)

            r.append(segment.read_sectors(sector, segment_sectors))
            sector += segment_sectors
            count -= segment_sectors

            segment_idx += 1

        return b"".join(r)

    def _read(self, offset, length):
        log.debug("EWF::read(0x%x, 0x%x)", offset, length)
        sector_offset = offset // self.volume.sector_size
        sector_count = (length + self.volume.sector_size - 1) // self.volume.sector_size

        return self.read_sectors(sector_offset, sector_count)


class EWFSegment:
    def __init__(self, fh, ewf):
        self.fh = fh
        self.ewf = ewf
        self.ewfheader = c_ewf.EWFHeader(fh)
        self.header = ewf.header
        self.volume = ewf.volume

        if self.ewfheader.signature not in (b"EVF\x09\x0d\x0a\xff\x00", b"LVF\x09\x0d\x0a\xff\x00"):
            raise EWFError(f"Invalid signature, got {self.ewfheader.signature!r}")

        self.sections = []
        self.tables = []
        self.table_offsets = []

        offset = 0
        sector_offset = 0

        while True:
            section = EWFSectionDescriptor(fh, self)
            self.sections.append(section)

            if section.type in (b"header", b"header2") and not self.header:
                self.header = EWFHeaderSection(fh, section, self)

            if section.type in (b"disk", b"volume") and not self.volume:
                self.volume = EWFVolumeSection(fh, section, self)

            if section.type == b"table":
                table = EWFTableSection(fh, section, self)

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
        self.sector_offset = None
        self.size = self.chunk_count * self.volume.sector_count * self.volume.sector_size
        self.offset = None

    def read_sectors(self, sector, count):
        log.debug("EWFSegment::read_sectors(0x%x, 0x%x)", sector, count)
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


class EWFHeaderSection:
    def __init__(self, fh, section, segment):
        fh.seek(section.data_offset)
        self.data = zlib.decompress(fh.read(section.size))

        if self.data[0] in (b"\xff", b"\xfe"):
            self.data = self.data.decode("utf16")

    def __repr__(self):
        return f"<EWFHeader categories={int(self.data[0])}>"


class EWFVolumeSection:
    def __init__(self, fh, section, segment):
        fh.seek(section.data_offset)
        if section.size == 0x41C:
            data = c_ewf.EWFVolumeSection(fh)
        else:
            data = c_ewf.EWFVolumeSectionSpec(fh)

        self.volume = data

    def __getattr__(self, k):
        if k in self.volume:
            return getattr(self.volume, k)

        return object.__getattribute__(self, k)


class EWFTableSection:
    def __init__(self, fh, section, segment):
        fh.seek(section.data_offset)
        self.fh = fh
        self.section = section
        self.segment = segment
        self.header = c_ewf.EWFTableSection(fh)
        self.base_offset = self.header.base_offset

        self.sector_count = self.header.num_entries * segment.volume.sector_count
        self.sector_offset = None
        self.size = self.sector_count * segment.volume.sector_size
        self.offset = None

    def __getattr__(self, k):
        if hasattr(self.header, k):
            return getattr(self.header, k)

        return object.__getattribute__(self, k)

    @lru_cache(1024)
    def read_chunk(self, chunk):
        log.debug("EWFTableSection::read_chunk(0x%x)", chunk)

        chunk_entry = self.header.entries[chunk]
        chunk_offset = self.base_offset + (chunk_entry & 0x7FFFFFFF)
        compressed = chunk_entry >> 31 == 1

        # EWF sucks
        # We don't know the chunk size, so try to determine it using the offset of the next chunk
        # When it's the last chunk in the table though, this becomes trickier.
        # We have to check if the chunk data is preceding the table, or if it's contained within the table section
        # Then we can calculate the chunk size using these offsets
        if chunk + 1 == self.header.num_entries:
            # The chunk data is stored before the table section
            if chunk_offset < self.section.offset:
                chunk_size = self.section.offset - chunk_offset
            # The chunk data is stored within the table section
            elif chunk_offset < self.section.offset + self.section.size:
                chunk_size = self.section.offset + self.section.size - chunk_offset
            else:
                raise EWFError("Unknown size of last chunk")
        else:
            chunk_size = self.base_offset + (self.header.entries[chunk + 1] & 0x7FFFFFFF) - chunk_offset

        # Non compressed chunks have a 4 byte checksum
        if not compressed:
            chunk_size -= 4

        self.fh.seek(chunk_offset)
        buf = self.fh.read(chunk_size)

        if compressed:
            buf = zlib.decompress(buf)

        return buf

    def read_sectors(self, sector, count):
        log.debug("EWFTableSection::read_sectors(0x%x, 0x%x)", sector, count)
        r = []

        chunk_sector_count = self.segment.ewf.volume.sector_count
        sector_size = self.segment.ewf.volume.sector_size

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
            r.append(buf)

            count -= table_sectors
            table_sector += table_sectors
            table_chunk += 1

        return b"".join(r)


class EWFSectionDescriptor:
    def __init__(self, fh, segment):
        self.fh = fh
        self.segment = segment

        self.offset = fh.tell()
        descriptor = c_ewf.EWFSectionDescriptor(fh)
        self.type = descriptor.type.rstrip(b"\x00")
        self.next = descriptor.next
        self.size = descriptor.size - 0x4C
        self.checksum = descriptor.checksum
        self.data_offset = fh.tell()

    def __repr__(self):
        return (
            f"<EWFSection type={self.type} size=0x{self.size:x} "
            f"offset=0x{self.offset:x} checksum=0x{self.checksum:x}>"
        )
