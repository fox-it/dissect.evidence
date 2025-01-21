# Acquire Snapshot Data Format

from __future__ import annotations

import gzip
import io
import shutil
import tarfile
import uuid
from bisect import bisect_right
from collections import defaultdict
from typing import TYPE_CHECKING, BinaryIO, Callable

from dissect.cstruct import cstruct
from dissect.util import ts
from dissect.util.stream import AlignedStream, RangeStream

from dissect.evidence.asdf.streams import CompressedStream, Crc32Stream, HashedStream
from dissect.evidence.exceptions import (
    InvalidBlock,
    InvalidSnapshot,
    UnsupportedVersion,
)

if TYPE_CHECKING:
    from collections.abc import Iterator

SnapshotTableEntry = tuple[int, int, int, int]

VERSION = 1
DEFAULT_BLOCK_SIZE = 4096
MAX_BLOCK_TABLE_SIZE = 2**32

MAX_IDX = 253
IDX_MEMORY = 254
IDX_METADATA = 255
RESERVED_IDX = [IDX_METADATA, IDX_MEMORY]

FILE_MAGIC = b"ASDF"
BLOCK_MAGIC = b"BL\xa5\xdf"
FOOTER_MAGIC = b"FT\xa5\xdf"
SPARSE_BYTES = b"\xa5\xdf"

asdf_def = """
flag FILE_FLAG : uint32 {
    SHA256      = 0x01,
};

flag BLOCK_FLAG : uint8 {
    CRC32       = 0x01,
    COMPRESS    = 0x02,
};

struct header {
    char        magic[4];       // File magic, must be "ASDF"
    FILE_FLAG   flags;          // File flags
    uint8       version;        // File version
    char        reserved1[7];   // Reserved
    uint64      timestamp;      // Creation timestamp of the file
    char        reserved2[8];   // Reserved
    char        guid[16];       // GUID, should be unique per writer
};

struct block {
    char        magic[4];       // Block magic, must be "BL\\xa5\\xdf"
    BLOCK_FLAG  flags;          // Block flags
    uint8       idx;            // Stream index, some reserved values have special meaning
    char        reserved[2];    // Reserved
    uint64      offset;         // Absolute offset of block in stream
    uint64      size;           // Size of block in stream
};

struct table_entry {
    BLOCK_FLAG  flags;          // Block flags
    uint8       idx;            // Stream index, some reserved values have special meaning
    char        reserved[2];    // Reserved
    uint64      offset;         // Absolute offset of block in stream
    uint64      size;           // Size of block in stream
    uint64      file_offset;    // Absolute offset of block in file
    uint64      file_size;      // Size of block in file
};

struct footer {
    char        magic[4];       // Footer magic, must be "FT\\xa5\\xdf"
    char        reserved[4];    // Reserved
    uint64      table_offset;   // Offset in file to start of block table
    char        sha256[32];     // SHA256 of this file up until this hash
};
"""
c_asdf = cstruct().load(asdf_def)


class AsdfWriter(io.RawIOBase):
    """ASDF file writer.

    Current limitations:
        - Maximum source disk size is ~16EiB
        - Maximum number of disks is 254

    Some things are currently hardcoded (like SHA256), although they may
    become variable in the future.

    Args:
        fh: File-like object to write to.
        guid: Unique identifier. Used to link images to writers.
        compress: Write gzip compressed file.
        block_crc: Flag to store a CRC32 after each block.
    """

    def __init__(
        self,
        fh: BinaryIO,
        guid: uuid.UUID | None = None,
        compress: bool = False,
        block_crc: bool = True,
    ):
        self._fh = fh
        self.fh = self._fh

        if compress:
            self.fh = gzip.GzipFile(fileobj=self.fh, mode="wb")

        self.fh = HashedStream(self.fh)
        self.guid = guid or uuid.uuid4()

        # Options
        self.block_crc = block_crc
        self.block_compress = False  # Disabled for now

        self._table = defaultdict(list)
        self._table_lookup = defaultdict(list)
        self._table_offset = 0

        self._meta_buf = io.BytesIO()
        self._meta_tar = tarfile.open(fileobj=self._meta_buf, mode="w")  # noqa: SIM115

        self._write_header()

    def add_metadata_file(self, path: str, fh: BinaryIO, size: int | None = None) -> None:
        """Add a file to the metadata stream.

        Args:
            path: The path in the metadata tar to write to.
            fh: The file-like object to write.
            size: Optional size to write.
        """
        info = self._meta_tar.tarinfo()
        info.name = path
        info.uname = "root"
        info.gname = "root"

        if size is None and fh.seekable():
            fh.seek(0, io.SEEK_END)
            size = fh.tell()

        info.size = size or 0

        fh.seek(0)
        self._meta_tar.addfile(info, fh)

    def add_bytes(self, data: bytes, idx: int = 0, base: int = 0) -> None:
        """Add some bytes into this snapshot.

        Convenience method for adding some bytes at a specific offset.

        Args:
            data: The bytes to copy.
            idx: The stream index.
            base: The base offset.
        """
        self._write_block(io.BytesIO(data), 0, len(data), idx=idx, base=base)

    def copy_bytes(self, source: BinaryIO, offset: int, num_bytes: int, idx: int = 0, base: int = 0) -> None:
        """Copy some bytes from the source file-like object into this snapshot.

        Often the source will be a volume on a disk, which is usually represented
        as a relative stream. If this is the case, use the ``base`` argument to
        indicate what the byte offset of the source is, relative to the start
        of the disk. The ``offset`` argument is always the offset in the
        source, so that is not affected.

        Args:
            source: The source file-like object to copy the bytes from.
            offset: The byte offset into the source to start copying bytes from.
            num_bytes: The amount of bytes to copy.
            idx: The stream index, if copying from multiple disks.
            base: The base offset, if the source is a relative stream from e.g. a disk.
        """
        self._write_block(source, offset, num_bytes, idx=idx, base=base)

    def copy_block(
        self,
        source: BinaryIO,
        offset: int,
        num_blocks: int,
        block_size: int | None = None,
        idx: int = 0,
        base: int = 0,
    ) -> None:
        """Copy some blocks in the given block size into this snapshot.

        If no block size is given, the ASDF native block size is used.
        This is really just a convenience method that does the block multiplication
        before calling ``copy_bytes``.

        Args:
            source: The source file-like object to copy the blocks from.
            offset: The byte offset into the source to start copying blocks from.
            num_blocks: The amount of blocks to copy.
            block_size: The size of each block.
            idx: The stream index, if copying from multiple disks.
            base: The base offset, if the source is a relative stream from e.g. a disk.
        """
        block_size = block_size or DEFAULT_BLOCK_SIZE
        return self.copy_bytes(source, offset, num_blocks * block_size, idx, base)

    def copy_runlist(
        self,
        source: BinaryIO,
        runlist: list[tuple[int | None, int]],
        runlist_block_size: int,
        idx: int = 0,
        base: int = 0,
    ) -> None:
        """Copy a runlist of blocks in the given block size into this snapshot.

        A runlist must be a list of tuples, where:
            (block_offset, num_blocks)

        This is really just a convenience method that does the runlist iteration
        and block multiplication before calling `copy_bytes`.

        Args:
            source: The source file-like object to copy the blocks from.
            runlist: The runlist that describes the blocks.
            runlist_block_size: The size of each block.
            idx: The stream index, if copying from multiple disks.
            base: The base offset, if the source is a relative stream from e.g. a disk.
        """
        for run_offset, run_length in runlist:
            # If run_offset is None, it's a sparse run
            if run_offset is None:
                continue

            # Save a function call by directly calling copy_bytes instead of copy_block.
            self.copy_bytes(source, run_offset * runlist_block_size, run_length * runlist_block_size, idx, base)

    def close(self) -> None:
        """Close the ASDF file.

        Writes the block table and footer, then closes the destination file-like object.
        """
        super().close()
        self._write_meta()
        if self._table:
            self._write_table()
        self._write_footer()
        self.fh.close()

    def _write_header(self) -> None:
        """Write the ASDF header to the destination file-like object."""
        header = c_asdf.header(
            magic=FILE_MAGIC,
            flags=c_asdf.FILE_FLAG.SHA256,  # Currently the only option
            version=VERSION,
            timestamp=ts.unix_now(),
            guid=self.guid.bytes_le,
        )
        header.write(self.fh)

    def _write_block(self, source: BinaryIO, offset: int, size: int, idx: int = 0, base: int = 0) -> None:
        """Write an ASDF block to the destination file-like object.

        Args:
            source: The source file-like object to copy the bytes from.
            offset: The byte offset of the copied block.
            size: The size of the copied block in bytes.
            idx: The stream index, if copying from multiple disks.
            base: The base offset, if the source is a relative stream from a disk.
        """
        absolute_offset = base + offset

        lookup_table = self._table_lookup[idx]
        entry_table = self._table[idx]

        table_idx, absolute_offset, size = _table_fit(
            absolute_offset, size, entry_table, lookup_table, lambda e: (e[2], e[3])
        )

        if table_idx is None:
            return

        offset = absolute_offset - base

        # Setup the block flags and block writer
        flags = 0
        outfh = self.fh
        if self.block_crc:
            outfh = Crc32Stream(outfh)
            flags |= c_asdf.BLOCK_FLAG.CRC32
        if self.block_compress:
            outfh = CompressedStream(outfh)
            flags |= c_asdf.BLOCK_FLAG.COMPRESS

        block_offset = self.fh.tell()  # Block header location
        block = c_asdf.block(
            magic=BLOCK_MAGIC,
            flags=flags,
            idx=idx,
            offset=absolute_offset,
            size=size,
        )
        block.write(self.fh)
        data_offset = self.fh.tell()  # Block data location

        source_stream = RangeStream(source, offset, size)
        shutil.copyfileobj(source_stream, outfh)
        # This writes any remaining data or footer for each block writer
        outfh.finalize()

        data_size = self.fh.tell() - data_offset

        lookup_table.insert(table_idx, absolute_offset)
        entry_table.insert(table_idx, (flags, idx, absolute_offset, size, block_offset, data_size))

    def _write_meta(self) -> None:
        """Write the metadata tar to the destination file-like object."""
        self._meta_tar.close()

        size = self._meta_buf.tell()
        self._meta_buf.seek(0)
        self.copy_bytes(self._meta_buf, 0, size, idx=IDX_METADATA)

    def _write_table(self) -> None:
        """Write the ASDF block table to the destination file-like object."""
        self._table_offset = self.fh.tell()
        for stream_table in self._table.values():
            for flags, idx, offset, size, file_offset, file_size in stream_table:
                table_entry = c_asdf.table_entry(
                    flags=flags,
                    idx=idx,
                    offset=offset,
                    size=size,
                    file_offset=file_offset,
                    file_size=file_size,
                )
                table_entry.write(self.fh)

    def _write_footer(self) -> None:
        """Write the ASDF footer to the destination file-like object."""
        footer = c_asdf.footer(
            magic=FOOTER_MAGIC,
            table_offset=self._table_offset,
            sha256=self.fh.digest(),
        )
        footer.write(self.fh)


class AsdfSnapshot:
    """ASDF file reader.

    Args:
        fh: File-like object to read the ASDF file from.
    """

    def __init__(self, fh: BinaryIO, recover: bool = False):
        self.fh = fh
        self.header = c_asdf.header(fh)
        if self.header.magic != FILE_MAGIC:
            raise InvalidSnapshot("invalid header magic")

        if self.header.version > VERSION:
            raise UnsupportedVersion("higher version")

        self.timestamp = ts.from_unix(self.header.timestamp)
        self.guid = uuid.UUID(bytes_le=self.header.guid)

        self.table: dict[list[SnapshotTableEntry]] = defaultdict(list)
        self._table_lookup: dict[list[int]] = defaultdict(list)

        footer_offset = self.fh.seek(-len(c_asdf.footer), io.SEEK_END)

        self.footer = c_asdf.footer(self.fh)
        if self.footer.magic != FOOTER_MAGIC:
            if recover:
                self._recover_block_table()
            else:
                raise InvalidSnapshot("invalid footer magic")
        else:
            self._parse_block_table(
                self.footer.table_offset,
                (footer_offset - self.footer.table_offset) // len(c_asdf.table_entry),
            )

        self.metadata = Metadata(self)

    def _parse_block_table(self, offset: int, count: int) -> None:
        """Parse the block table, getting rid of overlapping blocks."""
        self.fh.seek(offset)
        table_data = io.BytesIO(self.fh.read(count * len(c_asdf.table_entry)))

        for _ in range(count):
            entry = c_asdf.table_entry(table_data)
            self._table_insert(entry.idx, entry.offset, entry.size, entry.file_offset)

    def _recover_block_table(self) -> None:
        self.fh.seek(len(c_asdf.header))
        for block, file_offset in scrape_blocks(self.fh):
            self._table_insert(block.idx, block.offset, block.size, file_offset)

    def _table_insert(self, idx: int, offset: int, size: int, file_offset: int) -> None:
        stream_idx = idx
        entry_data_offset = file_offset + len(c_asdf.block)

        lookup_table = self._table_lookup[stream_idx]
        entry_table = self.table[stream_idx]

        table_idx, entry_offset, entry_size = _table_fit(
            offset, size, entry_table, lookup_table, lambda e: (e[0], e[1])
        )

        if table_idx is None:
            return

        entry_data_offset += entry_offset - offset

        lookup_table.insert(table_idx, entry_offset)
        entry_table.insert(
            table_idx,
            (
                entry_offset,
                entry_size,
                file_offset,
                entry_data_offset,
            ),
        )

    def contains(self, idx: int) -> bool:
        """Check whether this file contains the given stream index.

        Args:
            idx: The stream to check.
        """
        return idx in self.table

    def open(self, idx: int) -> AsdfStream:
        """Open a specific stream in the file.

        Args:
            idx: The stream to open.
        """
        if idx not in self.table:
            raise IndexError(f"invalid stream idx: {idx}")
        return AsdfStream(self, idx)

    def streams(self) -> Iterator[AsdfStream]:
        """Iterate over all streams in the file."""
        for i in sorted(self.table.keys()):
            yield self.open(i)

    def disks(self) -> Iterator[AsdfStream]:
        """Iterate over all non-reserved streams in the file."""
        for i in sorted(self.table.keys()):
            if i in RESERVED_IDX:
                continue
            yield self.open(i)


class Metadata:
    """ASDF metadata reader.

    Thin wrapper around ``tarfile``.

    Args:
        asdf: The :class:`AsdfSnapshot` to open the metadata of.
    """

    def __init__(self, asdf: AsdfSnapshot):
        self.tar = None
        if IDX_METADATA in asdf.table:
            self.tar = tarfile.open(fileobj=asdf.open(IDX_METADATA), mode="r")  # noqa: SIM115

    def names(self) -> list[str]:
        """Return all metadata file entries."""
        return self.tar.getnames() if self.tar else []

    def members(self) -> list[tarfile.TarInfo]:
        """Return all metadata :class:`tarfile.TarInfo` entries."""
        return self.tar.getmembers() if self.tar else []

    def open(self, path: str) -> BinaryIO:
        """Open a metadata entry and return a binary file-like object."""
        if self.tar:
            return self.tar.extractfile(path)
        raise KeyError(f"filename '{path}' not found")


class AsdfStream(AlignedStream):
    """ASDF stream from a snapshot.

    Args:
        asdf: :class:`AsdfSnapshot` parent object.
        idx: Stream index in the :class:`AsdfSnapshot`.
    """

    def __init__(self, asdf: AsdfSnapshot, idx: int):
        self.fh = asdf.fh
        self.asdf = asdf
        self.idx = idx
        self.table = asdf.table[idx]
        self._table_lookup = asdf._table_lookup[idx]

        # We don't actually know the size of the source disk
        # Doesn't really matter though, just take the last run offset + size
        size = self.table[-1][0] + self.table[-1][1]
        super().__init__(size)

    def _read(self, offset: int, length: int) -> bytes:
        result = []

        size = self.size
        run_idx = bisect_right(self._table_lookup, offset) - 1
        runlist_len = len(self.table)

        while length > 0 and run_idx < runlist_len:
            run_start, run_size, run_file_offset, run_data_offset = self.table[run_idx]
            run_end = run_start + run_size

            if run_idx + 1 < runlist_len:
                next_run_start, _, _, _ = self.table[run_idx + 1]
            else:
                next_run_start = None

            if run_idx < 0:
                # Missing first block
                if next_run_start is None:
                    break

                sparse_remaining = next_run_start - offset

                read_count = min(size - offset, min(sparse_remaining, length))
                result.append(SPARSE_BYTES * (read_count // len(SPARSE_BYTES)))

                # Proceed to next run
                run_idx += 1
            elif run_end <= offset:
                # Start outside of run bounds
                if next_run_start is None:
                    # No next run to sparse read to
                    break

                sparse_size = next_run_start - run_end
                sparse_pos = offset - run_end
                sparse_remaining = sparse_size - sparse_pos

                read_count = min(size - offset, min(sparse_remaining, length))
                result.append(SPARSE_BYTES * (read_count // len(SPARSE_BYTES)))

                # Proceed to next run
                run_idx += 1
            elif offset < run_start:
                # Previous run consumed, and next run is far away
                sparse_remaining = run_start - offset
                read_count = min(size - offset, min(sparse_remaining, length))
                result.append(SPARSE_BYTES * (read_count // len(SPARSE_BYTES)))

                # Don't proceed to next run, next loop iteration we'll be within the current run
            else:
                # We're in a run with data
                run_pos = offset - run_start
                run_remaining = run_size - run_pos
                read_count = min(size - offset, min(run_remaining, length))

                self.fh.seek(run_file_offset)
                if self.fh.read(4) != BLOCK_MAGIC:
                    raise InvalidBlock("invalid block magic")

                # Skip over block header
                self.fh.seek(run_data_offset + run_pos)
                result.append(self.fh.read(read_count))

                # Proceed to next run
                run_idx += 1

            offset += read_count
            length -= read_count

        return b"".join(result)


def scrape_blocks(fh: BinaryIO, buffer_size: int = io.DEFAULT_BUFFER_SIZE) -> Iterator[c_asdf.block, int]:
    """Scrape for block headers in ``fh`` and yield parsed block headers and their offset.

    Args:
        fh: The file-like object to scrape for block headers.
        buffer_size: The buffer size to use when scraping.
    """
    # If BLOCK_MAGIC is not found in the buffer (4 bytes), it's possible that part of it (up to 3 bytes) is in there
    # Keep an overlap buffer of 3 bytes that we prepend to the current buffer so we can also find these partial needles
    overlap_len = len(BLOCK_MAGIC) - 1
    overlap = b"\x00" * overlap_len
    while True:
        pos = fh.tell()
        buf = fh.read(buffer_size)
        if not buf:
            break

        data = overlap + buf
        needle_pos = -1
        while True:
            needle_pos = data.find(BLOCK_MAGIC, needle_pos + 1)
            if needle_pos == -1:
                break

            offset = pos + needle_pos - overlap_len

            fh.seek(offset)
            block_buf = fh.read(len(c_asdf.block))

            # Some sanity checks that this is actually a block header
            if block_buf[4] not in c_asdf.BLOCK_FLAG:
                continue

            if block_buf[6:8] != b"\x00\x00":
                continue

            block_entry = c_asdf.block(block_buf)
            yield block_entry, offset

        # Keep the last 3 bytes as overlap
        overlap = data[-overlap_len:]
        # Consumer may seek the fh, so seek it back to where we were
        fh.seek(pos + len(buf))


def _table_fit(
    entry_offset: int, entry_size: int, entry_table: list, lookup_table: list, getentry: Callable
) -> tuple[int, int, int]:
    """Calculate where to insert an entry with the given offset and size into the entry table.

    Moves or shrinks the entry to prevent block overlap, and remove any overlapping blocks.

    Args:
        entry_offset: The entry offset to calculate the insert for.
        entry_size: The entry size to calculate the insert for.
        entry_table: The entry table to insert into or remove entries from.
        lookup_table: The lookup table for the entry_table.
        getentry: A callable to return the ``(offset, size)`` tuple from an entry.

    Returns:
        A tuple of the table index to insert into, an adjusted entry offset and an adjusted entry size.
    """
    entry_end = entry_offset + entry_size

    prev_end = None
    next_start = None
    next_end = None

    table_idx = bisect_right(lookup_table, entry_offset)
    if table_idx > 0:
        prev_start, prev_size = getentry(entry_table[table_idx - 1])
        prev_end = prev_start + prev_size
    if table_idx < len(lookup_table):
        next_start, next_size = getentry(entry_table[table_idx])
        next_end = next_start + next_size

    if prev_end and prev_end >= entry_end:
        # This block is fully contained in the previous block
        return None, None, None

    if prev_end and prev_end > entry_offset:
        # The start of this block overlaps with the previous, so shrink this block
        entry_offset = prev_end

    # We may completely overlap one or more next entries
    while next_end and next_end <= entry_end:
        lookup_table.pop(table_idx)
        entry_table.pop(table_idx)

        if table_idx < len(lookup_table):
            next_start, next_size = getentry(entry_table[table_idx])
            next_end = next_start + next_size
        else:
            next_start, next_end = None, None

    if next_start and next_start < entry_end < next_end:
        # The next block overlaps with this block, so shrink this block
        entry_end = next_start

    if entry_offset >= entry_end:
        # Shouldn't be possible to go beyond the end, but we may end up with a 0 sized block
        return None, None, None

    return table_idx, entry_offset, entry_end - entry_offset
