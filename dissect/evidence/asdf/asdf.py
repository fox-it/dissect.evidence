# Acquire Snapshot Data Format

from __future__ import print_function

import io
import gzip
import uuid
import shutil
import tarfile
from bisect import bisect_right
from zlib import crc32
from collections import defaultdict

from dissect import cstruct
from dissect.util import ts
from dissect.util.stream import AlignedStream, RangeStream

from dissect.evidence.exceptions import InvalidSnapshot, UnsupportedVersion, InvalidBlock
from dissect.evidence.asdf.streams import HashedStream, CompressedStream, SubStreamBase

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
    SHADOW      = 0x04,
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
    uint64      offset;         // Absolute disk offset
    uint64      size;           // Size of block (on disk, not in file)
};

struct table_entry = {
    BLOCK_FLAG  flags;          // Block flags
    uint8       idx;            // Stream index, some reserved values have special meaning
    char        reserved[2];    // Reserved
    uint64      offset;         // Absolute disk offset
    uint64      size;           // Size of block (on disk, not in file)
    uint64      file_offset;    // Offset in file to this block
    uint64      file_size;      // Size of block in this file
};

struct footer {
    char        magic[4];       // Footer magic, must be "FT\\xa5\\xdf"
    char        reserved[4];    // Reserved
    uint64      table_offset;   // Offset in file to start of block table
    char        sha256[32];     // SHA256 of this file up until this hash
};
"""
c_asdf = cstruct.cstruct()
c_asdf.load(asdf_def)


class AsdfWriter(io.RawIOBase):
    """ASDF file writer.

    Current limitations:
        - Maximum source disk size is ~16EiB
        - Maximum number of disks is 254

    There's no cleverness here. Just writing blocks. We don't sort/"defrag"
    or prevent dupes on purpose. This is to make the process of writing
    these files as "lightweight" as possible. The decision to offload all
    heavy lifting to the readers is because writers are usually low power
    clients, whereas the readers are usually high power servers.

    Some things are currently hardcoded (like SHA256), although they may
    become variable in the future.

    Args:
        fh: File-like object to write to.
        guid: Unique identifier. Used to link images to writers.
        block_size: The block size to use for storing data.
        block_crc: Flag to store a CRC32 after each block.
        block_compress: Flag to compress blocks using zlib.
    """

    def __init__(self, fh, guid=None, compress=False, block_crc=True):
        self._fh = fh
        self.fh = self._fh

        if compress:
            self.fh = gzip.GzipFile(fileobj=self.fh, mode="wb")

        self.fh = HashedStream(self.fh)
        self.guid = guid or uuid.uuid4()

        # Options
        self.block_crc = block_crc
        self.block_compress = False  # Hard code this for now

        self._table = []
        self._table_offset = 0

        self._meta_buf = io.BytesIO()
        self._meta_tar = tarfile.open(fileobj=self._meta_buf, mode="w")

        self._write_header()

    def add_metadata(self, path, fh, size=None):
        info = self._meta_tar.tarinfo()
        info.name = path
        info.uname = "root"
        info.gname = "root"

        if not size:
            fh.seek(0, io.SEEK_END)
            size = fh.tell()

        info.size = size

        fh.seek(0)
        self._meta_tar.addfile(info, fh)

    def copy_bytes(self, source, offset, num_bytes, idx=0, base=0):
        """Copy some bytes from the source file-like object into this snapshot.

        Often the source will be a volume on a disk, which is usually represented
        as a relative stream. If this is the case, use the `base` argument to
        indicate what the byte offset of the source is, relative to the start
        of the disk. The `offset` argument is always the offset in the
        source, so that is not affected.

        Args:
            source: The source file-like object to copy the bytes from.
            offset: The byte offset into the source to start copying bytes from.
            num_bytes: The amount of bytes to copy.
            idx: The stream index, if copying from multiple disks.
            base: The base offset, if the source is a relative stream from a disk.
        """
        self._write_block(source, offset, num_bytes, idx=idx, base=base)

    def copy_block(self, source, offset, num_blocks, block_size=None, idx=0, base=0):
        """Copy some blocks in the given block size into this snapshot.

        If no block size is given, the ASDF native block size is used.
        This is really just a convenience method that does the block multiplication
        before calling `copy_bytes`.

        Args:
            source: The source file-like object to copy the blocks from.
            offset: The byte offset into the source to start copying blocks from.
            num_blocks: The amount of blocks to copy.
            block_size: The size of each block.
            idx: The stream index, if copying from multiple disks.
            base: The base offset, if the source is a relative stream from a disk.
        """
        block_size = block_size or DEFAULT_BLOCK_SIZE
        return self.copy_bytes(source, offset, num_blocks * block_size, idx, base)

    def copy_runlist(self, source, runlist, runlist_block_size, idx=0, base=0):
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
            base: The base offset, if the source is a relative stream from a disk.
        """
        for run_offset, run_length in runlist:
            # If run_offset is None, it's a sparse run
            if run_offset is None:
                continue

            # Save a function call by directly calling copy_bytes instead of copy_block.
            self.copy_bytes(source, run_offset * runlist_block_size, run_length * runlist_block_size, idx, base)

    def close(self):
        """Close the ASDF file.

        Writes the block table and footer, then closes the destination file-like object.
        """
        super().close()
        self._write_meta()
        if self._table:
            self._write_table()
        self._write_footer()
        self.fh.close()

    def _write_header(self):
        """Write the ASDF header to the destination file-like object."""
        header = c_asdf.header(
            magic=FILE_MAGIC,
            flags=c_asdf.FILE_FLAG.SHA256,  # Currently the only option
            version=VERSION,
            timestamp=ts.unix_now(),
            guid=self.guid.bytes_le,
        )
        header.write(self.fh)

    def _write_block(self, source, offset, size, idx=0, base=0):
        """Write an ASDF block to the destination file-like object.

        Args:
            source: The source file-like object to copy the bytes from.
            offset: The byte offset of the copied block.
            size: The size of the copied block in bytes.
            idx: The stream index, if copying from multiple disks.
            base: The base offset, if the source is a relative stream from a disk.
        """
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
        absolute_offset = base + offset
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
        self._table.append((flags, idx, absolute_offset, size, block_offset, data_size))

    def _write_meta(self):
        self._meta_tar.close()

        size = self._meta_buf.tell()
        self._meta_buf.seek(0)
        self.copy_bytes(self._meta_buf, 0, size, idx=IDX_METADATA)

    def _write_table(self):
        """Write the ASDF block table to the destination file-like object."""
        self._table_offset = self.fh.tell()
        for flags, idx, offset, size, file_offset, file_size in self._table:
            table_entry = c_asdf.table_entry(
                flags=flags,
                idx=idx,
                offset=offset,
                size=size,
                file_offset=file_offset,
                file_size=file_size,
            )
            table_entry.write(self.fh)

    def _write_footer(self):
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

    def __init__(self, fh):
        self.fh = fh
        self.header = c_asdf.header(fh)
        if self.header.magic != FILE_MAGIC:
            raise InvalidSnapshot("invalid header magic")

        if self.header.version > VERSION:
            raise UnsupportedVersion("higher version")

        self.fh.seek(-len(c_asdf.footer), io.SEEK_END)
        footer_offset = self.fh.tell()

        self.footer = c_asdf.footer(self.fh)
        if self.footer.magic != FOOTER_MAGIC:
            raise InvalidSnapshot("invalid footer magic")

        self.timestamp = ts.from_unix(self.header.timestamp)
        self.guid = uuid.UUID(bytes_le=self.header.guid)
        self.table = defaultdict(list)
        self._table_lookup = defaultdict(list)

        table_offset = self.footer.table_offset
        table_size = (footer_offset - table_offset) // len(c_asdf.table_entry)

        self.fh.seek(table_offset)
        for _ in range(table_size):
            entry = c_asdf.table_entry(self.fh)
            stream_idx = entry.idx
            lookup_idx = bisect_right(self._table_lookup[stream_idx], entry.offset)
            self._table_lookup[stream_idx].insert(lookup_idx, entry.offset)
            self.table[stream_idx].insert(lookup_idx, entry)

        self.metadata = Metadata(self)

    def contains(self, idx):
        """Check whether this file contains the given stream index.

        Args:
            idx: The stream to check.
        """
        return idx in self.table

    def open(self, idx):
        """Open a specific stream in the file.

        Args:
            idx: The stream to open.
        """
        if idx not in self.table:
            raise IndexError(f"invalid stream idx: {idx}")
        return AsdfStream(self, idx)

    def streams(self):
        """Iterate over all streams in the file."""
        for i in sorted(self.table.keys()):
            yield self.open(i)

    def disks(self):
        """Iterate over all non-reserved streams in the file."""
        for i in sorted(self.table.keys()):
            if i in RESERVED_IDX:
                continue
            yield self.open(i)


class Metadata:
    def __init__(self, asdf):
        self.tar = None
        if IDX_METADATA in asdf.table:
            self.tar = tarfile.open(fileobj=asdf.open(IDX_METADATA), mode="r")

    def names(self):
        return self.tar.getnames() if self.tar else []

    def members(self):
        return self.tar.getmembers() if self.tar else []

    def open(self, path):
        if self.tar:
            return self.tar.extractfile(path)
        raise KeyError(f"filename '{path}' not found")


class AsdfStream(AlignedStream):
    """Asdf stream from a snapshot.

    Args:
        asdf: AsdfFile parent object.
        idx: Stream index in the AsdfFile.
    """

    def __init__(self, asdf, idx):
        self.fh = asdf.fh
        self.asdf = asdf
        self.idx = idx
        self.table = asdf.table[idx]
        self._table_lookup = asdf._table_lookup[idx]

        # We don't actually know the size of the source disk
        # Doesn't really matter though, just take the last run offset + size
        size = self.table[-1].offset + self.table[-1].size
        super().__init__(size)

    def _read(self, offset, length):
        r = []

        size = self.size
        run_idx = bisect_right(self._table_lookup, offset) - 1
        runlist_len = len(self.table)

        while length > 0 and run_idx < len(self.table):

            run = self.table[run_idx]
            next_run = self.table[run_idx + 1] if run_idx + 1 < runlist_len else None

            run_start = run.offset
            run_end = run_start + run.size

            if run_idx < 0:
                # Missing first block
                if not next_run:
                    break

                sparse_remaining = next_run.offset - offset

                read_count = min(size - offset, min(sparse_remaining, length))
                r.append(SPARSE_BYTES * (read_count // len(SPARSE_BYTES)))

                # Proceed to next run
                run_idx += 1
            elif run_end <= offset:
                # Start outside of run bounds
                sparse_size = next_run.offset - run_end
                sparse_pos = offset - run_end
                sparse_remaining = sparse_size - sparse_pos

                read_count = min(size - offset, min(sparse_remaining, length))
                r.append(SPARSE_BYTES * (read_count // len(SPARSE_BYTES)))

                # Proceed to next run
                run_idx += 1
            elif offset < run_start:
                # Previous run consumed, and next run is far away
                sparse_remaining = run_start - offset
                read_count = min(size - offset, min(sparse_remaining, length))
                r.append(SPARSE_BYTES * (read_count // len(SPARSE_BYTES)))
            else:
                run_pos = offset - run_start
                run_remaining = run.size - run_pos
                read_count = min(size - offset, min(run_remaining, length))
                self.fh.seek(run.file_offset)

                block_header = c_asdf.block(self.fh)
                if block_header.magic != BLOCK_MAGIC:
                    raise InvalidBlock("invalid block magic")

                self.fh.seek(run_pos, io.SEEK_CUR)
                r.append(self.fh.read(read_count))

                run_idx += 1

            offset += read_count
            length -= read_count

        return b"".join(r)


class Crc32Stream(SubStreamBase):
    """Compute a CRC32 over all written data.

    This assumes that all data is written as a continuous stream.

    Args:
        fh: The file-like object to wrap.
    """

    def __init__(self, fh):
        super().__init__(fh)
        self.crc = 0

    def write(self, b):
        self.crc = crc32(b, self.crc) & 0xFFFFFFFF
        return self.fh.write(b)

    def digest(self):
        return self.crc

    def finalize(self):
        c_asdf.uint32.write(self.fh, self.digest())
        self.fh.finalize()
