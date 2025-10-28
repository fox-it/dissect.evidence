from __future__ import annotations

import re
import zlib
from datetime import datetime, timezone
from functools import cached_property
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import TYPE_CHECKING, BinaryIO

from dissect.util.stream import AlignedStream, MappingStream, RelativeStream

from dissect.evidence.ad1.c_ad1 import c_ad1
from dissect.evidence.exceptions import FileNotFoundError, NotADirectoryError, NotASymlinkError

if TYPE_CHECKING:
    from collections.abc import Iterator


EntryType = c_ad1.EntryType
MetaType = c_ad1.MetaType
FileClassType = c_ad1.FileClassType


def atoi(text: str) -> int | str:
    return int(text) if text.isdigit() else text


def natural_keys(text: str | Path) -> list[int | str]:
    return [atoi(c) for c in re.split(r"(\d+)", str(text))]


def find_files(path: Path) -> set[Path]:
    files = set()
    for file in path.parent.iterdir():
        if file.stem == path.stem and re.match(r"^\.ad[0-9]+$", file.suffix.lower()):
            files.add(file)
    return sorted(files, key=natural_keys)


class AD1:
    """AccessData Logical Image (AD1v4) implementation.

    Supports ``zlib`` compressed images. Does not directly support encrypted (``b"ADCRYPT"``) images.

    Should be initialized using a list of segment files, e.g.::

        fs = AD1([Path("file.ad1").open("rb"), Path("file.ad2").open("rb")])

    Resources:
        - Reversing FTK Imager
        - https://github.com/pcbje/pyad1/blob/master/documentation/AccessData%20Format%20(AD1).asciidoc
        - https://github.com/al3ks1s/AD1-tools
        - https://web.archive.org/web/20231013073319/https://tmairi.github.io/posts/dissecting-the-ad1-file-format/
        - https://al3ks1s.fr/posts/adventures-part-1/
    """

    def __init__(self, fh: BinaryIO | list[BinaryIO]):
        self.fhs: list[BinaryIO] = fh if isinstance(fh, list) else [fh]
        self.segments: list[AD1SegmentFile] = []
        self.stream = MappingStream()
        self.logical_image: AD1LogicalImage = None
        self.root: FileEntry = None

        if len(self.fhs) < 1 or not all(hasattr(fh, "read") for fh in self.fhs):
            raise ValueError(f"Invalid given file handles: {fh!r}")

        for fh in self.fhs:
            # Each file contains a segment header
            segment = AD1SegmentFile(fh)
            self.segments.append(segment)

            # Add the segment file handle to the mapping stream, minus the segment header.
            self.stream.add(self.stream.size or 0, segment.header.segment_size - 512, fh, 512)

        # The first .ad1 file contains an image header
        offset = self.segments[0].header.logical_image_offset
        self.logical_image = AD1LogicalImage(RelativeStream(self.fhs[0], offset))  # NOTE: Unnecesary RelativeStream?
        self.root = FileEntry(self, -1, is_root=True, root_name="/")

        # Add entries for all parts in logical_image.name. This name commonly contains the full path each entry in the
        # container is relative to.
        root_name = self.logical_image.header.name.decode()
        root_path = (
            PureWindowsPath(root_name) if "/" not in root_name and "\\" in root_name else PurePosixPath(root_name)
        )
        parts = list(root_path.parts)
        parent = self.root

        while parts:
            part = parts.pop(0)
            if root_path.drive and part == f"{root_path.drive}\\":
                part = root_path.drive
            entry = FileEntry(self, -1, is_root=True, root_name=part)
            parent.children = [entry]
            parent = entry

        # Add the first children to the last root part
        offset = self.logical_image.header.first_file_offset
        entry.children = []
        while offset != 0:
            child = FileEntry(self, offset)
            entry.children.append(child)
            offset = child.entry.next

    def entry(self, path: str) -> FileEntry:
        """Return a :class:`FileEntry` based on the given absolute `path`.

        Raises:
            FileNotFoundError if the given `path` is not found in the `AD1` container.

        Returns:
            :class:`FileEntry` when the given `path` is found.
        """

        components = path.lstrip("/").split("/")
        current = self.root

        if components[0] == "":
            return current

        for c in components:
            for entry in current.iterdir():
                if entry.name == c and entry.entry.type != EntryType.Deleted:
                    current = entry

        if current.name == components[-1]:
            return current

        raise FileNotFoundError(f"Path not found: {path}")

    def get(self, path: str) -> FileEntry:
        """Shortcut method to ``AD1.entry()`` for the given ``path``."""

        return self.entry(path)

    def open(self, path: str) -> FileObject:
        """Shortcut method to ``FileEntry.open()`` for the given ``path``."""

        return self.entry(path).open()


class AD1SegmentFile:
    """Represents an AD1 segmented file."""

    def __init__(self, fh: BinaryIO):
        self.fh = fh
        self.header = c_ad1.SegmentedFileHeader(fh)
        self.number = self.header.segment_number
        self.count = self.header.segment_count
        self.size = self.header.segment_size

    def __repr__(self) -> str:
        return f"<AD1SegmentFile id={self.number} count={self.count} size={self.size}>"


class AD1LogicalImage:
    """Represents an AD1 logical image."""

    def __init__(self, fh: BinaryIO):
        self.fh = fh
        self.header = c_ad1.LogicalImageHeader(fh)
        self.name = self.header.name
        self.version = self.header.version
        self.offset = self.header.first_file_offset
        self.chunk_size = self.header.chunk_size

    def __repr__(self) -> str:
        return f"<AD1LogicalImage version={self.version} name={self.name} offset={self.offset} chunk_size={self.chunk_size}>"  # noqa: E501


class FileEntry:
    """Represents a file entry in an AD1 logical image."""

    def __init__(self, ad1: AD1, offset: int, is_root: bool = False, root_name: str | None = None):
        self.ad1 = ad1
        self.offset = offset
        self.is_root = is_root

        self.entry = None
        self.type = None
        self.meta = []

        if is_root:
            self.entry = c_ad1.FileEntry(name=root_name.encode(), type=EntryType.Directory, size=0)

        else:
            fh = ad1.stream
            fh.seek(offset)
            self.entry = c_ad1.FileEntry(fh)
            self.size = self.entry.size
            self.type = self.entry.type

            offset = self.entry.meta
            while offset != 0:
                meta = FileMeta(ad1.stream, offset)
                offset = meta.entry.next
                self.meta.append(meta)

    def __repr__(self) -> str:
        if self.is_symlink():
            file_type = "AD1Symlink"
        elif self.is_file():
            file_type = "AD1File"
        elif self.is_dir():
            file_type = "AD1Directory"
        else:
            file_type = "AD1UnknownType"
        return f"<{file_type} name={self.name!r} size={self.size!r}>"

    @cached_property
    def name(self) -> str:
        return self.entry.name.decode()

    @cached_property
    def children(self) -> list[FileEntry]:
        children = []
        offset = self.entry.child
        while offset != 0:
            child = FileEntry(self.ad1, offset)
            children.append(child)
            offset = child.entry.next

        return children

    def open(self) -> FileObject:
        return FileObject(self)

    def is_file(self) -> bool:
        return self.entry.type in (EntryType.File, EntryType.Unknown_File)

    def is_dir(self) -> bool:
        return self.entry.type == EntryType.Directory

    def is_symlink(self) -> bool:
        if meta := self.get_meta(MetaType.FileClass):
            return int.from_bytes(meta.data, "little") == FileClassType.ReparsePoint
        return False

    def listdir(self) -> list[str]:
        if not self.is_dir():
            raise NotADirectoryError(self.name)
        return [child.name for child in self.children]

    def iterdir(self) -> Iterator[FileEntry]:
        if not self.is_dir():
            raise NotADirectoryError(self.name)
        yield from self.children

    def readlink(self) -> str:
        if not self.is_symlink():
            raise NotASymlinkError(self.name)

        # TODO: Investigate symlinks for unix-like filesystems.

        reparse_point = c_ad1.ReparsePoint(self.open())
        return reparse_point.link.strip("\00").split("\00")[-1]

    def get_meta(self, attr: int | c_ad1.MetaType) -> c_ad1.FileMeta | None:
        return next((m for m in self.meta if m.type == attr), None)

    @cached_property
    def size(self) -> int:
        meta = self.get_meta(c_ad1.MetaType.FileSize)
        return meta.data if meta else 0

    @cached_property
    def atime(self) -> datetime:
        meta = self.get_meta(c_ad1.MetaType.DateAccessed)
        return convert_ts(meta.data) if meta else datetime(1970, 1, 1, 0, 0, 0, tzinfo=timezone.utc)

    @cached_property
    def ctime(self) -> datetime:
        meta = self.get_meta(c_ad1.MetaType.DateModified)
        # We could use MetaType.MFTFileDateChanged here depending on the fs
        return convert_ts(meta.data) if meta else datetime(1970, 1, 1, 0, 0, 0, tzinfo=timezone.utc)

    @cached_property
    def mtime(self) -> datetime:
        meta = self.get_meta(c_ad1.MetaType.DateModified)
        return convert_ts(meta.data) if meta else datetime(1970, 1, 1, 0, 0, 0, tzinfo=timezone.utc)

    @cached_property
    def btime(self) -> datetime:
        meta = self.get_meta(c_ad1.MetaType.DateCreated)
        return convert_ts(meta.data) if meta else datetime(1970, 1, 1, 0, 0, 0, tzinfo=timezone.utc)


def convert_ts(input: bytes) -> datetime:
    """Convert an AD1 timestamp to datetime object. Assuming this is UTC."""

    # DateCreated does not (always) have ``.%f`` precision.
    fmt = "%Y%m%dT%H%M%S.%f" if b"." in input else "%Y%m%dT%H%M%S"
    return datetime.strptime(input.decode(), fmt).replace(tzinfo=timezone.utc)


class FileMeta:
    """Represents a single AD1 logical file metadata item found inside :class:`FileEntry`."""

    def __init__(self, stream: MappingStream, offset: int):
        self.stream = stream
        self.offset = offset

        fh = stream
        fh.seek(offset)
        self.entry = c_ad1.FileMeta(fh)

        self.type = self.entry.type
        self.data = self.entry.data

    def __repr__(self) -> str:
        return f"<FileMeta category={self.entry.category} type={self.entry.type} data={self.entry.data}>"


# TODO: Can we just use ZlibStream from dissect.util.stream?
class FileObject(AlignedStream):
    """Custom stream format implementation for AD1 :class:`FileEntry` file contents."""

    def __init__(self, entry: FileEntry):
        self.entry = entry
        super().__init__(self.entry.size, self.entry.ad1.logical_image.chunk_size)

        self.entry.ad1.stream.seek(self.entry.entry.zlib_meta)
        self.chunks = c_ad1.FileEntryChunks(self.entry.ad1.stream).chunks

    def _read(self, offset: int, length: int) -> bytes:
        r = []
        fh = self.entry.ad1.stream
        chunk_size = self.entry.ad1.logical_image.chunk_size

        chunk = offset // chunk_size
        chunk_count = (length + chunk_size - 1) // chunk_size

        chunk_offsets = self.chunks[chunk : chunk + chunk_count + 1]
        if len(chunk_offsets) != chunk_count + 1:
            chunk_offsets.append(self.entry.entry.meta)

        fh.seek(chunk_offsets[0])
        buf = fh.read(chunk_offsets[-1] - chunk_offsets[0])

        prev_offset = chunk_offsets[0]
        for offset in chunk_offsets[1:]:
            chunk_size = offset - prev_offset
            r.append(zlib.decompress(buf[:chunk_size]))
            buf = buf[chunk_size:]
            prev_offset = offset

        return b"".join(r)
