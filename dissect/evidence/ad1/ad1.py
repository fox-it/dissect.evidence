from __future__ import annotations

import re
from datetime import datetime, timezone
from functools import cached_property
from pathlib import Path, PurePath, PurePosixPath, PureWindowsPath
from typing import TYPE_CHECKING, BinaryIO

from dissect.evidence.ad1.c_ad1 import c_ad1
from dissect.evidence.ad1.stream import AD1Stream, FileStream
from dissect.evidence.adcrypt.adcrypt import ADCrypt, is_adcrypt
from dissect.evidence.exception import FileNotFoundError, NotADirectoryError, NotASymlinkError

if TYPE_CHECKING:
    from collections.abc import Iterator

EntryType = c_ad1.EntryType
MetaType = c_ad1.MetaType
FileClassType = c_ad1.FileClassType

MAX_OPEN_SEGMENTS = 128


def find_files(path: Path) -> list[Path]:
    files = set()
    for file in path.parent.iterdir():
        if file.stem == path.stem and re.match(r"^\.ad[0-9]+$", file.suffix.lower()):
            files.add(file)
    return sorted(files, key=lambda file: int(file.suffix[3:]))


class AD1:
    """AccessData Logical Image (AD1v4) implementation.

    Supports ``zlib`` compressed images and ADCRYPT encrypted images.

    Should be initialized using a list of segment paths or file-like objects, e.g.::

        fs = AD1([Path("file.ad1"), Path("file.ad2")])
        fs = AD1([Path("file.ad1").open("rb"), Path("file.ad2").open("rb")])

    If the AD1 container is ADCRYPT encrypted, it can be unlocked using either a passphrase or private key::

        fs.unlock(passphrase="my secret passphrase")
        fs.unlock(private_key=Path("path/to/private/key.pem"))

    Resources:
        - Reverse engineering FTK Imager
        - https://github.com/pcbje/pyad1/blob/master/documentation/AccessData%20Format%20(AD1).asciidoc
        - https://github.com/al3ks1s/AD1-tools
        - https://web.archive.org/web/20231013073319/https://tmairi.github.io/posts/dissecting-the-ad1-file-format/
        - https://al3ks1s.fr/posts/adventures-part-1/
    """

    def __init__(self, fh: BinaryIO | list[BinaryIO]):
        fhs = [fh] if not isinstance(fh, list) else fh
        self.fh = fhs
        self.root = VirtualEntry(self, "/")

        self._segments: dict[int, SegmentFile] = {}
        self._segment_lru = []
        self._segment_offsets = []

        self.size = 0
        self.stream: AD1Stream | None = None
        self.logical_image: LogicalImage | None = None

        if not self.fh:
            raise ValueError("No segment files provided for AD1 container")

        self.adcrypt = None

        first_segment = self.segment(0)
        if is_adcrypt(first_segment.fh):
            self.adcrypt = ADCrypt(first_segment.fh)
        else:
            self._open_ad1()

    def is_adcrypt(self) -> bool:
        """Return whether the AD1 container is ADCRYPT encrypted."""
        return self.adcrypt is not None

    def is_locked(self) -> bool:
        """Return whether the ADCRYPT container is locked."""
        return self.is_adcrypt() and self.adcrypt.is_locked()

    def segment(self, idx: int) -> SegmentFile:
        """Open a segment by index.

        Implements a simple LRU cache to limit the number of open segments.

        Args:
            idx: Index or URI of the segment to open.
        """
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

        if self.is_adcrypt() and not self.is_locked():
            fh = self.adcrypt.wrap(fh, idx)

        segment = SegmentFile(fh)

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

        # Open the AD1
        self._open_ad1()

    def _open_ad1(self) -> None:
        self._segment_offsets = []

        offset = 0
        for i in range(len(self.fh)):
            segment = self.segment(i)
            if segment.header.magic != c_ad1.ADSEGMENTEDFILE_MAGIC.encode():
                raise ValueError(f"Invalid AD1 segment file magic in segment {i}")

            if segment.number != i + 1:
                raise ValueError(f"Invalid AD1 segment number in segment {i}, got {segment.number}, expected {i + 1}")

            offset += segment.size
            self._segment_offsets.append(offset)

        self.size = offset
        self.stream = AD1Stream(self)

        # The first .ad1 file contains a logical image header
        first_segment = self.segment(0)
        first_segment.fh.seek(first_segment.header.logical_image_offset)
        self.logical_image = LogicalImage(first_segment.fh)

        # We need to create some fake entries for all parts leading up to `logical_image.name`
        # This name commonly contains the full path each entry in the container is relative to
        _hallicinate_root_entries(self)

    def entry(self, path: str, entry: FileEntry | None = None) -> FileEntry:
        """Return a :class:`FileEntry` based on the given absolute ``path``.

        Args:
            path: Absolute path within the AD1 container.
            entry: The starting entry for relative paths. Defaults to the root entry.

        Raises:
            ValueError: If the ADCRYPT container is locked.
            FileNotFoundError if the given ``path`` is not found in the container.

        Returns:
            :class:`FileEntry` when the given ``path`` is found.
        """
        if self.is_locked():
            raise ValueError("AD1 container is locked by ADCRYPT")

        entry = entry or self.root

        for part in path.split("/"):
            if not part:
                continue

            for child in entry.iterdir():
                if child.name == part and child.type != EntryType.Deleted:
                    entry = child
                    break
            else:
                raise FileNotFoundError(f"File not found: {path}")

        return entry

    def get(self, path: str) -> FileEntry:
        """Shortcut for ``AD1.entry(path)``."""
        return self.entry(path)

    def open(self, path: str) -> FileStream:
        """Shortcut for ``AD1.entry(path).open()``."""
        return self.entry(path).open()


def _hallicinate_root_entries(ad1: AD1) -> None:
    # We need to create some fake entries for all parts leading up to `logical_image.name`
    # This name commonly contains the full path each entry in the container is relative to
    # Not always though, so do some poor mans heuristics
    root_name = ad1.logical_image.name
    if root_name == "Custom Content Image([Multi])":
        ad1.root.entry.child = ad1.logical_image.header.first_file_offset
        if len(ad1.root.children) != 1:
            raise ValueError("Unexpected number of root children for Custom Content Image([Multi])")

        root_name = ad1.root.children[0].name.split(":", 1)[-1]
        first_file_entry = ad1.root.children[0].entry
        is_multi_image = True
    else:
        is_multi_image = False

    root_path = PureWindowsPath(root_name) if "/" not in root_name and "\\" in root_name else PurePosixPath(root_name)
    parts = list(root_path.parts)
    parent = _create_root_entries(ad1, ad1.root, root_path, parts)

    if is_multi_image:
        parent.name = parent.name
        parent.offset = ad1.logical_image.header.first_file_offset
        parent.entry = first_file_entry
    else:
        # Add the first file offset as the first child offset of the last root part
        parent.entry.child = ad1.logical_image.header.first_file_offset


def _create_root_entries(ad1: AD1, parent: FileEntry, path: PurePath, parts: list[str]) -> FileEntry:
    while parts:
        part = parts.pop(0)
        if path.drive and part == f"{path.drive}\\":
            part = path.drive

        entry = VirtualEntry(ad1, part)
        parent.children = [entry]
        parent = entry

    return parent


class SegmentFile:
    """Represents an AD1 segmented file."""

    def __init__(self, fh: BinaryIO):
        self.fh = fh
        self.fh.seek(0)
        self.header = c_ad1.SegmentedFileHeader(self.fh)
        self.number = self.header.segment_number
        self.count = self.header.segment_count
        self.size = self.header.segment_size - 512  # Subtract header size

    def __repr__(self) -> str:
        return f"<SegmentFile number={self.number} count={self.count} size={self.size}>"


class LogicalImage:
    """Represents an AD1 logical image."""

    def __init__(self, fh: BinaryIO):
        self.fh = fh
        self.header = c_ad1.LogicalImageHeader(fh)
        self.name = self.header.name.decode()
        self.version = self.header.version
        self.offset = self.header.first_file_offset
        self.chunk_size = self.header.chunk_size

    def __repr__(self) -> str:
        return (
            f"<LogicalImage version={self.version} name={self.name} offset={self.offset} chunk_size={self.chunk_size}>"
        )


class FileEntry:
    """Represents a file entry in an AD1 logical image."""

    def __init__(self, ad1: AD1, offset: int):
        self.ad1 = ad1
        self.offset = offset

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} type={self.type.name} name={self.name!r} size={self.size}>"

    @cached_property
    def entry(self) -> c_ad1.FileEntry:
        self.ad1.stream.seek(self.offset)
        return c_ad1.FileEntry(self.ad1.stream)

    @cached_property
    def name(self) -> str:
        return self.entry.name.decode()

    @cached_property
    def type(self) -> EntryType:
        return self.entry.type

    @cached_property
    def meta(self) -> dict[MetaType, FileMeta]:
        result = {}

        offset = self.entry.meta
        while offset != 0:
            meta = FileMeta(self.ad1, offset)
            offset = meta.next
            result[meta.type] = meta

        return result

    @cached_property
    def children(self) -> list[FileEntry]:
        result = []

        offset = self.entry.child
        while offset != 0:
            child = FileEntry(self.ad1, offset)
            result.append(child)
            offset = child.entry.next

        return result

    @cached_property
    def size(self) -> int:
        if meta := self.meta.get(MetaType.FileSize):
            return int(meta.data)
        return 0

    @cached_property
    def atime(self) -> datetime:
        if meta := self.meta.get(MetaType.DateAccessed):
            return convert_ts(meta.data)
        return datetime(1970, 1, 1, 0, 0, 0, tzinfo=timezone.utc)

    @cached_property
    def ctime(self) -> datetime:
        if meta := self.meta.get(MetaType.MFTFileDateChanged, self.meta.get(MetaType.DateModified)):
            return convert_ts(meta.data)
        return datetime(1970, 1, 1, 0, 0, 0, tzinfo=timezone.utc)

    @cached_property
    def mtime(self) -> datetime:
        if meta := self.meta.get(MetaType.DateModified):
            return convert_ts(meta.data)
        return datetime(1970, 1, 1, 0, 0, 0, tzinfo=timezone.utc)

    @cached_property
    def btime(self) -> datetime:
        if meta := self.meta.get(MetaType.DateCreated):
            return convert_ts(meta.data)
        return datetime(1970, 1, 1, 0, 0, 0, tzinfo=timezone.utc)

    @cached_property
    def md5(self) -> str | None:
        if meta := self.meta.get(MetaType.MD5):
            return meta.data.decode()
        return None

    @cached_property
    def sha1(self) -> str | None:
        if meta := self.meta.get(MetaType.SHA1):
            return meta.data.decode()
        return None

    def is_file(self) -> bool:
        return self.type in (EntryType.File, EntryType.Unknown_File)

    def is_dir(self) -> bool:
        return self.type == EntryType.Directory

    def is_symlink(self) -> bool:
        if meta := self.meta.get(MetaType.FileClass):
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

    def open(self) -> FileStream:
        """Open the file entry for reading."""
        if self.is_dir():
            raise IsADirectoryError(self.name)
        return FileStream(self)


class VirtualEntry(FileEntry):
    """Represents the root entry in an AD1 logical image."""

    def __init__(self, ad1: AD1, name: str):
        super().__init__(ad1, -1)
        self.entry = c_ad1.FileEntry(name=name.encode(), type=EntryType.Directory, size=0)


class FileMeta:
    """Represents a single AD1 logical file metadata item found inside :class:`FileEntry`."""

    def __init__(self, ad1: AD1, offset: int):
        self.ad1 = ad1
        self.offset = offset

        self.ad1.stream.seek(offset)
        self.entry = c_ad1.FileMeta(self.ad1.stream)

        self.category = self.entry.category
        self.type = self.entry.type
        self.data = self.entry.data

        self.next = self.entry.next

    def __repr__(self) -> str:
        return f"<FileMeta category={self.category} type={self.type} data={self.data}>"


def convert_ts(value: bytes) -> datetime:
    """Convert an AD1 timestamp to datetime object. Assuming this is UTC."""

    # DateCreated does not (always) have ``.%f`` precision.
    fmt = "%Y%m%dT%H%M%S.%f" if b"." in value else "%Y%m%dT%H%M%S"
    return datetime.strptime(value.decode(), fmt).replace(tzinfo=timezone.utc)
