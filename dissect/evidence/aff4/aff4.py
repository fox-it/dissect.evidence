from __future__ import annotations

import urllib.parse
import zipfile
from functools import cached_property
from pathlib import Path
from typing import TYPE_CHECKING, BinaryIO

from dissect.evidence.aff4.metadata import Information
from dissect.evidence.aff4.util import parse_turtle

if TYPE_CHECKING:
    import pathlib
    from types import TracebackType

    from typing_extensions import Self

    from dissect.evidence.aff4.metadata import FileImage, Image, Object, ValueType

MAX_OPEN_SEGMENTS = 128


class AFF4:
    """AFF4 evidence container.

    Args:
        fh: A file-like object, ``pathlib.Path`` or a list of those representing the AFF4 segments.
    """

    def __init__(self, fh: BinaryIO | list[BinaryIO] | pathlib.Path | list[pathlib.Path]):
        fhs = [fh] if not isinstance(fh, list) else fh

        self.fh = fhs
        self._segments: dict[str, Segment] = {}
        self._segment_lru = []
        self._segment_map: dict[str, int] = {}

        all_information: dict[str, Object] = {}

        for idx in range(len(self.fh)):
            segment = self.segment(idx)

            self._segment_map[segment.uri] = idx
            for key, value in segment.information.items():
                if key in all_information and len(value) < len(all_information[key]):
                    continue
                all_information[key] = value

        self.information = Information(self, all_information)

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self, exc_type: type[BaseException] | None, exc_value: BaseException | None, traceback: TracebackType | None
    ) -> None:
        self.close()

    def segment(self, idx: int | str) -> Segment:
        """Open a segment by index or URI.

        Implements a simple LRU cache to limit the number of open segments.

        Args:
            idx: Index or URI of the segment to open.

        Returns:
            The opened :class:`Segment` object.
        """
        if isinstance(idx, str):
            idx = self._segment_map[idx]

        # Poor mans LRU
        if idx in self._segments:
            self._segment_lru.remove(idx)
            self._segment_lru.append(idx)
            return self._segments[idx]

        if len(self._segment_lru) >= MAX_OPEN_SEGMENTS:
            oldest_idx = self._segment_lru.pop(0)
            oldest_segment = self._segments.pop(oldest_idx)

            # Only close file handles that we opened ourselves
            if isinstance(self.fh[oldest_idx], Path) and self.fh[oldest_idx].is_file():
                oldest_segment.fh.close()

            del oldest_segment

        fh = self.fh[idx]
        if isinstance(fh, Path) and fh.is_file():
            fh = fh.open("rb")

        segment = Segment(self, fh)

        self._segments[idx] = segment
        self._segment_lru.append(idx)

        return segment

    def images(self) -> list[Image]:
        """List all images in the AFF4 evidence."""
        return list(self.information.find("Image"))

    def files(self) -> list[FileImage]:
        """List all file images in the AFF4 evidence."""
        return list(self.information.find("FileImage"))

    def close(self) -> None:
        """Close all segment file handles that we opened ourselves and clear the segment cache."""
        for idx, segment in self._segments.items():
            if isinstance(self.fh[idx], Path) and self.fh[idx].is_file():
                segment.fh.close()

        self._segments = {}
        self._segment_lru = []


class Segment:
    """AFF4 segment.

    Args:
        aff4: The parent :class:`AFF4` object.
        fh: A file-like object or ``pathlib.Path`` representing the segment.
    """

    def __init__(self, aff4: AFF4, fh: BinaryIO | pathlib.Path):
        self.aff4 = aff4
        self.fh = fh
        self._zip = None

        if not isinstance(fh, Path):
            self._zip = zipfile.ZipFile(self.fh)
            self.path = zipfile.Path(self._zip)
        else:
            self.path = fh

    @cached_property
    def uri(self) -> str:
        """Return the URI of the segment."""
        if (path := self.path.joinpath("container.description")).exists():
            return path.read_text()

        if self._zip and self._zip.comment:
            return self._zip.comment.split(b"\x00", 1).decode()

        raise ValueError("No URI found in segment")

    @cached_property
    def version(self) -> dict[str, str]:
        """Return the version information of the segment."""
        if not (path := self.path.joinpath("version.txt")).exists():
            raise ValueError("No version.txt found in segment")

        result = {}
        with path.open("rt") as fh:
            for line in fh:
                if "=" in line:
                    key, _, value = line.strip().partition("=")
                    result[key] = value

        return result

    @cached_property
    def information(self) -> dict[str, ValueType]:
        """Return the parsed ``information.turtle`` of the segment."""
        if not (path := self.path.joinpath("information.turtle")).exists():
            raise ValueError("No information.turtle found in segment")

        with path.open("rt") as fh:
            return parse_turtle(fh)

    def get(self, path: str) -> pathlib.Path | zipfile.Path:
        """Resolve a path of a file in the segment.

        Args:
            path: Path to the file in the segment.

        Returns:
            A :class:`Path` or :class:`zipfile.Path` object representing the file.
        """
        if path.startswith(self.uri):
            path = path.removeprefix(self.uri)
        else:
            # Encode the IRI to its zip member name. The scheme and authority are percent-encoded
            # (e.g. ``aff4://`` -> ``aff4%3A%2F%2F``), but path separators are kept intact.
            parsed = urllib.parse.urlsplit(path)
            if parsed.netloc:
                path = urllib.parse.quote_plus(f"{parsed.scheme}://{parsed.netloc}") + parsed.path
            else:
                path = urllib.parse.quote_plus(path)
        return self.path.joinpath(path)
