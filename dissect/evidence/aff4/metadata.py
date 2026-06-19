from __future__ import annotations

import datetime
import struct
from typing import TYPE_CHECKING, ClassVar, TypeAlias

from dissect.util.stream import BufferedStream

from dissect.evidence.aff4.stream import BevyStream, MapStream
from dissect.evidence.aff4.util import NS_AFF4, NS_RDF, CompressionMethod

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.evidence.aff4.aff4 import AFF4


ValueType: TypeAlias = str | int | bool | datetime.datetime | bytes | list["ValueType"]


class Information:
    """AFF4 information container.

    Used for accessing AFF4 objects.

    Args:
        aff4: The parent :class:`AFF4` object.
        objects: A dictionary mapping object IDs to their property dictionaries.
    """

    def __init__(self, aff4: AFF4, objects: dict[str, dict[str, str]]):
        self.aff4 = aff4
        self.objects = {id: Object.from_values(self, id, values) for id, values in objects.items()}

        # Register some constants globally
        for value in CompressionMethod:
            self.objects[value.value] = value

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} objects={len(self.objects)}>"

    def get(self, id: str) -> Object | None:
        """Get an object by ID."""
        return self.objects.get(id)

    def find(self, type: str) -> Iterator[Object]:
        """Find all objects of a given type."""
        search_type = f"{NS_AFF4}{type}"
        for obj in self.objects.values():
            if isinstance(obj, Object) and (
                (isinstance(obj.type, str) and obj.type == search_type)
                or (isinstance(obj.type, list) and search_type in obj.type)
            ):
                yield obj


class Object:
    """AFF4 object.

    Represents a generic AFF4 object.

    Args:
        ctx: The parent :class:`Information` object.
        id: The ID of the object.
        values: A dictionary mapping predicates to their values.
    """

    __type__ = None
    __types__: ClassVar[dict[str, type[Object]]] = {}

    def __init_subclass__(cls):
        if cls.__type__ is not None:
            cls.__types__[cls.__type__] = cls

    def __init__(self, ctx: Information, id: str, values: dict[str, str]):
        self.ctx = ctx
        self.id = id
        self.values = values

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} {self.id} type={self.type!r}>"

    def __getitem__(self, key: str) -> ValueType:
        if (result := self.get(key)) is None:
            raise KeyError(key)
        return result

    @classmethod
    def from_values(cls, ctx: Information, id: str, values: dict[str, str]) -> Object:
        """Create an object from its values, instantiating the appropriate subclass based on its type."""
        if type := values.get(f"{NS_RDF}type"):
            if isinstance(type, str):
                type = [type]

            subcls = cls
            for t in type:
                if t in cls.__types__ and len(cls.__types__[t].__mro__) > len(subcls.__mro__):
                    subcls = cls.__types__[t]
            return subcls(ctx, id, values)
        return cls(ctx, id, values)

    @property
    def type(self) -> str | list[str] | None:
        """Return the RDF type of the object."""
        return self.values.get(f"{NS_RDF}type")

    def _transform_value(self, value: ValueType) -> ValueType | Object | None:
        """Transform a value into an ``Object`` if it's a reference."""
        if isinstance(value, str) and value.startswith("<") and value.endswith(">"):
            value = value[1:-1]
            return self.ctx.get(value) or UnresolvedObject(self.ctx, value, {})
        return value

    def get(self, predicate: str, *, prefix: str = NS_AFF4) -> ValueType | None:
        """Get a property of the object."""
        if (result := self.values.get(f"{prefix}{predicate}")) is not None:
            if isinstance(result, list):
                result = [self._transform_value(r) for r in result]
            result = self._transform_value(result)
        return result


class UnresolvedObject(Object):
    """AFF4 unresolved object.

    Represents an object that could not be resolved from the AFF4 information.
    """

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} {self.id}>"

    def get(self, predicate: str, prefix: str = NS_AFF4) -> ValueType | None:
        raise ValueError(f"Cannot get property {predicate} of unresolved object {self.id}")


class Map(Object):
    """AFF4 Map object."""

    __type__ = f"{NS_AFF4}Map"

    _ENTRY = struct.Struct("<QQQI")

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} {self.id} size={self.size}>"

    @property
    def size(self) -> int:
        """Return the size of the mapped stream."""
        return self["size"]

    @property
    def map_gap_default_stream(self) -> str:
        """Return the default gap stream type, defaulting to the ``Zero`` symbolic stream."""
        return self.get("mapGapDefaultStream") or f"{NS_AFF4}Zero"

    @property
    def dependent_stream(self) -> ImageStream | list[ImageStream]:
        """Return the dependent stream(s)."""
        return self["dependentStream"]

    @property
    def target(self) -> Object:
        """Return the target (parent) object."""
        return self["target"]

    @property
    def stored(self) -> Object:
        """Return the volume the stream is stored in."""
        return self["stored"]

    @property
    def index(self) -> list[str]:
        """Return the list of stream IDs in the map index."""
        segment = self.ctx.aff4.segment(self.stored.id)
        return segment.get(self.id).joinpath("idx").read_text().splitlines()

    @property
    def map(self) -> dict[int, tuple[int, int, int, int]]:
        """Return the mapping of the stream."""
        segment = self.ctx.aff4.segment(self.stored.id)

        result = {}
        with segment.get(self.id).joinpath("map").open("rb") as fh:
            while buf := fh.read(self._ENTRY.size):
                mapped, length, target, idx = self._ENTRY.unpack(buf)
                result[mapped + length] = (mapped, length, target, idx)

        return result

    def open(self) -> MapStream:
        """Open the mapped stream for reading."""
        return MapStream(self)


class ImageStream(Object):
    """AFF4 ImageStream object."""

    __type__ = f"{NS_AFF4}ImageStream"

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} {self.id} target={self.target.id} stored={self.stored.id}>"

    @property
    def chunk_size(self) -> int:
        """Return the chunk size of the image stream."""
        return self["chunkSize"]

    @property
    def chunks_in_segment(self) -> int:
        """Return the number of chunks in each segment."""
        return self["chunksInSegment"]

    @property
    def compression_method(self) -> CompressionMethod:
        """Return the compression method of the image stream."""
        return self["compressionMethod"]

    @property
    def size(self) -> int:
        """Return the size of the image stream."""
        return self["size"]

    @property
    def target(self) -> Object:
        """Return the target (parent) object."""
        return self["target"]

    @property
    def stored(self) -> Object:
        """Return the volume the stream is stored in."""
        return self["stored"]

    def open(self) -> BevyStream:
        """Open the image stream for reading."""
        return BevyStream(self)


class Image(Object):
    """AFF4 Image object."""

    __type__ = f"{NS_AFF4}Image"

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} {self.id} hash={self.get('hash')}>"

    @property
    def hash(self) -> str | list[str]:
        """Return the hash(es) of the image."""
        return self["hash"]

    @property
    def size(self) -> int:
        """Return the size of the image."""
        return self["size"]

    @property
    def block_size(self) -> int:
        """Return the block size of the image."""
        return self["blockSize"]


class ContiguousImage(Image):
    """AFF4 ContiguousImage object."""

    __type__ = f"{NS_AFF4}ContiguousImage"

    @property
    def data_stream(self) -> Map | ImageStream:
        """Return the data stream of the image."""
        return self["dataStream"]

    def open(self) -> BufferedStream:
        """Open the image for reading."""
        return BufferedStream(self.data_stream.open(), size=self.size)


class DiscontiguousImage(ContiguousImage):
    """AFF4 DiscontiguousImage object.

    A sparse image whose ``dataStream`` is typically a :class:`Map`, mapping populated regions to
    underlying streams and filling the gaps with the map's default gap stream.
    """

    __type__ = f"{NS_AFF4}DiscontiguousImage"


class DiskImage(ContiguousImage):
    """AFF4 DiskImage object."""

    __type__ = f"{NS_AFF4}DiskImage"


class FileImage(Image):
    """AFF4 FileImage object."""

    __type__ = f"{NS_AFF4}FileImage"

    @property
    def birth_time(self) -> datetime.datetime:
        """Return the birth time of the file."""
        return self["birthTime"]

    @property
    def last_accessed(self) -> datetime.datetime:
        """Return the last accessed time of the file."""
        return self["lastAccessed"]

    @property
    def last_written(self) -> datetime.datetime:
        """Return the last written time of the file."""
        return self["lastWritten"]

    @property
    def record_changed(self) -> datetime.datetime:
        """Return the record changed time of the file."""
        return self["recordChanged"]

    @property
    def original_file_name(self) -> str:
        """Return the original file name of the file."""
        return self["originalFileName"]

    @property
    def stored(self) -> Object:
        """Return the volume the file is stored in."""
        return self["stored"]


class ZipVolume(Object):
    """AFF4 ZipVolume object."""

    __type__ = f"{NS_AFF4}ZipVolume"

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} {self.id} creation_time={self.creation_time}>"

    @property
    def contains(self) -> list[Object]:
        """Return the contained objects."""
        return self["contains"]

    @property
    def creation_time(self) -> datetime.datetime:
        """Return the creation time of the volume."""
        return self["creationTime"]

    @property
    def interface(self) -> str:
        """Return the interface of the volume."""
        return self["interface"]

    @property
    def stored(self) -> str:
        """Return the storage location of the volume."""
        return self["stored"]


class CaseDetails(Object):
    """AFF4 CaseDetails object."""

    __type__ = f"{NS_AFF4}CaseDetails"

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} {self.id} case_name={self.case_name!r}>"

    @property
    def case_description(self) -> str:
        """Return the case description."""
        return self["caseDescription"]

    @property
    def case_name(self) -> str:
        """Return the case name."""
        return self["caseName"]

    @property
    def examiner(self) -> str:
        """Return the examiner name."""
        return self["examiner"]

    @property
    def stored(self) -> Object:
        """Return the storage location of the case details."""
        return self["stored"]

    @property
    def target(self) -> Object:
        """Return the target (parent) object."""
        return self["target"]


class CaseNotes(Object):
    """AFF4 CaseNotes object."""

    __type__ = f"{NS_AFF4}CaseNotes"

    def __repr__(self) -> str:
        return (
            f"<{self.__class__.__name__} {self.id} "
            f"case_number={self.case_number!r} evidence_number={self.evidence_number!r}>"
        )

    @property
    def case_number(self) -> str:
        """Return the case number."""
        return self["caseNumber"]

    @property
    def evidence_number(self) -> str:
        """Return the evidence number."""
        return self["evidenceNumber"]

    @property
    def examiner(self) -> str:
        """Return the examiner name."""
        return self["examiner"]

    @property
    def notes(self) -> str:
        """Return the case notes."""
        return self["notes"]

    @property
    def timestamp(self) -> datetime.datetime:
        """Return the timestamp of the case notes."""
        return self["timestamp"]

    @property
    def stored(self) -> Object:
        """Return the storage location of the case notes."""
        return self["stored"]

    @property
    def target(self) -> Object:
        """Return the target (parent) object."""
        return self["target"]


class TimeStamps(Object):
    """AFF4 TimeStamps object."""

    __type__ = f"{NS_AFF4}TimeStamps"

    def __repr__(self) -> str:
        return (
            f"<{self.__class__.__name__} {self.id} "
            f"operation={self.operation!r} start_time={self.start_time} end_time={self.end_time}>"
        )

    @property
    def start_time(self) -> datetime.datetime:
        """Return the start time of the operation."""
        return self["startTime"]

    @property
    def end_time(self) -> datetime.datetime:
        """Return the end time of the operation."""
        return self["endTime"]

    @property
    def operation(self) -> str:
        """Return the operation performed."""
        return self["operation"]

    @property
    def stored(self) -> Object:
        """Return the storage location of the timestamps."""
        return self["stored"]

    @property
    def target(self) -> Object:
        """Return the target (parent) object."""
        return self["target"]
