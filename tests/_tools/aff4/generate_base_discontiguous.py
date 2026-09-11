"""Generate a minimal sparse (discontiguous) AFF4 fixture: ``Base-Discontiguous.aff4``.

This fixture borrows only the *structure* of a real AFF4 APFS container image (the kind produced
for sparse/APFS physical images): a ``bbt:APFSContainerImage`` (a ``DiscontiguousImage``) whose
``dataStream`` is a ``Map`` that maps a populated region onto a bevy ``ImageStream`` and fills the
gaps with the ``Zero`` symbolic stream. It carries the vendor (BlackBag) ``bbt:`` metadata too.

Every value here is synthetic. The UUIDs were generated once and hardcoded below, the sizes are
arbitrary, the data block is a deterministic pattern, and all hashes derive solely from that pattern.
There are no references to any real evidence file.

Layout (image size 65536):

    [0, 32768)      sparse gap  -> Zero symbolic stream
    [32768, 65536)  populated   -> chunk 0 of the bevy ImageStream

The single map entry ends exactly at the image size, so no read can run past the final map entry.
The chunk is stored uncompressed: the bevy reader returns a chunk verbatim when its stored size
equals ``chunkSize``, so we can declare lz4 compression without needing a compressor.

Run this script to (re)create ``Base-Discontiguous.aff4`` next to it.
"""

# This is a standalone fixture generator living in the test-data tree, not an importable package.
# ruff: noqa: INP001

from __future__ import annotations

import hashlib
import struct
import urllib.parse
import zipfile
from pathlib import Path

# Freshly generated random UUIDs (hardcoded once); no relation to any real image.
VOLUME_UUID = "01f7d819-cda3-4e70-b0d0-df3d75b13e1e"
MAP_UUID = "ec9769e3-04e9-4798-b023-adee1d87b890"  # ImageStream id = MAP_UUID + "/data"
IMAGE_UUID = "70a85032-8ea0-460c-8de9-43bdc7df538b"

CHUNK_SIZE = 32768
CHUNKS_IN_SEGMENT = 1024
BLOCK_SIZE = 4096
IMAGE_SIZE = 65536
DATA_OFFSET = 32768  # logical offset of the populated block

VOLUME_URI = f"aff4://{VOLUME_UUID}"
MAP_URI = f"aff4://{MAP_UUID}"
STREAM_URI = f"{MAP_URI}/data"
IMAGE_URI = f"aff4://{IMAGE_UUID}"

# Deterministic, synthetic content for the single populated chunk, and its hashes. The ImageStream
# is exactly one chunk, so its aff4:hash is taken over this content.
CHUNK = bytes((i * 7 + 0x42) & 0xFF for i in range(CHUNK_SIZE))
STREAM_SHA1 = hashlib.sha1(CHUNK).hexdigest()
STREAM_MD5 = hashlib.md5(CHUNK).hexdigest()

INFORMATION_TURTLE = f"""@base <{VOLUME_URI}> .
@prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .
@prefix aff4: <http://aff4.org/Schema#> .
@prefix xsd: <http://www.w3.org/2001/XMLSchema#> .
@prefix bbt: <https://blackbagtech.com/aff4/Schema#> .

<{MAP_URI}>
    aff4:size {IMAGE_SIZE} ;
    aff4:stored <> ;
    a aff4:Map .

<{STREAM_URI}>
    aff4:chunkSize {CHUNK_SIZE} ;
    aff4:chunksInSegment {CHUNKS_IN_SEGMENT} ;
    aff4:compressionMethod <https://code.google.com/p/lz4/> ;
    aff4:hash "{STREAM_SHA1}"^^aff4:SHA1, "{STREAM_MD5}"^^aff4:MD5 ;
    aff4:size {CHUNK_SIZE} ;
    aff4:stored <> ;
    a aff4:ImageStream .

<{IMAGE_URI}>
    aff4:blockSize {BLOCK_SIZE} ;
    aff4:dataStream <{MAP_URI}> ;
    aff4:size {IMAGE_SIZE} ;
    a aff4:DiscontiguousImage, aff4:Image, bbt:APFSContainerImage ;
    bbt:APFSContainerType bbt:APFST2ContainerType ;
    bbt:ContainsExtents true ;
    bbt:ContainsUnallocated true ;
    bbt:integrityStream <{STREAM_URI}> .
"""


def member_name(uri: str) -> str:
    """Encode an AFF4 IRI to its zip member name, matching ``Segment.get``."""
    parsed = urllib.parse.urlsplit(uri)
    if parsed.netloc:
        return urllib.parse.quote_plus(f"{parsed.scheme}://{parsed.netloc}") + parsed.path
    return urllib.parse.quote_plus(uri)


def build(path: Path) -> None:
    # Map entry: (mapped_offset, length, target_offset, stream_idx). Stream 0 is the ImageStream.
    map_entry = struct.pack("<QQQI", DATA_OFFSET, CHUNK_SIZE, 0, 0)
    # Bevy index entry: (offset, size). size == chunkSize -> stored raw, returned verbatim.
    bevy_index = struct.pack("<QI", 0, CHUNK_SIZE)

    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_STORED) as zf:
        zf.comment = VOLUME_URI.encode()
        zf.writestr("container.description", VOLUME_URI)
        zf.writestr("version.txt", "major=1\nminor=0\ntool=dissect.evidence test fixture\n")
        zf.writestr("information.turtle", INFORMATION_TURTLE)
        zf.writestr(f"{member_name(MAP_URI)}/idx", f"{STREAM_URI}\n")
        zf.writestr(f"{member_name(MAP_URI)}/map", map_entry)
        zf.writestr(f"{member_name(STREAM_URI)}/00000000", CHUNK)
        zf.writestr(f"{member_name(STREAM_URI)}/00000000.index", bevy_index)


if __name__ == "__main__":
    out = Path(__file__).with_name("Base-Discontiguous.aff4")
    build(out)
    print(f"Wrote {out}")
