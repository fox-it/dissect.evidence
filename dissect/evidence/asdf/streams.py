import hashlib
import io
import struct
from typing import BinaryIO
from zlib import compressobj, crc32


class SubStreamBase(io.RawIOBase):
    """Convenience class for easy sub stream subclassing.

    Additionally adds the `finalize` method.

    Args:
        fh: The file-like object to wrap.
    """

    def __init__(self, fh: BinaryIO):
        self.fh = fh

    def write(self, b: bytes) -> int:
        return self.fh.write(b)

    def tell(self) -> int:
        return self.fh.tell()

    def seek(self, pos: int, whence: int = io.SEEK_CUR) -> int:
        return self.fh.seek(pos, whence)

    def close(self) -> None:
        super().close()

    def finalize(self) -> None:
        self.fh.flush()
        if hasattr(self.fh, "finalize"):
            self.fh.finalize()


class Crc32Stream(SubStreamBase):
    """Compute a CRC32 over all written data.

    This assumes that all data is written as a continuous stream.

    Args:
        fh: The file-like object to wrap.
    """

    def __init__(self, fh: BinaryIO):
        super().__init__(fh)
        self.crc = 0

    def write(self, b: bytes) -> int:
        self.crc = crc32(b, self.crc) & 0xFFFFFFFF
        return self.fh.write(b)

    def digest(self) -> bytes:
        return struct.pack("<I", self.crc)

    def finalize(self) -> None:
        self.fh.write(self.digest())
        super().finalize()


class HashedStream(SubStreamBase):
    """Compute a hash over all written data.

    This assumes that all data is written as a continuous stream.

    Args:
        fh: The file-like object to wrap.
        alg: The hashing algorithm to use. Must be supported by hashlib.
    """

    def __init__(self, fh: BinaryIO, alg: str = "sha256"):
        super().__init__(fh)
        self.ctx = hashlib.new(alg)

    def write(self, b: bytes) -> int:
        self.ctx.update(b)
        return self.fh.write(b)

    def digest(self) -> bytes:
        return self.ctx.digest()

    def hexdigest(self) -> str:
        return self.ctx.hexdigest()

    def close(self) -> None:
        super().close()
        self.fh.close()


class CompressedStream(SubStreamBase):
    """Compress data as it's being written.

    This assumes that all data is written as a continuous stream.

    Args:
        fh: The file-like object to wrap.
    """

    def __init__(self, fh: BinaryIO):
        super().__init__(fh)
        self.cobj = compressobj()

    def write(self, b: bytes) -> int:
        return self.fh.write(self.cobj.compress(b))

    def finalize(self) -> None:
        self.fh.write(self.cobj.flush())
        super().finalize()
