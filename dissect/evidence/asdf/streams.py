import hashlib
import io
from zlib import compressobj


class SubStreamBase(io.RawIOBase):
    """Convenience class for easy sub stream subclassing.

    Additionally adds the `finalize` method.

    Args:
        fh: The file-like object to wrap.
    """

    def __init__(self, fh):
        self.fh = fh

    def write(self, b):
        return self.fh.write(b)

    def tell(self):
        return self.fh.tell()

    def seek(self, pos, whence=io.SEEK_CUR):
        return self.fh.seek(pos, whence)

    def close(self):
        super().close()

    def finalize(self):
        self.fh.flush()


class HashedStream(SubStreamBase):
    """Compute a hash over all written data.

    This assumes that all data is written as a continuous stream.

    Args:
        fh: The file-like object to wrap.
        alg: The hashing algorithm to use. Must be supported by hashlib.
    """

    def __init__(self, fh, alg="sha256"):
        super().__init__(fh)
        self.ctx = hashlib.new(alg)

    def write(self, b):
        self.ctx.update(b)
        return self.fh.write(b)

    def digest(self):
        return self.ctx.digest()

    def hexdigest(self):
        return self.ctx.hexdigest()

    def close(self):
        super().close()
        self.fh.close()


class CompressedStream(SubStreamBase):
    """Compress data as it's being written.

    This assumes that all data is written as a continuous stream.

    Args:
        fh: The file-like object to wrap.
    """

    def __init__(self, fh):
        super().__init__(fh)
        self.cobj = compressobj()

    def write(self, b):
        return self.fh.write(self.cobj.compress(b))

    def finalize(self):
        self.fh.write(self.cobj.flush())
        self.fh.finalize()
