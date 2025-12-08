from __future__ import annotations

import io
from typing import BinaryIO

from dissect.util.stream import AlignedStream

try:
    from Crypto.Cipher import AES
    from Crypto.Util import Counter

    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False


class ADCryptStream(AlignedStream):
    def __init__(self, fh: BinaryIO, key: bytes, index: int):
        if not HAS_CRYPTO:
            raise RuntimeError("Missing required dependency 'pycryptodome' for ADCRYPT decryption")

        self.fh = fh
        self.key = key
        self.index = index

        self.fh.seek(0, io.SEEK_END)
        size = self.fh.tell() - (512 if index == 0 else 0)  # Skip ADCRYPT header
        super().__init__(size)

    def _read(self, offset: int, length: int) -> bytes:
        self.fh.seek(offset + (512 if self.index == 0 else 0))  # Skip ADCRYPT header
        buf = self.fh.read(length)

        ctr = Counter.new(
            128,
            initial_value=self.index << 64 | (offset // (128 // 8)),
            little_endian=True,
        )
        cipher = AES.new(self.key, AES.MODE_CTR, counter=ctr)
        return cipher.decrypt(buf)
