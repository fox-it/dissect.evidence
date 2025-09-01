from __future__ import annotations

from pathlib import Path
from typing import BinaryIO

from dissect.evidence.adcrypt.c_adcrypt import c_adcrypt

try:
    from Crypto import Hash
    from Crypto.Cipher import AES, PKCS1_v1_5
    from Crypto.Hash import HMAC
    from Crypto.Protocol.KDF import PBKDF2
    from Crypto.PublicKey import RSA
    from Crypto.Util import Counter

    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False


class ADCrypt:
    """Access Data ADCRYPT encrypted container implementation.

    References:
        - Reversing adencrypt.dll
        - https://github.com/libyal/libewf/blob/main/documentation/Expert%20Witness%20Compression%20Format%20(EWF).asciidoc#7-ad-encryption
        - https://github.com/log2timeline/plaso/issues/2726#issuecomment-517444736
    """

    def __init__(self, fhs: BinaryIO | list[BinaryIO]):
        self.fhs = fhs if isinstance(fhs, list) else [fhs]
        self.segments: list[ADCryptSegment] = []

        try:
            self.header: c_adcrypt.Header = c_adcrypt.Header(self.fhs[0])
        except EOFError:
            raise ValueError("File handle is not an ADCRYPT container: Unable to read ADCRYPT header")

        if self.header.magic != c_adcrypt.ADCRYPT_MAGIC.encode():
            raise ValueError(f"File handle is not an ADCRYPT container: Unknown magic {self.header.magic!r}")

        if self.header.version != 1:
            raise ValueError(f"Unsupported ADCRYPT container version {self.header.version!r}")

        for i, fh in enumerate(self.fhs):
            self.segments.append(ADCryptSegment(fh, i))
            # TODO: We should probably create a mapping stream.

    def decrypt(self, *, passphrase: str | bytes | None = None, private_key: Path | BinaryIO | None = None) -> None:
        """Attempt to decrypt all ADCRYPT segment files.

        Raises:
            ImportError if dependencies are missing.
            ValueError if decryption failed.
        """

        if not HAS_CRYPTO:
            raise ImportError("Missing required dependency 'pycryptodome' for ADCRYPT decryption.")

        if all(segment.decrypted for segment in self.segments):
            return

        if not private_key and isinstance(passphrase, str):
            passphrase = passphrase.encode()

        # If a private key was used, the passphrase is empty.
        passphrase_hash = b""

        if passphrase and not private_key:
            hash = Hash.new(self.header.hash_algo.name)
            hash.update(passphrase)
            passphrase_hash = hash.digest()

        # If no private key was used, the "encrypted" salt is the plaintext salt as-is.
        salt = self.header.enc_salt

        # Decrypt the salt if a private key was provided.
        if private_key:
            rsa_key = RSA.import_key(
                private_key.read_bytes() if isinstance(private_key, Path) else private_key, passphrase
            )
            pkcs_cipher = PKCS1_v1_5.new(rsa_key)
            if not (salt := pkcs_cipher.decrypt(self.header.enc_salt, sentinel=None, expected_pt_len=16)):
                raise ValueError("Failed to decrypt salt using provided private key")

        key_len = self.header.key_len
        count = self.header.pbkdf2_count
        pkey = PBKDF2(passphrase_hash, salt, key_len, count)

        # Verify the HMAC of EKEY using PKEY + hash algo, comparing with header HMAC
        hmac = HMAC.new(pkey, digestmod=Hash.new(self.header.hash_algo.name))
        hmac.update(self.header.enc_key)
        try:
            hmac.verify(self.header.hmac_enc_key)
        except ValueError as e:
            raise ValueError("Unable to decrypt: HMAC verification of passphrase failed") from e

        # Decrypt EKEY using PKEY
        # TODO: Set counter bit length according to EncAlgo
        ctr = Counter.new(128, initial_value=0, little_endian=True)
        cipher = AES.new(pkey, AES.MODE_CTR, counter=ctr)
        fkey = cipher.decrypt(self.header.enc_key)
        self.key = fkey

        for segment in self.segments:
            segment.decrypt(self.key)


class ADCryptSegment:
    def __init__(self, fh: BinaryIO, index: int):
        self.index = index
        self.fh = fh
        self.decrypted = False

    def __repr__(self) -> str:
        return f"<ADCryptSegment index={self.index!r} decrypted={self.decrypted!r}>"

    def decrypt(self, fkey: bytes) -> None:
        """Prepare this segment for decrypted reading."""

        if self.decrypted:
            return

        # TODO: Set counter bit length according to EncAlgo
        ctr = Counter.new(128, initial_value=self.index << 64, little_endian=True)
        cipher = AES.new(fkey, AES.MODE_CTR, counter=ctr)

        # Offset for ADCRYPT header in first segment.
        # TODO: We should use the header size as offset, it could be different than 512.
        if self.index == 0:
            self.fh.seek(512)

        self.key = fkey
        self._cipher = cipher
        self.decrypted = True

        # TODO: Check for plaintext headers, e.g. b"ADSEGMENTEDFILE", b"ADLOGICALIMAGE", b"EVF\x09\x0d\x0a\xff\x00"
        # and b"LVF\x09\x0d\x0a\xff\x00".

    def read(self, blocks: int | None = None) -> bytes:
        # TODO: Since AES CTR mode is used, we can seek to an offset of the ciphertext and calculate the counter value
        # based on the offset (random block read).
        return self._cipher.decrypt(self.fh.read(blocks * 16 if blocks else None))
