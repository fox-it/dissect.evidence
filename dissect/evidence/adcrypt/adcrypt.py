from __future__ import annotations

import hashlib
import hmac
from pathlib import Path
from typing import BinaryIO

from dissect.evidence.adcrypt.c_adcrypt import c_adcrypt
from dissect.evidence.adcrypt.stream import ADCryptStream

try:
    from Crypto.Cipher import AES, PKCS1_v1_5
    from Crypto.Protocol.KDF import PBKDF2
    from Crypto.PublicKey import RSA
    from Crypto.Util import Counter

    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False


def is_adcrypt(fh: BinaryIO) -> bool:
    """Check if the file handle is an ADCRYPT container.

    Args:
        fh: The file handle to check.
    """
    fh.seek(0)
    return fh.read(8) == c_adcrypt.ADCRYPT_MAGIC.encode()


class ADCrypt:
    """Access Data ADCRYPT encrypted container implementation.

    Not particularly useful on its own, but used by other evidence types such as AD1.
    Pass the first segment file handle to this class, then use :meth:`unlock` to unlock the container,
    and :meth:`wrap` to wrap other segment file handles into decrypting streams.

    References:
        - Reverse engineering ``adencrypt.dll``
        - https://github.com/libyal/libewf/blob/main/documentation/Expert%20Witness%20Compression%20Format%20(EWF).asciidoc#7-ad-encryption
        - https://github.com/log2timeline/plaso/issues/2726#issuecomment-517444736
    """

    def __init__(self, fh: BinaryIO) -> None:
        self.fh = fh
        self.fh.seek(0)

        try:
            self.header: c_adcrypt.Header = c_adcrypt.Header(self.fh)
        except EOFError:
            raise ValueError("File handle is not an ADCRYPT container: Unable to read ADCRYPT header")

        if self.header.magic != c_adcrypt.ADCRYPT_MAGIC.encode():
            raise ValueError(f"File handle is not an ADCRYPT container: Unknown magic {self.header.magic!r}")

        if self.header.version != 1:
            raise ValueError(f"Unsupported ADCRYPT container version {self.header.version!r}")

        self.key: bytes | None = None

    def is_locked(self) -> bool:
        """Return whether the ADCRYPT container is locked."""
        return self.key is None

    def unlock(self, *, passphrase: str | bytes | None = None, private_key: Path | bytes | None = None) -> None:
        """Unlock the ADCRYPT container with a given passphrase or private key.

        Args:
            passphrase: The passphrase to unlock the container.
            private_key: The private key to unlock the container.

        Raises:
            RuntimeError: If required dependencies are missing.
            ValueError: If unlocking failed.
        """
        if not HAS_CRYPTO:
            raise RuntimeError("Missing required dependency 'pycryptodome' for ADCRYPT decryption")

        pkey = adcrypt_kdf(
            passphrase,
            private_key,
            self.header.enc_salt,
            self.header.key_len,
            self.header.pbkdf2_count,
            self.header.hash_algo.name.lower(),
        )

        # Verify the HMAC of EKEY using PKEY + hash algo, comparing with header HMAC
        if hmac.digest(pkey, self.header.enc_key, self.header.hash_algo.name.lower()) != self.header.hmac_enc_key:
            raise ValueError("Unable to unlock: HMAC verification of passphrase failed")

        # Decrypt EKEY using PKEY
        ctr = Counter.new(128, initial_value=0, little_endian=True)
        cipher = AES.new(pkey, AES.MODE_CTR, counter=ctr)
        self.key = cipher.decrypt(self.header.enc_key)

    def wrap(self, fh: BinaryIO, index: int) -> ADCryptStream:
        """Wrap a file handle into an :class:`ADCryptStream` for decryption.

        Args:
            fh: The file handle to wrap.
            index: The segment index.

        Raises:
            ValueError: If the container is not unlocked.
        """
        if self.is_locked():
            raise ValueError("ADCRYPT container is not unlocked")

        return ADCryptStream(fh, self.key, index)


def adcrypt_kdf(
    passphrase: str | bytes | None,
    private_key: Path | bytes | None,
    salt: bytes,
    key_len: int,
    count: int,
    algorithm: str,
) -> bytes:
    """Derive the ADCRYPT decryption key.

    Args:
        passphrase: The passphrase to unlock the container.
        private_key: The private key to unlock the container.
        salt: The salt used for key derivation.
        key_len: The length of the derived key.
        count: The number of iterations for PBKDF2.
        algorithm: The hash algorithm to use.

    Returns:
        The derived key as bytes.
    """
    if isinstance(passphrase, str):
        passphrase = passphrase.encode()

    # If a private key was used, the passphrase is empty.
    passphrase_hash = b""
    if passphrase is not None and private_key is None:
        passphrase_hash = hashlib.new(algorithm, passphrase).digest()

    # If no private key was used, the "encrypted" salt is the plaintext salt as-is.
    derived_salt = salt

    # Decrypt the salt if a private key was provided.
    if private_key is not None:
        rsa_key = RSA.import_key(private_key.read_bytes() if isinstance(private_key, Path) else private_key, passphrase)
        if not (derived_salt := PKCS1_v1_5.new(rsa_key).decrypt(salt, sentinel=None, expected_pt_len=16)):
            raise ValueError("Failed to decrypt salt using provided private key")

    return PBKDF2(passphrase_hash, derived_salt, key_len, count)
