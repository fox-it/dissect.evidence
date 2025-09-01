from __future__ import annotations

from typing import BinaryIO

from dissect.evidence.adcrypt.adcrypt import ADCrypt
from tests._utils import absolute_path


def test_adcrypt_ad1_passphrase(ad1_data_encrypted_passphrase: list[BinaryIO]) -> None:
    """Test if we can decrypt ADCRYPT AD1 images, in this example a segmented AD1 logical image."""

    adcrypt = ADCrypt(ad1_data_encrypted_passphrase)
    adcrypt.decrypt(passphrase="password")

    assert adcrypt.key.hex() == "9030a43f29689a045e815cf4f0ad82b68850063b414f2797f0897e188f98d7b4"
    assert all(segment.decrypted for segment in adcrypt.segments)

    plain = adcrypt.segments[0].read(512)
    assert plain.startswith(b"ADSEGMENTEDFILE")
    assert b"ADLOGICALIMAGE" in plain


def test_adcrypt_ad1_certificate(ad1_data_encrypted_certificate: list[BinaryIO]) -> None:
    """Test if we can decrypt ADCRYPT AD1 images, in this example a segmented AD1 logical image."""

    adcrypt = ADCrypt(ad1_data_encrypted_certificate)
    adcrypt.decrypt(private_key=absolute_path("_data/ad1/encrypted-certificate/key"))

    assert adcrypt.key.hex() == "6cc0a9f94f944381cc51be474e5da6178059324bb457a87e0035b80f80ff9d4b"
    assert all(segment.decrypted for segment in adcrypt.segments)

    plain = adcrypt.segments[0].read(512)
    assert plain.startswith(b"ADSEGMENTEDFILE")
    assert b"ADLOGICALIMAGE" in plain
