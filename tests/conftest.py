from __future__ import annotations

from io import BytesIO
from pathlib import Path
from typing import TYPE_CHECKING, BinaryIO

import pytest

from dissect.evidence.asdf import AsdfWriter
from tests._utils import absolute_path

if TYPE_CHECKING:
    from collections.abc import Iterator


def open_data(name: str) -> Iterator[BinaryIO]:
    with (Path(__file__).parent / name).open("rb") as fh:
        yield fh


@pytest.fixture
def ad1_basic() -> Iterator[BinaryIO]:
    yield from open_data("_data/ad1/test.ad1")


@pytest.fixture
def ad1_long() -> Iterator[BinaryIO]:
    yield from open_data("_data/ad1/long.ad1")


@pytest.fixture
def ad1_compressed() -> Iterator[BinaryIO]:
    yield from open_data("_data/ad1/compressed.ad1")


@pytest.fixture
def ad1_segmented() -> list[Path]:
    return [
        absolute_path("_data/ad1/pcbje/text-and-pictures.ad1"),
        absolute_path("_data/ad1/pcbje/text-and-pictures.ad2"),
        absolute_path("_data/ad1/pcbje/text-and-pictures.ad3"),
        absolute_path("_data/ad1/pcbje/text-and-pictures.ad4"),
    ]


@pytest.fixture
def ad1_encrypted_passphrase() -> list[Path]:
    return [
        absolute_path("_data/ad1/encrypted-passphrase/encrypted.ad1"),
        absolute_path("_data/ad1/encrypted-passphrase/encrypted.ad2"),
        absolute_path("_data/ad1/encrypted-passphrase/encrypted.ad3"),
        absolute_path("_data/ad1/encrypted-passphrase/encrypted.ad4"),
        absolute_path("_data/ad1/encrypted-passphrase/encrypted.ad5"),
        absolute_path("_data/ad1/encrypted-passphrase/encrypted.ad6"),
        absolute_path("_data/ad1/encrypted-passphrase/encrypted.ad7"),
        absolute_path("_data/ad1/encrypted-passphrase/encrypted.ad8"),
        absolute_path("_data/ad1/encrypted-passphrase/encrypted.ad9"),
        absolute_path("_data/ad1/encrypted-passphrase/encrypted.ad10"),
        absolute_path("_data/ad1/encrypted-passphrase/encrypted.ad11"),
        absolute_path("_data/ad1/encrypted-passphrase/encrypted.ad12"),
        absolute_path("_data/ad1/encrypted-passphrase/encrypted.ad13"),
    ]


@pytest.fixture
def ad1_encrypted_certificate() -> list[Path]:
    return [
        absolute_path("_data/ad1/encrypted-certificate/encrypted.ad1"),
        absolute_path("_data/ad1/encrypted-certificate/encrypted.ad2"),
        absolute_path("_data/ad1/encrypted-certificate/encrypted.ad3"),
        absolute_path("_data/ad1/encrypted-certificate/encrypted.ad4"),
        absolute_path("_data/ad1/encrypted-certificate/encrypted.ad5"),
        absolute_path("_data/ad1/encrypted-certificate/encrypted.ad6"),
        absolute_path("_data/ad1/encrypted-certificate/encrypted.ad7"),
    ]


@pytest.fixture
def ewf_data() -> Iterator[BinaryIO]:
    yield from open_data("_data/ewf/ewf.E01")


@pytest.fixture
def asdf_writer() -> AsdfWriter:
    def noop() -> None:
        pass

    fh = BytesIO()
    fh.close = noop  # Prevent clearing the buffer, we need it
    return AsdfWriter(fh)
