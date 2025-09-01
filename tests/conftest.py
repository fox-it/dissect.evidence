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
def ad1_data() -> Iterator[BinaryIO]:
    yield from open_data("_data/ad1/test.ad1")


@pytest.fixture
def ad1_data_long() -> Iterator[BinaryIO]:
    yield from open_data("_data/ad1/long.ad1")


@pytest.fixture
def ad1_data_compressed() -> Iterator[BinaryIO]:
    yield from open_data("_data/ad1/compressed.ad1")


@pytest.fixture
def ad1_data_segmented() -> list[BinaryIO]:
    return [
        absolute_path("_data/ad1/pcbje/text-and-pictures.ad1").open("rb"),
        absolute_path("_data/ad1/pcbje/text-and-pictures.ad2").open("rb"),
        absolute_path("_data/ad1/pcbje/text-and-pictures.ad3").open("rb"),
        absolute_path("_data/ad1/pcbje/text-and-pictures.ad4").open("rb"),
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
