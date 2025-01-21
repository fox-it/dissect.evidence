from __future__ import annotations

from io import BytesIO
from pathlib import Path
from typing import TYPE_CHECKING, BinaryIO

import pytest

from dissect.evidence.asdf import AsdfWriter

if TYPE_CHECKING:
    from collections.abc import Iterator


def open_data(name: str) -> Iterator[BinaryIO]:
    with (Path(__file__).parent / name).open("rb") as fh:
        yield fh


@pytest.fixture
def ad1_data() -> Iterator[BinaryIO]:
    yield from open_data("data/ad1_test.ad1")


@pytest.fixture
def ad1_data_long() -> Iterator[BinaryIO]:
    yield from open_data("data/ad1_long.ad1")


@pytest.fixture
def ad1_data_compressed() -> Iterator[BinaryIO]:
    yield from open_data("data/ad1_test_compressed.ad1")


@pytest.fixture
def ewf_data() -> Iterator[BinaryIO]:
    yield from open_data("data/ewf.E01")


@pytest.fixture
def asdf_writer() -> AsdfWriter:
    def noop() -> None:
        pass

    fh = BytesIO()
    fh.close = noop  # Prevent clearing the buffer, we need it
    return AsdfWriter(fh)
