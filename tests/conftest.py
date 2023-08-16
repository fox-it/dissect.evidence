import os
from io import BytesIO
from typing import BinaryIO, Iterator

import pytest

from dissect.evidence.asdf import AsdfWriter


def open_data(name: str) -> BinaryIO:
    return open(os.path.join(os.path.dirname(__file__), name), "rb")


@pytest.fixture
def ad1_data() -> BinaryIO:
    return open_data("data/ad1_test.ad1")


@pytest.fixture
def ad1_data_long() -> BinaryIO:
    return open_data("data/ad1_long.ad1")


@pytest.fixture
def ad1_data_compressed() -> BinaryIO:
    return open_data("data/ad1_test_compressed.ad1")


@pytest.fixture
def ewf_data() -> BinaryIO:
    return open_data("data/ewf.E01")


@pytest.fixture
def asdf_writer() -> Iterator[AsdfWriter]:
    def noop():
        pass

    fh = BytesIO()
    fh.close = noop  # Prevent clearing the buffer, we need it
    yield AsdfWriter(fh)
