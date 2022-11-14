import os
from io import BytesIO

import pytest

from dissect.evidence.asdf import AsdfWriter


def open_data(name):
    return open(os.path.join(os.path.dirname(__file__), name), "rb")


@pytest.fixture
def ad1_data():
    return open_data("data/ad1_test.ad1")


@pytest.fixture
def ad1_data_long():
    return open_data("data/ad1_long.ad1")


@pytest.fixture
def ad1_data_compressed():
    return open_data("data/ad1_test_compressed.ad1")


@pytest.fixture
def ewf_data():
    return open_data("data/ewf.E01")


@pytest.fixture
def asdf_writer():
    def noop():
        pass

    fh = BytesIO()
    fh.close = noop  # Prevent clearing the buffer, we need it
    yield AsdfWriter(fh)
