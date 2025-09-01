from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import BinaryIO

import pytest

from dissect.evidence import ad1
from dissect.evidence.ad1.ad1 import EntryType, MetaType, find_files
from tests._utils import absolute_path


def test_ad1(ad1_data: BinaryIO) -> None:
    """Test if we can parse a basic non-segmented AD1 file with no file hierarchy."""

    fs = ad1.AD1(ad1_data)
    assert fs.segments[0].header.magic == b"ADSEGMENTEDFILE\x00"

    assert fs.root.is_dir()
    assert list(fs.root.listdir()) == ["E:"]

    file = fs.get("E:/AD1_test/doc1.txt")
    assert file.is_file()
    assert file.size == 17
    assert file.atime == datetime(2017, 3, 31, 18, 2, 31, 189682, tzinfo=timezone.utc)
    assert file.open().read() == b"Inhoud document 1"


def test_ad1_long(ad1_data_long: BinaryIO) -> None:
    """Test if we can parse a basic non-segmented AD1 file with long file names."""

    fs = ad1.AD1(ad1_data_long)

    assert fs.segments[0].header.magic == b"ADSEGMENTEDFILE\x00"
    assert fs.root.is_dir()

    assert [file.name for file in fs.root.children] == ["E:"]

    assert [file.name for file in fs.get("E:").children] == [
        "testdatamap 2 met spaties en een heel stuk langer",
    ]

    assert [file.name for file in fs.get("E:/testdatamap 2 met spaties en een heel stuk langer").iterdir()] == [
        "een lange filenaam 1 met spaties.txt",
        "Een nog langere bestandsnaam met nog meer tekens en 12345.txt",
    ]

    entry = fs.get("E:/testdatamap 2 met spaties en een heel stuk langer").children[0]
    assert entry.name == "een lange filenaam 1 met spaties.txt"
    assert entry.open().read() == (
        b"masdhdslkfjasdfjlksadjflkjsda;lfj\r\nasdflk\r\na;lsdkf\r\n"
        b";lasdklf;lkasd\r\n;lk\r\nfask;ldkf\r\n;lka\r\nsd;lkf\r\n"
        b"asdfasdaflkjsd;lkg;dfshglkdksfhg;ljsdflgjs;dlkkjg'qwjer'pgtoks\r\n"
        b"ddasd'dgkls'dfkjg\r\nsd'g;lkksd'f';gkjsd\r\n[fkgli'erjrg';ksd\r\n"
        b"'g'asldjg';askg\r\nkqe\r\n-["
    )
    md5sum = hashlib.md5(entry.open().read())
    assert md5sum.hexdigest().encode() == next(meta for meta in entry.meta if meta.type == ad1.MetaType.MD5).data


def test_ad1_compressed(ad1_data_compressed: BinaryIO) -> None:
    """Test if we can parse a non-segmented AD1 file with standard zlib compression."""

    fs = ad1.AD1(ad1_data_compressed)

    assert fs.segments[0].header.magic == b"ADSEGMENTEDFILE\x00"

    assert fs.get("/").listdir() == ["E:"]
    assert fs.get("E:/AD1_test").listdir() == ["doc1.txt", "doc2.txt"]
    assert fs.get("E:/AD1_test/doc1.txt").open().read() == b"Inhoud document 1"


@pytest.mark.parametrize(
    ("path", "expected_files"),
    [
        pytest.param(
            "_data/ad1/pcbje/text-and-pictures.ad1",
            [
                "text-and-pictures.ad1",
                "text-and-pictures.ad2",
                "text-and-pictures.ad3",
                "text-and-pictures.ad4",
            ],
            id="segmented-simple",
        ),
        pytest.param(
            "_data/ad1/encrypted-passphrase/encrypted.ad1",
            [
                "encrypted.ad1",
                "encrypted.ad2",
                "encrypted.ad3",
                "encrypted.ad4",
                "encrypted.ad5",
                "encrypted.ad6",
                "encrypted.ad7",
                "encrypted.ad8",
                "encrypted.ad9",
                "encrypted.ad10",
                "encrypted.ad11",
                "encrypted.ad12",
                "encrypted.ad13",
            ],
            id="segmented-natural-sorting",
        ),
    ],
)
def test_ad1_find_files(path: str, expected_files: list[str]) -> None:
    """Test if we correctly find and order segmented AD1 files and do not find .txt or .csv artifact files."""

    files = find_files(absolute_path(path))
    assert [file.name for file in files] == expected_files


def test_ad1_segmented(ad1_data_segmented: list[BinaryIO]) -> None:
    """Test if we can parse segmented AD1 files.

    References:
        - https://github.com/pcbje/pyad1/tree/master/test_data
    """

    fs = ad1.AD1(ad1_data_segmented)

    assert len(fs.segments) == 4
    assert len(fs.stream._runs) == 4
    assert fs.segments[0].number == 1
    assert fs.segments[0].count == 4
    assert fs.segments[0].size == 0x200000

    assert fs.logical_image.version == 4
    assert fs.logical_image.name == b"C:\\Users\\pcbje\\Desktop\\Data"

    dir = fs.get("C:/Users/pcbje/Desktop/Data/Pictures")
    assert dir.is_dir()
    assert not dir.is_symlink()
    assert not dir.is_file()
    assert dir.name == "Pictures"
    assert dir.type == EntryType.Directory
    assert dir.size == 0
    assert dir.btime == datetime(2018, 5, 2, 7, 34, 11, 284926, tzinfo=timezone.utc)
    assert dir.mtime == datetime(2018, 5, 2, 7, 42, 39, 841574, tzinfo=timezone.utc)
    assert dir.ctime == datetime(2018, 5, 2, 7, 42, 39, 841574, tzinfo=timezone.utc)
    assert dir.atime == datetime(2018, 5, 2, 7, 46, 59, 164650, tzinfo=timezone.utc)
    assert dir.listdir() == [
        "0-0-581-Hydrangeas.jpg",
        "1-0-858-Chrysanthemum.jpg",
        "2-0-826-Desert.jpg",
        "4-0-757-Jellyfish.jpg",
        "5-0-762-Koala.jpg",
        "6-0-548-Lighthouse.jpg",
        "7-0-759-Penguins.jpg",
    ]

    picture = fs.get("C:/Users/pcbje/Desktop/Data/Pictures/5-0-762-Koala.jpg")
    assert picture.is_file()
    assert not picture.is_dir()
    assert not picture.is_symlink()
    assert picture.btime == datetime(2018, 1, 28, 7, 18, 0, tzinfo=timezone.utc)
    assert picture.mtime == datetime(2018, 5, 2, 7, 42, 34, 287014, tzinfo=timezone.utc)
    assert picture.ctime == datetime(2018, 5, 2, 7, 42, 34, 287014, tzinfo=timezone.utc)
    assert picture.atime == datetime(2018, 5, 2, 7, 42, 35, 611785, tzinfo=timezone.utc)

    buf = picture.open().read()
    assert picture.name == "5-0-762-Koala.jpg"
    assert picture.size == 780831
    assert len(buf) == 780831
    assert picture.get_meta(MetaType.SHA1).data == b"9c3dcb1f9185a314ea25d51aed3b5881b32f420c"
    assert hashlib.sha1(buf).hexdigest() == "9c3dcb1f9185a314ea25d51aed3b5881b32f420c"
