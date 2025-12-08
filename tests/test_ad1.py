from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import TYPE_CHECKING, BinaryIO

import pytest

from dissect.evidence.ad1 import ad1
from dissect.evidence.ad1.ad1 import EntryType, find_files
from tests._utils import absolute_path

if TYPE_CHECKING:
    from pathlib import Path


def test_ad1(ad1_basic: BinaryIO) -> None:
    """Test if we can parse a basic non-segmented AD1 file with no file hierarchy."""

    fs = ad1.AD1(ad1_basic)
    assert fs.segment(0).header.magic == b"ADSEGMENTEDFILE\x00"

    assert fs.root.is_dir()
    assert fs.root.listdir() == ["E:"]

    file = fs.get("E:/AD1_test/doc1.txt")
    assert file.is_file()
    assert file.size == 17
    assert file.atime == datetime(2017, 3, 31, 18, 2, 31, 189682, tzinfo=timezone.utc)
    assert file.open().read() == b"Inhoud document 1"


def test_ad1_long(ad1_long: BinaryIO) -> None:
    """Test if we can parse a basic non-segmented AD1 file with long file names."""

    fs = ad1.AD1(ad1_long)

    assert fs.segment(0).header.magic == b"ADSEGMENTEDFILE\x00"
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
    assert md5sum.hexdigest() == entry.md5


def test_ad1_compressed(ad1_compressed: BinaryIO) -> None:
    """Test if we can parse a non-segmented AD1 file with standard zlib compression."""

    fs = ad1.AD1(ad1_compressed)

    assert fs.segment(0).header.magic == b"ADSEGMENTEDFILE\x00"

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


def test_ad1_segmented(ad1_segmented: list[Path]) -> None:
    """Test if we can parse segmented AD1 files.

    References:
        - https://github.com/pcbje/pyad1/tree/master/test_data
    """

    fs = ad1.AD1(ad1_segmented)

    assert len(fs.fh) == 4
    assert fs.segment(0).number == 1
    assert fs.segment(0).count == 4
    assert fs.segment(0).size == 0x200000 - 512

    assert fs.logical_image.version == 4
    assert fs.logical_image.name == "C:\\Users\\pcbje\\Desktop\\Data"

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
    assert picture.sha1 == "9c3dcb1f9185a314ea25d51aed3b5881b32f420c"
    assert hashlib.sha1(buf).hexdigest() == "9c3dcb1f9185a314ea25d51aed3b5881b32f420c"


def test_adcrypt_passphrase(ad1_encrypted_passphrase: list[Path]) -> None:
    """Test if we can decrypt ADCRYPT AD1 images, in this example a segmented AD1 logical image."""
    fs = ad1.AD1(ad1_encrypted_passphrase)

    assert fs.is_adcrypt()
    assert fs.is_locked()

    with pytest.raises(ValueError, match="AD1 container is locked by ADCRYPT"):
        fs.get("/")

    with pytest.raises(ValueError, match="Unable to unlock: HMAC verification of passphrase failed"):
        fs.unlock(passphrase="asdf")

    fs.unlock(passphrase="password")

    assert fs.adcrypt.key.hex() == "9030a43f29689a045e815cf4f0ad82b68850063b414f2797f0897e188f98d7b4"

    assert fs.get("C:/Users/User/Downloads").listdir() == [
        "7z2501-x64.exe",
        "desktop.ini",
        "Exterro_FTK_Imager_(x64)-4.7.3.81.exe",
        "hans-veth-8y--BAFlC9c-unsplash.jpg",
        "marc-olivier-jodoin-tauPAnOIGvE-unsplash.jpg",
        "marek-szturc-8Ou3EZmTMWA-unsplash.jpg",
        "milo-weiler-1AIYdIb3O5M-unsplash.jpg",
    ]

    for file in fs.get("C:/Users/User/Downloads").iterdir():
        buf = file.open().read()
        assert len(buf) == file.size
        assert hashlib.sha1(buf).hexdigest() == file.sha1


def test_adcrypt_certificate(ad1_encrypted_certificate: list[Path]) -> None:
    """Test if we can decrypt ADCRYPT AD1 images, in this example a segmented AD1 logical image."""
    fs = ad1.AD1(ad1_encrypted_certificate)

    assert fs.is_adcrypt()
    assert fs.is_locked()

    with pytest.raises(ValueError, match="AD1 container is locked by ADCRYPT"):
        fs.get("/")

    with pytest.raises(ValueError, match="Unable to unlock: HMAC verification of passphrase failed"):
        fs.unlock(passphrase="asdf")

    fs.unlock(private_key=absolute_path("_data/ad1/encrypted-certificate/key"))

    assert fs.adcrypt.key.hex() == "6cc0a9f94f944381cc51be474e5da6178059324bb457a87e0035b80f80ff9d4b"

    assert fs.get("C:/Users/User/Downloads").listdir() == [
        "desktop.ini",
        "hans-veth-8y--BAFlC9c-unsplash.jpg",
        "key.pem",
        "marc-olivier-jodoin-tauPAnOIGvE-unsplash.jpg",
        "marek-szturc-8Ou3EZmTMWA-unsplash.jpg",
        "milo-weiler-1AIYdIb3O5M-unsplash.jpg",
        "programs",
    ]

    for file in fs.get("C:/Users/User/Downloads").iterdir():
        if file.is_dir():
            continue

        buf = file.open().read()
        assert len(buf) == file.size
        assert hashlib.sha1(buf).hexdigest() == file.sha1

    assert fs.get("C:/Users/User/Downloads/programs").listdir() == [
        "7z2501-x64.exe",
        "Exterro_FTK_Imager_(x64)-4.7.3.81.exe",
    ]


def test_ad1_segment_lru(ad1_segmented: list[Path], monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ad1, "MAX_OPEN_SEGMENTS", 2)

    fs = ad1.AD1(ad1_segmented)
    assert fs._segment_lru == [3, 0]

    fs.segment(2)
    assert fs._segment_lru == [0, 2]

    fs.segment(1)
    assert fs._segment_lru == [2, 1]

    picture = fs.get("C:/Users/pcbje/Desktop/Data/Pictures/5-0-762-Koala.jpg")
    assert hashlib.sha1(picture.open().read()).hexdigest() == "9c3dcb1f9185a314ea25d51aed3b5881b32f420c"
