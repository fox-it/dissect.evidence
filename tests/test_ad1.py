from __future__ import annotations

import hashlib
from typing import BinaryIO

from dissect.evidence import ad1


def test_ad1(ad1_data: BinaryIO) -> None:
    a = ad1.AD1(ad1_data)

    assert a.header.magic == b"ADSEGMENTEDFILE\x00"
    assert a.root.name == b"E:\\AD1_test"
    assert len(a.root.children) == 2
    assert a.root.children[0].name == b"doc1.txt"
    assert a.root.children[0].open().read() == b"Inhoud document 1"


def test_ad1_long(ad1_data_long: BinaryIO) -> None:
    a = ad1.AD1(ad1_data_long)

    assert a.header.magic == b"ADSEGMENTEDFILE\x00"
    assert a.root.name == b"E:\\testdatamap 2 met spaties en een heel stuk langer"
    assert len(a.root.children) == 2

    entry = a.root.children[0]
    assert entry.name == b"een lange filenaam 1 met spaties.txt"
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
    a = ad1.AD1(ad1_data_compressed)

    assert a.root.children[0].open().read() == b"Inhoud document 1"
