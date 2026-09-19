from pathlib import Path

import pytest

from dissect.evidence.asdf import AsdfWriter
from dissect.evidence.asdf.asdf import CHECKSUM_MAPPING
from dissect.evidence.tools.asdf.verify import main as asdf_verify


@pytest.fixture(params=CHECKSUM_MAPPING.keys())
def asdf_file(tmp_path: Path, request: pytest.FixtureRequest) -> Path:
    asdf_file = tmp_path.joinpath("asdf.asdf")
    fh = asdf_file.open("wb")
    with AsdfWriter(fh, checksum_algorithm=request.param) as asdf_writer:
        asdf_writer.add_bytes(b"\x00" * 0x1000, idx=0, base=0)
        asdf_writer.add_bytes(b"\x02" * 0x1000, idx=0, base=0x4000)
        asdf_writer.add_bytes(b"\x04" * 0x1000, idx=0, base=0x8000)
        asdf_writer.add_bytes(b"\x06" * 0x1000, idx=0, base=0x10000)
        asdf_writer.add_bytes(b"\xff" * 0x1000, idx=0, base=0x14000)

        asdf_writer.add_bytes(b"\x08" * 0x1000, idx=1, base=0x2000)
        asdf_writer.add_bytes(b"\x10" * 0x1000, idx=1, base=0x5000)
        asdf_writer.add_bytes(b"\x12" * 0x1000, idx=1, base=0x8000)
        asdf_writer.add_bytes(b"\x14" * 0x1000, idx=1, base=0xB000)
        asdf_writer.add_bytes(b"\xff" * 0x1000, idx=1, base=0xE000)
    return asdf_file


def test_asdf_verify(asdf_file: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    with monkeypatch.context() as m:
        m.setattr(
            "sys.argv",
            ["asdf-verify", str(asdf_file)],
        )

        assert asdf_verify() == 0
