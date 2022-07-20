from dissect.evidence import ewf


def test_ewf(ewf_data):
    e = ewf.EWF(ewf_data)

    assert e.size == 4097
    assert e.read(4097) == (b"\xde\xad\xbe\xef" * 1024) + b"\n"
