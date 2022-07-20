class Error(Exception):
    """Base class for exceptions for this module.
    It is used to recognize errors specific to this module"""

    pass


class EWFError(Error):
    """Related to EWF (Expert Witness disk image Format)"""

    pass


class InvalidSnapshot(Error):
    """Related to ASDF (Acquire Snapshot Data Format)"""

    pass


class InvalidBlock(Error):
    """Related to ASDF (Acquire Snapshot Data Format)"""

    pass


class UnsupportedVersion(Error):
    """Related to ASDF (Acquire Snapshot Data Format)"""

    pass
