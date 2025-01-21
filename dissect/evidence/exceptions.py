class Error(Exception):
    """Base class for exceptions for this module.
    It is used to recognize errors specific to this module"""


class EWFError(Error):
    """Related to EWF (Expert Witness disk image Format)"""


class InvalidSnapshot(Error):
    """Related to ASDF (Acquire Snapshot Data Format)"""


class InvalidBlock(Error):
    """Related to ASDF (Acquire Snapshot Data Format)"""


class UnsupportedVersion(Error):
    """Related to ASDF (Acquire Snapshot Data Format)"""
