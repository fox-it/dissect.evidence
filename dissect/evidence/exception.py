class Error(Exception):
    pass


class FileNotFoundError(Error, FileNotFoundError):
    pass


class IsADirectoryError(Error, IsADirectoryError):
    pass


class NotADirectoryError(Error, NotADirectoryError):
    pass


class NotASymlinkError(Error):
    pass


class EWFError(Error):
    """Related to EWF (Expert Witness disk image Format)"""


class InvalidSnapshot(Error):
    """Related to ASDF (Acquire Snapshot Data Format)"""


class InvalidBlock(Error):
    """Related to ASDF (Acquire Snapshot Data Format)"""


class UnsupportedVersion(Error):
    """Related to ASDF (Acquire Snapshot Data Format)"""
