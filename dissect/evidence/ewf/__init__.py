from __future__ import annotations

from dissect.evidence.ewf.c_ewf import c_ewf
from dissect.evidence.ewf.ewf import (
    EWF,
    HeaderSection,
    SectionDescriptor,
    Segment,
    TableSection,
    VolumeSection,
    find_files,
)
from dissect.evidence.ewf.stream import EWFStream

__all__ = [
    "EWF",
    "EWFStream",
    "HeaderSection",
    "SectionDescriptor",
    "Segment",
    "TableSection",
    "VolumeSection",
    "c_ewf",
    "find_files",
]
