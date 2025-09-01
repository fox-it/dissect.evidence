from __future__ import annotations

from dissect.evidence.ewf.c_ewf import c_ewf
from dissect.evidence.ewf.ewf import (
    EWF,
    EWFError,
    EWFStream,
    HeaderSection,
    SectionDescriptor,
    Segment,
    TableSection,
    VolumeSection,
)

__all__ = [
    "EWF",
    "EWFError",
    "EWFStream",
    "HeaderSection",
    "SectionDescriptor",
    "Segment",
    "TableSection",
    "VolumeSection",
    "c_ewf",
]
