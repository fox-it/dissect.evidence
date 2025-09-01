from __future__ import annotations

from dissect.cstruct import cstruct

ewf_def = """
enum MediaType : uint8 {
    Removable   = 0x00,
    Fixed       = 0x01,
    Optical     = 0x03,
    Logical     = 0x0e,
    RAM         = 0x10
};

enum MediaFlags : uint8 {
    Image       = 0x01,
    Physical    = 0x02,
    Fastbloc    = 0x04,
    Tablaeu     = 0x08
};

enum CompressionLevel : uint8 {
    None        = 0x00,
    Good        = 0x01,
    Best        = 0x02
};

typedef struct {
    char        signature[8];
    uint8       fields_start;
    uint16      segment_number;
    uint16      fields_end;
} EWFHeader;

typedef struct {
    char    type[16];
    uint64  next;
    uint64  size;
    uint8   pad[40];
    uint32  checksum;
} EWFSectionDescriptor;

typedef struct {
    uint32  reserved_1;
    uint32  chunk_count;
    uint32  sector_count;
    uint32  sector_size;
    uint32  total_sector_count;
    uint8   reserved[20];
    uint8   pad[45];
    char    signature[5];
    uint32  checksum;
} EWFVolumeSectionSpec;

typedef struct {
    MediaType           media_type;
    uint8               reserved_1[3];
    uint32              chunk_count;
    uint32              sector_count;
    uint32              sector_size;
    uint64              total_sector_count;
    uint32              num_cylinders;
    uint32              num_heads;
    uint32              num_sectors;
    uint8               media_flags;
    uint8               unknown_1[3];
    uint32              palm_start_sector;
    uint32              unknown_2;
    uint32              smart_start_sector;
    CompressionLevel    compression_level;
    uint8               unknown_3[3];
    uint32              error_granularity;
    uint32              unknown_4;
    uint8               uuid[16];
    uint8               pad[963];
    char                signature[5];
    uint32              checksum;
} EWFVolumeSection;

typedef struct {
    uint32  num_entries;
    uint32  _;
    uint64  base_offset;
    uint32  _;
    uint32  checksum;
    uint32  entries[num_entries];
} EWFTableSection;
"""

c_ewf = cstruct().load(ewf_def)
