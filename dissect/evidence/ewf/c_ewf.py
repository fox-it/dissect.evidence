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
    char                signature[8];
    uint8               fields_start;
    uint16              segment_number;
    uint16              fields_end;
} SegmentHeader;

typedef struct {
    char                type[16];
    uint64              next;
    uint64              size;
    uint8               pad[40];
    uint32              checksum;
} SectionDescriptor;

typedef struct {
    uint32              reserved_1;
    uint32              number_of_chunks;
    uint32              sectors_per_chunk;
    uint32              bytes_per_sector;
    uint32              number_of_sectors;
    uint8               reserved[20];
    uint8               pad[45];
    char                signature[5];
    uint32              checksum;
} VolumeSectionSmart;

typedef struct {
    MediaType           media_type;
    uint8               reserved_1[3];
    uint32              number_of_chunks;
    uint32              sectors_per_chunk;
    uint32              bytes_per_sector;
    uint64              number_of_sectors;
    uint32              chs_cylinders;
    uint32              chs_heads;
    uint32              chs_sectors;
    uint8               media_flags;
    uint8               unknown_1[3];
    uint32              palm_volume_start_sector;
    uint32              unknown_2;
    uint32              smart_logs_start_sector;
    CompressionLevel    compression_level;
    uint8               unknown_3[3];
    uint32              error_granularity;
    uint32              unknown_4;
    uint8               set_identifier[16];
    uint8               pad[963];
    char                signature[5];
    uint32              checksum;
} VolumeSection;

typedef struct {
	MediaType           media_type;
	uint8               unknown1[3];
	uint32              number_of_chunks;
	uint32              sectors_per_chunk;
	uint32              bytes_per_sector;
	uint64              number_of_sectors;
	uint32              chs_cylinders;
	uint32              chs_heads;
	uint32              chs_sectors;
	MediaFlags          media_flags;
	uint8               unknown2[3];
	uint32              palm_volume_start_sector;
	uint32              unknown3;
	uint32              smart_logs_start_sector;
	CompressionLevel    compression_level;
	uint8               unknown4[3];
	uint32              error_granularity;
	uint32              unknown5;
	uint8               set_identifier[16];
	char                pad[963];
	char                signature[5];
	uint32              checksum;
} DataSection;

typedef struct {
    uint32              number_of_entries;
    uint32              _;
    uint64              base_offset;
    uint32              _;
    uint32              checksum;
} TableSection;

typedef struct {
	char                md5[16];
	char                unknown1[16];
	uint32              checksum;
} HashSection;
"""

c_ewf = cstruct().load(ewf_def)
