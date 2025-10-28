from __future__ import annotations

from dissect.cstruct import cstruct

asdf_def = """
flag FILE_FLAG : uint32 {
    SHA256      = 0x01,
};

flag BLOCK_FLAG : uint8 {
    CRC32       = 0x01,
    COMPRESS    = 0x02,
};

struct header {
    char        magic[4];       // File magic, must be "ASDF"
    FILE_FLAG   flags;          // File flags
    uint8       version;        // File version
    char        reserved1[7];   // Reserved
    uint64      timestamp;      // Creation timestamp of the file
    char        reserved2[8];   // Reserved
    char        guid[16];       // GUID, should be unique per writer
};

struct block {
    char        magic[4];       // Block magic, must be "BL\\xa5\\xdf"
    BLOCK_FLAG  flags;          // Block flags
    uint8       idx;            // Stream index, some reserved values have special meaning
    char        reserved[2];    // Reserved
    uint64      offset;         // Absolute offset of block in stream
    uint64      size;           // Size of block in stream
};

struct table_entry {
    BLOCK_FLAG  flags;          // Block flags
    uint8       idx;            // Stream index, some reserved values have special meaning
    char        reserved[2];    // Reserved
    uint64      offset;         // Absolute offset of block in stream
    uint64      size;           // Size of block in stream
    uint64      file_offset;    // Absolute offset of block in file
    uint64      file_size;      // Size of block in file
};

struct footer {
    char        magic[4];       // Footer magic, must be "FT\\xa5\\xdf"
    char        reserved[4];    // Reserved
    uint64      table_offset;   // Offset in file to start of block table
    char        sha256[32];     // SHA256 of this file up until this hash
};
"""

c_asdf = cstruct().load(asdf_def)
