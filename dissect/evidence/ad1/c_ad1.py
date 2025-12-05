from __future__ import annotations

from dissect.cstruct import cstruct

ad1_def = """
enum EntryType : uint32 {
    File                    = 0x0,
    Unknown_File            = 0x1,
    Deleted                 = 0x2,
    Directory               = 0x5,
};

enum FileClassType : uint32 {
    File                    = 0x1,          // b"1"
    Directory               = 0x3,          // b"3"
    ReparsePoint            = 0x3131,       // b"11"
};

enum MetaType : uint32 {
    // Generic attributes
    ItemContentHashes       = 0x1,
    FileClass               = 0x2,
    FileSize                = 0x3,
    PhysicalSize            = 0x4,
    Timestamps              = 0x5,
    StartCluster            = 0x6,
    DateAccessed            = 0x7,
    DateCreated             = 0x8,
    DateModified            = 0x9,
    // .. 0xa, 0xb, 0xc ..
    Encrypted               = 0xd,
    Compressed              = 0xe,
    // .. 0xf ..
    ActualFile              = 0x1e,
    StartSector             = 0x1f,
    ADSCount                = 0x24,         // Alternate Data Stream Count

    // DOS attributes
    ShortFilename           = 0x1001,
    Hidden                  = 0x1002,
    System                  = 0x1003,
    ReadOnly                = 0x1004,
    Archive                 = 0x1005,

    // NTFS attributes
    MFTRecordNumber         = 0xa001,
    MFTDateChanged          = 0xa002,       // Specifies the MFT record change timestamp of the file.
    MFTIsResident           = 0xa003,
    MFTIsOffline            = 0xa004,
    MFTIsSparse             = 0xa005,
    MFTIsTemporary          = 0xa006,
    MFTOwnerSid             = 0xa007,
    MFTOwnerName            = 0xa008,
    MFTGroupSid             = 0xa009,
    MFTGroupName            = 0xa00a,

    MFTFileDateCreated      = 0xa01c,       // According to the filename attribute in the MFT.
    MFTFileDateModified     = 0xa01d,
    MFTFileDateAccessed     = 0xa01e,
    MFTFileDateChanged      = 0xa01f,
    MFTFileSize             = 0xa020,
    MFTFilePhysicalSize     = 0xa021,

    // 8.3 MFT Filename
    // 0xa022,
    // 0xa023,
    // 0xa024,
    // 0xa025,
    // 0xa026,
    // 0xa027,

    IndxFilename            = 0xa028,       // According to the filename attribute in the $I30 INDX.
    IndxFileSize            = 0xa029,
    IndxPhysicalSize        = 0xa02a,
    IndxDateCreated         = 0xa02b,
    IndxDateModified        = 0xa02c,
    IndxDateAccessed        = 0xa02d,
    IndxDateChanged         = 0xa02e,

    // 8.3 INDX
    // 0xa02f, 0xa030, 0xa031, 0xa032, 0xa033, 0xa034, 0xa035

    // NTFS Access Control Entry (0)
    AceType                 = 0x1000001,
    AceInheritable          = 0x1000004,
    AceSID                  = 0x1000005,    // The Security ID of the user or group this ACE applies to.
    AceName                 = 0x1000006,    // The name of the user or roup this ACE applies to.
    AceAccessMask           = 0x1000007,    // Raw bitmask specifying the actions this ACE controls.
    AceExecuteFile          = 0x1000008,
    AceReadData             = 0x1000009,
    AceWriteData            = 0x100000a,
    AceAppendData           = 0x100000b,
    AceTraverseFolder       = 0x100000c,
    AceListFolder           = 0x100000d,
    AceCreateFiles          = 0x100000e,
    AceCreateFolders        = 0x100000f,
    AceDeleteChildren       = 0x1000010,
    AceDeleteSelf           = 0x1000011,
    AceReadPermissions      = 0x1000012,
    AceChangePermissions    = 0x1000013,
    AceTakeOwnership        = 0x1000014,
    // .. 0x10010XX - 0x10060XX ..

    // Verification hashes
    MD5                     = 0x5001,
    SHA1                    = 0x5002,

    // TODO: Clean up
    ClusterSize             = 0x9001,
    ClusterCount            = 0x9002,
    FreeClusterCount        = 0x9003,
    VolumeSerialNumber      = 0x9006,
    PosixPermissions        = 0x2001,
};

#define ADSEGMENTEDFILE_MAGIC ADSEGMENTEDFILE\00

typedef struct {
    char        magic[16];                  // b"ADSEGMENTEDFILE" + padding
    uint32      unk1;                       // 0x01
    uint32      unk2;                       // 0x02
    uint32      segment_number;             // segment number starts at 0x01
    uint32      segment_count;              // number of segments
    uint64      segment_size;               // off by 512 bytes
    uint32      logical_image_offset;
    char        padding[468];               // 0x00
} SegmentedFileHeader;

typedef struct {
    char        magic[16];                  // b"ADLOGICALIMAGE" + padding
    uint32      version;                    // 0x03 or 0x04
    uint32      unk1;                       // 0x01
    uint32      chunk_size;                 // zlib chunk size (uint64?)
    uint64      metadata_offset;
    uint64      first_file_offset;
    uint32      name_len;

    // ADv4 (offset 48 contains name[name_len] in ADv3)
    char        unk_magic[4];               // b"AD" + (2 * 0x00)
    uint64      name_offset;                // 0x5c
    uint64      attr_guid_offset;
    uint64      unk2;                       // 0x00
    uint64      locs_guid_offset;
    uint64      unk3;                       // 0x00
    // END ADv4

    char        name[name_len];
} LogicalImageHeader;

typedef struct {
    uint64      next;                       // Next FileEntry in same hierarchy level
    uint64      child;                      // Next FileEntry within this dir, 0x00 if file
    uint64      meta;                       // Offset of first FileMeta entry
    uint64      zlib_meta;                  // Offset of zlib chunk metadata
    uint64      size;                       // Decompressed file size, 0x00 if no data
    EntryType   type;                       // 0x00 = file, 0x05 = directory
    uint32      name_len;
    char        name[name_len];
    uint64      parent_index;               // Parent folder index, 0x00 if at root
} FileEntry;

typedef struct {
    uint64      num_chunks;                 // only if FileEntry.size != 0x00
    uint64      chunks[num_chunks];
} FileEntryChunks;

typedef struct {
    uint64      next;
    uint32      category;
    MetaType    type;
    uint32      len;
    char        data[len];
} FileMeta;

typedef struct {
    char        unk1[352];                  // version 4 only
} Footer;

typedef struct {
    CHAR        unknown[16];
    WCHAR       link[EOF];
} ReparsePoint;
"""

c_ad1 = cstruct().load(ad1_def)
