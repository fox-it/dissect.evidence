import zlib

from dissect import cstruct
from dissect.util.stream import RelativeStream, AlignedStream

ad1_def = """
enum EntryType : uint32 {
    File        = 0x0,
    Directory   = 0x5
};

enum MetaType : uint32 {
    FileClass           = 0x2,
    FileSize            = 0x3,
    PhysicalSize        = 0x4,
    StartCluster        = 0x6,
    DateAccessed        = 0x7,
    DateCreated         = 0x8,
    DateModified        = 0x9,
    Unknown_1           = 0xd,
    Unknown_2           = 0xe,
    ActualFile          = 0x1e,
    Unknown_3           = 0x1002,
    Unknown_4           = 0x1003,
    Unknown_5           = 0x1004,
    Unknown_6           = 0x1005,
    MD5                 = 0x5001,
    SHA1                = 0x5002,
    ClusterSize         = 0x9001,
    ClusterCount        = 0x9002,
    FreeClusterCount    = 0x9003,
    VolumeSerialNumber  = 0x9006
};

typedef struct {
    char        magic[16];
    uint32      unk1;
    uint32      unk2;
    uint32      unk3;
    uint32      unk4;
    uint16      unk5;
    uint16      version;
    uint32      unk6;
    uint64      logical_image_offset;
} SegmentedFileHeader;

typedef struct {
    char        magic[16];
    uint32      unk1;
    uint32      unk2;
    uint32      chunk_size;     // This is supposed to be uint64? But that doesn't seem right
    uint32      unk3;
    uint32      unk4;
    uint64      entry_offset;
    uint32      name_len;
    uint32      unk5;
    uint64      name_offset;
    uint64      unk6;
    uint64      unk7;
    uint64      unk8;
    uint64      unk9;
    char        name[name_len];
} LogicalImageHeader;

typedef struct {
    uint64      next;
    uint64      child;
    uint64      meta;
    uint64      unk1;
    uint64      size;
    EntryType   type;
    uint32      name_len;
    char        name[name_len];
    uint64      unk2;
    uint64      num_chunks;
    uint64      chunks[num_chunks];
} FileEntry;

typedef struct {
    uint64      next;
    uint32      category;
    MetaType    type;
    uint32      len;
    char        data[len];
} FileMeta;
"""
c_ad1 = cstruct.cstruct()
c_ad1.load(ad1_def)

EntryType = c_ad1.EntryType
MetaType = c_ad1.MetaType


class AD1:
    def __init__(self, fh):
        self.fh = fh
        self.header = c_ad1.SegmentedFileHeader(fh)

        offset = self.header.logical_image_offset
        self.logical_image = LogicalImage(RelativeStream(fh, offset))
        self.root = self.logical_image

    def __getattr__(self, k):
        if k in self.header:
            return getattr(self.header, k)

        return super().__getattr__(k)

    def entry(self, path=""):
        components = path.lstrip("/").split("/")
        current = self.root

        if components[0] == "":
            return current

        for c in components:
            for item in current.children:
                if item.name == c:
                    current = item

        if current.name == components[-1]:
            return current

        raise IOError("Path not found: %s" % path)

    def listdir(self, path):
        return [e.name for e in self.entry(path).children]

    def get(self, path):
        return self.entry(path)

    def open(self, path):
        return self.entry(path).open()

    def walk(self):
        raise NotImplementedError()


class LogicalImage:
    def __init__(self, fh):
        self.fh = fh
        self.header = c_ad1.LogicalImageHeader(fh)

        self.children = []
        offset = self.header.entry_offset
        while offset != 0:
            child = FileEntry(self, offset, None)
            offset = child.entry.next
            self.children.append(child)

    def __repr__(self):
        return f"<LogicalImage name={self.header.name}>"

    def __getattr__(self, k):
        if k in self.header:
            return getattr(self.header, k)

        return object.__getattribute__(self, k)


class FileEntry:
    def __init__(self, image, offset, parent):
        fh = image.fh
        fh.seek(offset)
        self.image = image
        self.offset = offset
        self.entry = c_ad1.FileEntry(fh)
        self.size = self.entry.size

        self.meta = []
        offset = self.entry.meta
        while offset != 0:
            meta = FileMeta(image, offset)
            offset = meta.entry.next
            self.meta.append(meta)

        self.children = []
        offset = self.entry.child
        while offset != 0:
            child = FileEntry(image, offset, self)
            offset = child.entry.next
            self.children.append(child)

    def __repr__(self):
        file_type = "Unknown type"
        if self.is_file():
            file_type = "File"
        elif self.is_dir():
            file_type = "Directory"
        return f"<{file_type} name={self.entry.name}>"

    def __getattr__(self, k):
        if k in self.entry:
            return getattr(self.entry, k)

        return object.__getattribute__(self, k)

    def open(self):
        return FileObject(self)

    def is_file(self):
        return self.entry.type == EntryType.File

    def is_dir(self):
        return self.entry.type == EntryType.Directory


class FileMeta:
    def __init__(self, image, offset):
        fh = image.fh
        fh.seek(offset)
        self.image = image
        self.offset = offset
        self.entry = c_ad1.FileMeta(fh)

    def __repr__(self):
        return f"<Meta category={self.entry.category} type={self.entry.type} data={self.entry.data}>"

    def __getattr__(self, k):
        if k in self.entry:
            return getattr(self.entry, k)

        return object.__getattribute__(self, k)


class FileObject(AlignedStream):
    def __init__(self, entry):
        self.entry = entry
        super().__init__(self.entry.size, self.entry.image.chunk_size)

    def _read(self, offset, length):
        r = []
        fh = self.entry.image.fh
        chunk_size = self.entry.image.chunk_size

        chunk = offset // chunk_size
        chunk_count = (length + chunk_size - 1) // chunk_size

        chunk_offsets = self.entry.entry.chunks[chunk : chunk + chunk_count + 1]
        if len(chunk_offsets) != chunk_count + 1:
            chunk_offsets.append(self.entry.entry.meta)

        fh.seek(chunk_offsets[0])
        buf = fh.read(chunk_offsets[-1] - chunk_offsets[0])

        prev_offset = chunk_offsets[0]
        for offset in chunk_offsets[1:]:
            chunk_size = offset - prev_offset
            r.append(zlib.decompress(buf[:chunk_size]))
            buf = buf[chunk_size:]
            prev_offset = offset

        return b"".join(r)
