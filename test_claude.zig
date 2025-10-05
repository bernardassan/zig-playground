const std = @import("std");
const testing = std.testing;

pub const Mask = packed struct(u32) {
    /// Want/got stx_mode & S_IFMT
    type: bool = false,
    /// Want/got stx_mode & ~S_IFMT
    mode: bool = false,
    /// Want/got stx_nlink
    nlink: bool = false,
    /// Want/got stx_uid
    uid: bool = false,
    /// Want/got stx_gid
    gid: bool = false,
    /// Want/got stx_atime
    atime: bool = false,
    /// Want/got stx_mtime
    mtime: bool = false,
    /// Want/got stx_ctime
    ctime: bool = false,
    /// Want/got stx_ino
    ino: bool = false,
    /// Want/got stx_size
    size: bool = false,
    /// Want/got stx_blocks
    blocks: bool = false,
    /// Want/got stx_btime
    btime: bool = false,
    /// Got stx_mnt_id
    mnt_id: bool = false,
    /// Want/got direct I/O alignment info
    dioalign: bool = false,
    /// Want/got extended stx_mount_id
    mnt_id_unique: bool = false,
    /// Want/got stx_subvol
    subvol: bool = false,

    /// Want/got atomic_write_* fields
    write_atomic: bool = false,
    /// Want/got dio read alignment info
    dio_read_align: bool = false,
    _: u14 = 0,

    /// The stuff in the normal stat struct (bits 0-10)
    pub const basic_stats: Mask = .{
        .type = true,
        .mode = true,
        .nlink = true,
        .uid = true,
        .gid = true,
        .atime = true,
        .mtime = true,
        .ctime = true,
        .ino = true,
        .size = true,
        .blocks = true,
    };
};

pub const Attr = packed struct(u64) {
    _0: u2 = 0,
    /// File is compressed by the fs
    compressed: bool = false,
    _1: u1 = 0,
    /// File is marked immutable
    immutable: bool = false,
    /// File is append-only
    append: bool = false,
    /// File is not to be dumped
    nodump: bool = false,
    _2: u4 = 0,
    /// File requires key to decrypt in fs
    encrypted: bool = false,
    /// Dir: Automount trigger
    automount: bool = false,
    /// Root of a mount
    mount_root: bool = false,
    _3: u6 = 0,
    /// Verity protected file
    verity: bool = false,
    /// File is currently in DAX state
    dax: bool = false,
    /// File supports atomic write operations
    write_atomic: bool = false,
    _: u41 = 0,
};

test "StatxMask - individual fields match constants" {
    // Constants for comparison
    const STATX_TYPE: u32 = 0x00000001;
    const STATX_MODE: u32 = 0x00000002;
    const STATX_NLINK: u32 = 0x00000004;
    const STATX_UID: u32 = 0x00000008;
    const STATX_GID: u32 = 0x00000010;
    const STATX_ATIME: u32 = 0x00000020;
    const STATX_MTIME: u32 = 0x00000040;
    const STATX_CTIME: u32 = 0x00000080;
    const STATX_INO: u32 = 0x00000100;
    const STATX_SIZE: u32 = 0x00000200;
    const STATX_BLOCKS: u32 = 0x00000400;
    const STATX_BASIC_STATS: u32 = 0x000007ff;
    const STATX_BTIME: u32 = 0x00000800;
    const STATX_MNT_ID: u32 = 0x00001000;
    const STATX_DIOALIGN: u32 = 0x00002000;
    const STATX_MNT_ID_UNIQUE: u32 = 0x00004000;
    const STATX_SUBVOL: u32 = 0x00008000;
    const STATX_WRITE_ATOMIC: u32 = 0x00010000;
    const STATX_DIO_READ_ALIGN: u32 = 0x00020000;

    const STATX_ATTR_COMPRESSED: u64 = 0x00000004;
    const STATX_ATTR_IMMUTABLE: u64 = 0x00000010;
    const STATX_ATTR_APPEND: u64 = 0x00000020;
    const STATX_ATTR_NODUMP: u64 = 0x00000040;
    const STATX_ATTR_ENCRYPTED: u64 = 0x00000800;
    const STATX_ATTR_AUTOMOUNT: u64 = 0x00001000;
    const STATX_ATTR_MOUNT_ROOT: u64 = 0x00002000;
    const STATX_ATTR_VERITY: u64 = 0x00100000;
    const STATX_ATTR_DAX: u64 = 0x00200000;
    const STATX_ATTR_WRITE_ATOMIC: u64 = 0x00400000;

    try testing.expectEqual(STATX_TYPE, @as(u32, @bitCast(Mask{ .type = true })));
    try testing.expectEqual(STATX_MODE, @as(u32, @bitCast(Mask{ .mode = true })));
    try testing.expectEqual(STATX_NLINK, @as(u32, @bitCast(Mask{ .nlink = true })));
    try testing.expectEqual(STATX_UID, @as(u32, @bitCast(Mask{ .uid = true })));
    try testing.expectEqual(STATX_GID, @as(u32, @bitCast(Mask{ .gid = true })));
    try testing.expectEqual(STATX_ATIME, @as(u32, @bitCast(Mask{ .atime = true })));
    try testing.expectEqual(STATX_MTIME, @as(u32, @bitCast(Mask{ .mtime = true })));
    try testing.expectEqual(STATX_CTIME, @as(u32, @bitCast(Mask{ .ctime = true })));
    try testing.expectEqual(STATX_INO, @as(u32, @bitCast(Mask{ .ino = true })));
    try testing.expectEqual(STATX_SIZE, @as(u32, @bitCast(Mask{ .size = true })));
    try testing.expectEqual(STATX_BLOCKS, @as(u32, @bitCast(Mask{ .blocks = true })));
    try testing.expectEqual(STATX_BTIME, @as(u32, @bitCast(Mask{ .btime = true })));
    try testing.expectEqual(STATX_MNT_ID, @as(u32, @bitCast(Mask{ .mnt_id = true })));
    try testing.expectEqual(STATX_DIOALIGN, @as(u32, @bitCast(Mask{ .dioalign = true })));
    try testing.expectEqual(STATX_MNT_ID_UNIQUE, @as(u32, @bitCast(Mask{ .mnt_id_unique = true })));
    try testing.expectEqual(STATX_SUBVOL, @as(u32, @bitCast(Mask{ .subvol = true })));
    try testing.expectEqual(STATX_WRITE_ATOMIC, @as(u32, @bitCast(Mask{ .write_atomic = true })));
    try testing.expectEqual(STATX_DIO_READ_ALIGN, @as(u32, @bitCast(Mask{ .dio_read_align = true })));

    // StatxMask - basic_stats constant
    const mask_value: u32 = @bitCast(Mask.basic_stats);
    try testing.expectEqual(STATX_BASIC_STATS, mask_value);
    // StatxAttr - individual fields match constants
    try testing.expectEqual(STATX_ATTR_COMPRESSED, @as(u64, @bitCast(Attr{ .compressed = true })));
    try testing.expectEqual(STATX_ATTR_IMMUTABLE, @as(u64, @bitCast(Attr{ .immutable = true })));
    try testing.expectEqual(STATX_ATTR_APPEND, @as(u64, @bitCast(Attr{ .append = true })));
    try testing.expectEqual(STATX_ATTR_NODUMP, @as(u64, @bitCast(Attr{ .nodump = true })));
    try testing.expectEqual(STATX_ATTR_ENCRYPTED, @as(u64, @bitCast(Attr{ .encrypted = true })));
    try testing.expectEqual(STATX_ATTR_AUTOMOUNT, @as(u64, @bitCast(Attr{ .automount = true })));
    try testing.expectEqual(STATX_ATTR_MOUNT_ROOT, @as(u64, @bitCast(Attr{ .mount_root = true })));
    try testing.expectEqual(STATX_ATTR_VERITY, @as(u64, @bitCast(Attr{ .verity = true })));
    try testing.expectEqual(STATX_ATTR_DAX, @as(u64, @bitCast(Attr{ .dax = true })));
    try testing.expectEqual(STATX_ATTR_WRITE_ATOMIC, @as(u64, @bitCast(Attr{ .write_atomic = true })));
}

pub const RenameFlags = packed struct(u32) {
    /// Don't overwrite target
    noreplace: bool = false,
    /// Exchange source and dest
    exchange: bool = false,
    /// Whiteout source
    whiteout: bool = false,
    _: u29 = 0,
};

test "RenameFlags - individual fields match constants" {
    // Constants for comparison
    const RENAME_NOREPLACE: u32 = 1 << 0;
    const RENAME_EXCHANGE: u32 = 1 << 1;
    const RENAME_WHITEOUT: u32 = 1 << 2;

    try testing.expectEqual(RENAME_NOREPLACE, @as(u32, @bitCast(RenameFlags{ .noreplace = true })));
    try testing.expectEqual(RENAME_EXCHANGE, @as(u32, @bitCast(RenameFlags{ .exchange = true })));
    try testing.expectEqual(RENAME_WHITEOUT, @as(u32, @bitCast(RenameFlags{ .whiteout = true })));
}
