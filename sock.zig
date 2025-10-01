const std = @import("std");
const testing = std.testing;
const builtin = @import("builtin");

const is_mips = builtin.cpu.arch.isMIPS();
const is_sparc = builtin.cpu.arch.isSPARC();

/// SOCK_* Socket type and flags
pub const Sock = packed struct(u32) {
    type: Type,
    flags: Flags = .{},

    /// matches sock_type in kernel
    pub const Type = enum(u7) {
        stream = if (is_mips) 2 else 1,
        dgram = if (is_mips) 1 else 2,
        raw = 3,
        rdm = 4,
        seqpacket = 5,
        dccp = 6,
        packet = 10,

        _,
    };

    // bit range is (8 - 32] of the u32
    /// Flags for socket, socketpair, accept4
    pub const Flags = if (is_sparc) packed struct(u25) {
        _: u7 = 0, // start from u7 since Type comes before Flags
        nonblock: bool = false,
        _1: u7 = 0,
        cloexec: bool = false,
        _2: u9 = 0,
    } else if (is_mips) packed struct(u25) {
        nonblock: bool = false,
        _: u11 = 0,
        cloexec: bool = false,
        _1: u12 = 0,
    } else packed struct(u25) {
        _: u4 = 0,
        nonblock: bool = false,
        _1: u7 = 0,
        cloexec: bool = false,
        _2: u12 = 0,
    };
};

// Constants for backward compatibility and testing
pub const SOCK = struct {
    pub const STREAM: u32 = if (is_mips) 2 else 1;
    pub const DGRAM: u32 = if (is_mips) 1 else 2;
    pub const RAW: u32 = 3;
    pub const RDM: u32 = 4;
    pub const SEQPACKET: u32 = 5;
    pub const DCCP: u32 = 6;
    pub const PACKET: u32 = 10;
    pub const CLOEXEC: u32 = if (is_sparc) 0o20000000 else 0o2000000;
    pub const NONBLOCK: u32 = if (is_mips) 0o200 else if (is_sparc) 0o40000 else 0o4000;
};

test "SocketType - enum values" {
    try testing.expectEqual(SOCK.STREAM, @as(u32, @bitCast(Sock{ .type = .stream })));
    try testing.expectEqual(SOCK.DGRAM, @as(u32, @bitCast(Sock{ .type = .dgram })));
    try testing.expectEqual(SOCK.RAW, @as(u32, @bitCast(Sock{ .type = .raw })));
    try testing.expectEqual(SOCK.RDM, @as(u32, @bitCast(Sock{ .type = .rdm })));
    try testing.expectEqual(SOCK.SEQPACKET, @as(u32, @bitCast(Sock{ .type = .seqpacket })));
    try testing.expectEqual(SOCK.DCCP, @as(u32, @bitCast(Sock{ .type = .dccp })));
    try testing.expectEqual(SOCK.PACKET, @as(u32, @bitCast(Sock{ .type = .packet })));
}

test "SocketFlags - create with type only" {
    const sock: Sock = .{ .type = .stream };
    try testing.expect(!sock.flags.nonblock);
    try testing.expect(!sock.flags.cloexec);
}

test "SocketFlags - type with CLOEXEC" {
    var sock: Sock = .{ .type = .stream };
    sock.flags.cloexec = true;

    const expected: u32 = SOCK.STREAM | SOCK.CLOEXEC;
    try testing.expectEqual(expected, @as(u32, @bitCast(sock)));
}

test "SocketFlags - type with NONBLOCK" {
    var sock: Sock = .{ .type = .dgram };
    sock.flags.nonblock = true;

    const expected: u32 = SOCK.DGRAM | SOCK.NONBLOCK;
    try testing.expectEqual(expected, @as(u32, @bitCast(sock)));
}

test "SocketFlags - type with both flags" {
    var sock: Sock = .{ .type = .stream };
    sock.flags.nonblock = true;
    sock.flags.cloexec = true;

    const expected = SOCK.STREAM | SOCK.CLOEXEC | SOCK.NONBLOCK;
    try testing.expectEqual(expected, @as(u32, @bitCast(sock)));
}

test "SocketFlags - fromInt and extract type" {
    const value: u32 = SOCK.STREAM | SOCK.CLOEXEC | SOCK.NONBLOCK;
    const sock: Sock = @bitCast(value);
    try testing.expectEqual(sock.type, @as(Sock.Type, @enumFromInt(SOCK.STREAM)));
    try testing.expect(sock.flags.cloexec);
    try testing.expect(sock.flags.nonblock);
}

test "SocketFlags - round trip" {
    var original: Sock = .{ .type = .seqpacket };
    original.flags.cloexec = true;

    const value: u32 = @bitCast(original);
    const restored: Sock = @bitCast(value);

    try testing.expectEqual(original.type, restored.type);
    try testing.expectEqual(original.flags.cloexec, restored.flags.cloexec);
    try testing.expectEqual(original.flags.nonblock, restored.flags.nonblock);
}

test "SocketFlags - size check" {
    try testing.expectEqual(@sizeOf(u32), @sizeOf(Sock));
}

test "SocketFlags - different socket types" {
    const types = [_]Sock.Type{ .stream, .dgram, .raw, .rdm, .seqpacket, .dccp, .packet };

    for (types) |sock_type| {
        const flags: Sock = .{ .type = sock_type };
        try testing.expectEqual(sock_type, flags.type);
    }
}

test "Sock - default flags are zero" {
    const sock = Sock{ .type = .stream };
    try testing.expect(!sock.flags.cloexec);
    try testing.expect(!sock.flags.nonblock);
}

test "Sock.Flags - verify bit positions" {
    // Test that NONBLOCK flag is at correct position
    const nonblock_only = Sock{
        .type = @enumFromInt(0),
        .flags = .{ .nonblock = true },
    };
    const nonblock_value: u32 = @bitCast(nonblock_only);
    try testing.expectEqual(SOCK.NONBLOCK, nonblock_value);

    // Test that CLOEXEC flag is at correct position
    const cloexec_only = Sock{
        .type = @enumFromInt(0),
        .flags = .{ .cloexec = true },
    };
    const cloexec_value: u32 = @bitCast(cloexec_only);
    try testing.expectEqual(SOCK.CLOEXEC, cloexec_value);
}

/// enum sock_shutdown_cmd - Shutdown types
/// matches SHUT_* in kenel
pub const Shut = enum(u32) {
    /// SHUT_RD: shutdown receptions
    rd = 0,
    /// SHUT_WR: shutdown transmissions
    wd = 1,
    /// SHUT_RDWR: shutdown receptions/transmissions
    rdwr = 2,

    _,
};

/// matches AT_* and AT_STATX_*
pub const At = packed struct(u32) {
    _reserved: u8 = 0,
    /// Do not follow symbolic links
    symlink_nofollow: bool = false,
    /// Remove directory instead of unlinking file
    /// Or
    /// File handle is needed to compare object identity and may not be usable
    /// with open_by_handle_at(2)
    removedir_or_handle_fid: bool = false,
    /// Follow symbolic links.
    symlink_follow: bool = false,
    /// Suppress terminal automount traversal
    no_automount: bool = false,
    /// Allow empty relative pathname
    empty_path: bool = false,
    _unused: u2 = 0,
    /// Apply to the entire subtree
    recursive: bool = false,

    /// Special value used to indicate openat should use the current working directory
    pub const fdcwd = -100;

    /// Matches AT_STATX_* in kernel
    pub const Statx = packed struct(u32) {
        _unused: u13 = 0,
        /// - Force the attributes to be sync'd with the server
        force_sync: bool = false,
        /// - Don't sync attributes with the server
        dont_sync: bool = false,

        // https://github.com/torvalds/linux/blob/d3479214c05dbd07bc56f8823e7bd8719fcd39a9/tools/perf/trace/beauty/fs_at_flags.sh#L15
        /// AT_STATX_SYNC_TYPE is not a bit, its a mask of
        /// AT_STATX_SYNC_AS_STAT, AT_STATX_FORCE_SYNC and AT_STATX_DONT_SYNC
        /// Type of synchronisation required from statx()
        pub const sync_type = 0x6000;

        /// Do whatever stat() does
        /// This is the default and is very much filesystem-specific
        pub const sync_as_stat: Statx = .{
            .dont_sync = false,
            .force_sync = false,
        };
    };
};

pub const W = packed struct(u32) {
    nohang: bool = false,
    untraced_or_stopped: bool = false,
    exited: bool = false,
    continued: bool = false,
    _unused: u20 = 0,
    nowait: bool = false,
    _unused_1: u7 = 0,

    pub fn EXITSTATUS(s: W) u8 {
        return @intCast((@as(u32, @bitCast(s)) & 0xff00) >> 8);
    }

    pub fn TERMSIG(s: W) u32 {
        return @as(u32, @bitCast(s)) & 0x7f;
    }

    pub fn STOPSIG(s: W) u32 {
        return EXITSTATUS(s);
    }

    pub fn IFEXITED(s: W) bool {
        return TERMSIG(s) == 0;
    }

    pub fn IFSTOPPED(s: W) bool {
        return @as(u16, @truncate(((@as(u32, @bitCast(s)) & 0xffff) *% 0x10001) >> 8)) > 0x7f00;
    }

    pub fn IFSIGNALED(s: W) bool {
        return (s & 0xffff) -% 1 < 0xff;
    }
};
