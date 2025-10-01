const std = @import("std");
const testing = std.testing;
const builtin = @import("builtin");

const is_mips = builtin.cpu.arch.isMIPS();
const is_sparc = builtin.cpu.arch.isSPARC();

pub const Sock = packed struct(u32) {
    type: Type,
    flags: Flags = .{},

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

    pub const Flags = if (is_sparc) packed struct(u25) {
        _: u14 = 0,
        nonblock: bool = false,
        _1: u7 = 0,
        cloexec: bool = false,
        _2: u2 = 0,
    } else if (is_mips) packed struct(u25) {
        _: u7 = 0,
        nonblock: bool = false,
        _1: u11 = 0,
        cloexec: bool = false,
        _2: u5 = 0,
    } else packed struct(u25) {
        _: u11 = 0,
        nonblock: bool = false,
        _1: u7 = 0,
        cloexec: bool = false,
        _2: u5 = 0,
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

// test "SocketType - enum values" {
//     try testing.expectEqual(SOCK.STREAM, @as(u32, @bitCast(Sock{ .type = .stream })));
//     try testing.expectEqual(SOCK.DGRAM, @as(u32, @bitCast(Sock{ .type = .dgram })));
//     try testing.expectEqual(SOCK.RAW, @as(u32, @bitCast(Sock{ .type = .raw })));
//     try testing.expectEqual(SOCK.RDM, @as(u32, @bitCast(Sock{ .type = .rdm })));
//     try testing.expectEqual(SOCK.SEQPACKET, @as(u32, @bitCast(Sock{ .type = .seqpacket })));
//     try testing.expectEqual(SOCK.DCCP, @as(u32, @bitCast(Sock{ .type = .dccp })));
//     try testing.expectEqual(SOCK.PACKET, @as(u32, @bitCast(Sock{ .type = .packet })));
// }

// test "SocketFlags - create with type only" {
//     const sock: Sock = .{ .type = .stream };
//     try testing.expect(!sock.flags.nonblock);
//     try testing.expect(!sock.flags.cloexec);
// }

// test "SocketFlags - type with CLOEXEC" {
//     var sock: Sock = .{ .type = .stream };
//     sock.flags.cloexec = true;

//     const expected: u32 = SOCK.STREAM | SOCK.CLOEXEC;
//     std.debug.print("sock is {}\n", .{sock});
//     try testing.expectEqual(expected, @as(u32, @bitCast(sock)));
// }

// test "SocketFlags - type with NONBLOCK" {
//     var sock: Sock = .{ .type = .dgram };
//     sock.flags.nonblock = true;

//     const expected: u32 = SOCK.DGRAM | SOCK.NONBLOCK;
//     try testing.expectEqual(expected, @as(u32, @bitCast(sock)));
// }

// test "SocketFlags - type with both flags" {
//     var sock: Sock = .{ .type = .stream };
//     sock.flags.nonblock = true;
//     sock.flags.cloexec = true;

//     const expected = SOCK.STREAM | SOCK.CLOEXEC | SOCK.NONBLOCK;
//     try testing.expectEqual(expected, @as(u32, @bitCast(sock)));
// }

// test "SocketFlags - fromInt and extract type" {
//     const value: u32 = SOCK.STREAM | SOCK.CLOEXEC | SOCK.NONBLOCK;
//     const sock: Sock = @bitCast(value);
//     try testing.expectEqual(sock.type, @as(Sock.Type, @enumFromInt(SOCK.STREAM)));
//     try testing.expect(sock.flags.cloexec);
//     try testing.expect(sock.flags.nonblock);
// }

// test "SocketFlags - round trip" {
//     var original: Sock = .{ .type = .seqpacket };
//     original.flags.cloexec = true;

//     const value: u32 = @bitCast(original);
//     const restored: Sock = @bitCast(value);

//     try testing.expectEqual(original.type, restored.type);
//     try testing.expectEqual(original.flags.cloexec, restored.flags.cloexec);
//     try testing.expectEqual(original.flags.nonblock, restored.flags.nonblock);
// }

// test "SocketFlags - size check" {
//     try testing.expectEqual(@sizeOf(u32), @sizeOf(Sock));
// }

// test "SocketFlags - different socket types" {
//     const types = [_]Sock.Type{ .stream, .dgram, .raw, .rdm, .seqpacket, .dccp, .packet };

//     for (types) |sock_type| {
//         const flags: Sock = .{ .type = sock_type };
//         try testing.expectEqual(sock_type, flags.type);
//     }
// }

test "Sock.Type - enum values match constants" {
    try testing.expectEqual(SOCK.STREAM, @intFromEnum(Sock.Type.stream));
    try testing.expectEqual(SOCK.DGRAM, @intFromEnum(Sock.Type.dgram));
    try testing.expectEqual(SOCK.RAW, @intFromEnum(Sock.Type.raw));
    try testing.expectEqual(SOCK.RDM, @intFromEnum(Sock.Type.rdm));
    try testing.expectEqual(SOCK.SEQPACKET, @intFromEnum(Sock.Type.seqpacket));
    try testing.expectEqual(SOCK.DCCP, @intFromEnum(Sock.Type.dccp));
    try testing.expectEqual(SOCK.PACKET, @intFromEnum(Sock.Type.packet));
}

test "Sock - type only" {
    const sock = Sock{ .type = .stream };
    const value: u32 = @bitCast(sock);
    try testing.expectEqual(SOCK.STREAM, value);
}

test "Sock - type with CLOEXEC" {
    const sock = Sock{
        .type = .stream,
        .flags = .{ .cloexec = true },
    };
    const value: u32 = @bitCast(sock);
    const expected = SOCK.STREAM | SOCK.CLOEXEC;
    try testing.expectEqual(expected, value);
}

test "Sock - type with NONBLOCK" {
    const sock = Sock{
        .type = .dgram,
        .flags = .{ .nonblock = true },
    };
    const value: u32 = @bitCast(sock);
    const expected = SOCK.DGRAM | SOCK.NONBLOCK;
    try testing.expectEqual(expected, value);
}

test "Sock - type with both flags" {
    const sock = Sock{
        .type = .stream,
        .flags = .{ .cloexec = true, .nonblock = true },
    };
    const value: u32 = @bitCast(sock);
    const expected = SOCK.STREAM | SOCK.CLOEXEC | SOCK.NONBLOCK;
    try testing.expectEqual(expected, value);
}

test "Sock - convert from u32" {
    const value: u32 = SOCK.STREAM | SOCK.CLOEXEC | SOCK.NONBLOCK;
    const sock: Sock = @bitCast(value);

    try testing.expectEqual(Sock.Type.stream, sock.type);
    try testing.expect(sock.flags.cloexec);
    try testing.expect(sock.flags.nonblock);
}

test "Sock - round trip conversion" {
    const original = Sock{
        .type = .seqpacket,
        .flags = .{ .cloexec = true },
    };
    const value: u32 = @bitCast(original);
    const restored: Sock = @bitCast(value);

    try testing.expectEqual(original.type, restored.type);
    try testing.expectEqual(original.flags.cloexec, restored.flags.cloexec);
    try testing.expectEqual(original.flags.nonblock, restored.flags.nonblock);
}

test "Sock - size check" {
    try testing.expectEqual(@sizeOf(u32), @sizeOf(Sock));
    try testing.expectEqual(4, @sizeOf(Sock));
}

test "Sock - all socket types" {
    const types = [_]Sock.Type{ .stream, .dgram, .raw, .rdm, .seqpacket, .dccp, .packet };

    for (types) |sock_type| {
        const sock = Sock{ .type = sock_type };
        const value: u32 = @bitCast(sock);
        const restored: Sock = @bitCast(value);
        try testing.expectEqual(sock_type, restored.type);
    }
}

test "Sock - default flags are zero" {
    const sock = Sock{ .type = .stream };
    try testing.expect(!sock.flags.cloexec);
    try testing.expect(!sock.flags.nonblock);
}

test "Sock - DGRAM with flags" {
    const sock = Sock{
        .type = .dgram,
        .flags = .{ .nonblock = true, .cloexec = true },
    };
    const value: u32 = @bitCast(sock);
    const expected = SOCK.DGRAM | SOCK.NONBLOCK | SOCK.CLOEXEC;
    try testing.expectEqual(expected, value);
}

test "Sock - RAW socket" {
    const sock = Sock{ .type = .raw };
    const value: u32 = @bitCast(sock);
    try testing.expectEqual(SOCK.RAW, value);
}

test "Sock - PACKET socket with CLOEXEC" {
    const sock = Sock{
        .type = .packet,
        .flags = .{ .cloexec = true },
    };
    const value: u32 = @bitCast(sock);
    const expected = SOCK.PACKET | SOCK.CLOEXEC;
    try testing.expectEqual(expected, value);
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
