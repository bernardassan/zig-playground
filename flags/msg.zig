const std = @import("std");
const testing = std.testing;

pub const Msg = packed struct(u32) {
    /// Process out-of-band data
    oob: bool = false,
    /// Peek at incoming message
    peek: bool = false,
    /// Send without using routing tables
    dontroute: bool = false,
    /// Control data truncated
    ctrunc: bool = false,
    /// Do not send. Only probe path (e.g. for MTU)
    probe: bool = false,
    /// Normal data truncated
    trunc: bool = false,
    /// Nonblocking I/O
    dontwait: bool = false,
    /// End of record
    eor: bool = false,
    /// Wait for a full request
    waitall: bool = false,
    /// FIN flag
    fin: bool = false,
    /// SYN flag
    syn: bool = false,
    /// Confirm path validity
    confirm: bool = false,
    /// RST flag
    rst: bool = false,
    /// Fetch message from error queue
    errqueue: bool = false,
    /// Do not generate SIGPIPE
    nosignal: bool = false,
    /// Sender will send more
    more: bool = false,
    /// recvmmsg(): block until 1+ packets available
    waitforone: bool = false,
    _18: u1 = 0,
    /// sendmmsg(): more messages coming
    batch: bool = false,
    /// sendpage() internal: page frags are not shared
    no_shared_frags: bool = false,
    /// sendpage() internal: page may carry plain text and require encryption
    sendpage_decrypted: bool = false,
    _22: u4 = 0,
    // COMMIT: new flags
    /// Receive devmem skbs as cmsg
    sock_devmem: bool = false,
    /// Use user data in kernel path
    zerocopy: bool = false,
    /// Splice the pages from the iterator in sendmsg()
    splice_pages: bool = false,
    _29: u1 = 0,
    /// Send data in TCP SYN
    fastopen: bool = false,
    /// Set close_on_exec for file descriptor received through SCM_RIGHTS
    cmsg_cloexec: bool = false,
    _: u1 = 0,

    // DEPRECATED CONSTANTS
    pub const OOB: u32 = @bitCast(Msg{ .oob = true });
    pub const PEEK: u32 = @bitCast(Msg{ .peek = true });
    pub const DONTROUTE: u32 = @bitCast(Msg{ .dontroute = true });
    pub const CTRUNC: u32 = @bitCast(Msg{ .ctrunc = true });
    // fix typo PROBE not PROXY
    pub const PROBE: u32 = @bitCast(Msg{ .probe = true });
    pub const TRUNC: u32 = @bitCast(Msg{ .trunc = true });
    pub const DONTWAIT: u32 = @bitCast(Msg{ .dontwait = true });
    pub const EOR: u32 = @bitCast(Msg{ .eor = true });
    pub const WAITALL: u32 = @bitCast(Msg{ .waitall = true });
    pub const FIN: u32 = @bitCast(Msg{ .fin = true });
    pub const SYN: u32 = @bitCast(Msg{ .syn = true });
    pub const CONFIRM: u32 = @bitCast(Msg{ .confirm = true });
    pub const RST: u32 = @bitCast(Msg{ .rst = true });
    pub const ERRQUEUE: u32 = @bitCast(Msg{ .errqueue = true });
    pub const NOSIGNAL: u32 = @bitCast(Msg{ .nosignal = true });
    pub const MORE: u32 = @bitCast(Msg{ .more = true });
    pub const WAITFORONE: u32 = @bitCast(Msg{ .waitforone = true });
    pub const BATCH: u32 = @bitCast(Msg{ .batch = true });
    pub const ZEROCOPY: u32 = @bitCast(Msg{ .zerocopy = true });
    pub const FASTOPEN: u32 = @bitCast(Msg{ .fastopen = true });
    pub const CMSG_CLOEXEC: u32 = @bitCast(Msg{ .cmsg_cloexec = true });
};

// Legacy constants for backward compatibility
pub const MSG = struct {
    pub const OOB: u32 = 1;
    pub const PEEK: u32 = 2;
    pub const DONTROUTE: u32 = 4;
    pub const TRYHARD: u32 = 4;
    pub const CTRUNC: u32 = 8;
    pub const PROBE: u32 = 0x10;
    pub const TRUNC: u32 = 0x20;
    pub const DONTWAIT: u32 = 0x40;
    pub const EOR: u32 = 0x80;
    pub const WAITALL: u32 = 0x100;
    pub const FIN: u32 = 0x200;
    pub const SYN: u32 = 0x400;
    pub const CONFIRM: u32 = 0x800;
    pub const RST: u32 = 0x1000;
    pub const ERRQUEUE: u32 = 0x2000;
    pub const NOSIGNAL: u32 = 0x4000;
    pub const MORE: u32 = 0x8000;
    pub const WAITFORONE: u32 = 0x10000;
    pub const SENDPAGE_NOPOLICY: u32 = 0x10000;
    pub const BATCH: u32 = 0x40000;
    pub const EOF: u32 = MSG.FIN;
    pub const NO_SHARED_FRAGS: u32 = 0x80000;
    pub const SENDPAGE_DECRYPTED: u32 = 0x100000;
};

test "MsgFlags - individual flags match constants" {
    try testing.expectEqual(MSG.OOB, @as(u32, @bitCast(Msg{ .oob = true })));
    try testing.expectEqual(MSG.OOB, Msg.OOB);
    try testing.expectEqual(MSG.PEEK, @as(u32, @bitCast(Msg{ .peek = true })));
    try testing.expectEqual(MSG.PEEK, Msg.PEEK);
    try testing.expectEqual(MSG.DONTROUTE, @as(u32, @bitCast(Msg{ .dontroute = true })));
    try testing.expectEqual(MSG.DONTROUTE, Msg.DONTROUTE);
    try testing.expectEqual(MSG.CTRUNC, @as(u32, @bitCast(Msg{ .ctrunc = true })));
    try testing.expectEqual(MSG.CTRUNC, Msg.CTRUNC);
    try testing.expectEqual(MSG.PROBE, @as(u32, @bitCast(Msg{ .probe = true })));
    try testing.expectEqual(MSG.PROBE, Msg.PROBE);
    try testing.expectEqual(MSG.TRUNC, @as(u32, @bitCast(Msg{ .trunc = true })));
    try testing.expectEqual(MSG.TRUNC, Msg.TRUNC);
    try testing.expectEqual(MSG.DONTWAIT, @as(u32, @bitCast(Msg{ .dontwait = true })));
    try testing.expectEqual(MSG.DONTWAIT, Msg.DONTWAIT);
    try testing.expectEqual(MSG.EOR, @as(u32, @bitCast(Msg{ .eor = true })));
    try testing.expectEqual(MSG.EOR, Msg.EOR);
    try testing.expectEqual(MSG.WAITALL, @as(u32, @bitCast(Msg{ .waitall = true })));
    try testing.expectEqual(MSG.WAITALL, Msg.WAITALL);
    try testing.expectEqual(MSG.FIN, @as(u32, @bitCast(Msg{ .fin = true })));
    try testing.expectEqual(MSG.FIN, Msg.FIN);
    try testing.expectEqual(MSG.SYN, @as(u32, @bitCast(Msg{ .syn = true })));
    try testing.expectEqual(MSG.SYN, Msg.SYN);
    try testing.expectEqual(MSG.CONFIRM, @as(u32, @bitCast(Msg{ .confirm = true })));
    try testing.expectEqual(MSG.CONFIRM, Msg.CONFIRM);
    try testing.expectEqual(MSG.RST, @as(u32, @bitCast(Msg{ .rst = true })));
    try testing.expectEqual(MSG.RST, Msg.RST);
    try testing.expectEqual(MSG.ERRQUEUE, @as(u32, @bitCast(Msg{ .errqueue = true })));
    try testing.expectEqual(MSG.ERRQUEUE, Msg.ERRQUEUE);
    try testing.expectEqual(MSG.NOSIGNAL, @as(u32, @bitCast(Msg{ .nosignal = true })));
    try testing.expectEqual(MSG.NOSIGNAL, Msg.NOSIGNAL);
    try testing.expectEqual(MSG.MORE, @as(u32, @bitCast(Msg{ .more = true })));
    try testing.expectEqual(MSG.MORE, Msg.MORE);
    try testing.expectEqual(MSG.WAITFORONE, @as(u32, @bitCast(Msg{ .waitforone = true })));
    try testing.expectEqual(MSG.WAITFORONE, Msg.WAITFORONE);
    try testing.expectEqual(MSG.BATCH, @as(u32, @bitCast(Msg{ .batch = true })));
    try testing.expectEqual(MSG.BATCH, Msg.BATCH);
    try testing.expectEqual(MSG.NO_SHARED_FRAGS, @as(u32, @bitCast(Msg{ .no_shared_frags = true })));
    try testing.expectEqual(MSG.SENDPAGE_DECRYPTED, @as(u32, @bitCast(Msg{ .sendpage_decrypted = true })));
}

test "MsgFlags - combine multiple flags" {
    const flags = Msg{
        .peek = true,
        .dontwait = true,
        .nosignal = true,
    };
    const expected = MSG.PEEK | MSG.DONTWAIT | MSG.NOSIGNAL;
    try testing.expectEqual(expected, @as(u32, @bitCast(flags)));
}

test "MsgFlags - convert from u32" {
    const value: u32 = MSG.OOB | MSG.PEEK | MSG.DONTWAIT;
    const flags: Msg = @bitCast(value);

    try testing.expect(flags.oob);
    try testing.expect(flags.peek);
    try testing.expect(flags.dontwait);
    try testing.expect(!flags.trunc);
    try testing.expect(!flags.waitall);
}

test "MsgFlags - default is all false" {
    const flags = Msg{};
    try testing.expectEqual(@as(u32, 0), @as(u32, @bitCast(flags)));
}

test "MsgFlags - size check" {
    try testing.expectEqual(@sizeOf(u32), @sizeOf(Msg));
}

test "MsgFlags - round trip conversion" {
    const original = Msg{
        .peek = true,
        .dontwait = true,
        .waitall = true,
        .nosignal = true,
    };
    const value: u32 = @bitCast(original);
    const restored: Msg = @bitCast(value);
    try testing.expectEqual(original, restored);
}

test "MsgFlags - aliases match constants" {
    try testing.expectEqual(MSG.DONTROUTE, MSG.TRYHARD);
    try testing.expectEqual(MSG.FIN, MSG.EOF);
}

test "MsgFlags - common recv flags" {
    const flags = Msg{
        .peek = true,
        .dontwait = true,
    };
    const value: u32 = @bitCast(flags);
    const expected = MSG.PEEK | MSG.DONTWAIT;
    try testing.expectEqual(expected, value);
}

test "MsgFlags - common send flags" {
    const flags = Msg{
        .nosignal = true,
        .more = true,
    };
    const value: u32 = @bitCast(flags);
    const expected = MSG.NOSIGNAL | MSG.MORE;
    try testing.expectEqual(expected, value);
}

test "MsgFlags - waitforone and sendpage_nopolicy share bit" {
    // These two flags share the same bit (0x10000)
    const flags = Msg{ .waitforone = true };
    const value: u32 = @bitCast(flags);
    try testing.expectEqual(MSG.WAITFORONE, value);
    try testing.expectEqual(MSG.SENDPAGE_NOPOLICY, value);
}

test "MsgFlags - error queue flag" {
    const flags = Msg{ .errqueue = true };
    const value: u32 = @bitCast(flags);
    try testing.expectEqual(MSG.ERRQUEUE, value);
}

test "MsgFlags - TCP flags" {
    const flags = Msg{
        .syn = true,
        .fin = true,
        .rst = true,
    };
    const value: u32 = @bitCast(flags);
    const expected = MSG.SYN | MSG.FIN | MSG.RST;
    try testing.expectEqual(expected, value);
}

test "MsgFlags - truncation flags" {
    const flags = Msg{
        .trunc = true,
        .ctrunc = true,
    };
    const value: u32 = @bitCast(flags);
    const expected = MSG.TRUNC | MSG.CTRUNC;
    try testing.expectEqual(expected, value);
}

test "MsgFlags - internal sendpage flags" {
    const flags = Msg{
        .no_shared_frags = true,
        .sendpage_decrypted = true,
    };
    const value: u32 = @bitCast(flags);
    const expected = MSG.NO_SHARED_FRAGS | MSG.SENDPAGE_DECRYPTED;
    try testing.expectEqual(expected, value);
}

test "MsgFlags - batch operations" {
    const flags = Msg{
        .batch = true,
        .more = true,
    };
    const value: u32 = @bitCast(flags);
    const expected = MSG.BATCH | MSG.MORE;
    try testing.expectEqual(expected, value);
}

test "MsgFlags - all common user flags" {
    const flags = Msg{
        .oob = true,
        .peek = true,
        .dontwait = true,
        .waitall = true,
        .nosignal = true,
    };
    const value: u32 = @bitCast(flags);
    const expected = MSG.OOB | MSG.PEEK | MSG.DONTWAIT | MSG.WAITALL | MSG.NOSIGNAL;
    try testing.expectEqual(expected, value);
}
