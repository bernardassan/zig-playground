const std = @import("std");
const testing = std.testing;

/// Protocol Family
pub const ProtocolFamily = enum(u16) {
    unspec = 0,
    unix = 1,
    inet = 2,
    ax25 = 3,
    ipx = 4,
    appletalk = 5,
    netrom = 6,
    bridge = 7,
    atmpvc = 8,
    x25 = 9,
    inet6 = 10,
    rose = 11,
    decnet = 12,
    netbeui = 13,
    security = 14,
    key = 15,
    route = 16,
    packet = 17,
    ash = 18,
    econet = 19,
    atmsvc = 20,
    rds = 21,
    sna = 22,
    irda = 23,
    pppox = 24,
    wanpipe = 25,
    llc = 26,
    ib = 27,
    mpls = 28,
    can = 29,
    tipc = 30,
    bluetooth = 31,
    iucv = 32,
    rxrpc = 33,
    isdn = 34,
    phonet = 35,
    ieee802154 = 36,
    caif = 37,
    alg = 38,
    nfc = 39,
    vsock = 40,
    kcm = 41,
    qipcrtr = 42,
    smc = 43,
    xdp = 44,
    max = 45,
    _,

    // Aliases
    pub const local = ProtocolFamily.unix;
    pub const file = ProtocolFamily.unix;
    pub const netlink = ProtocolFamily.route;
};

/// Address Family (same values as Protocol Family)
pub const AddressFamily = ProtocolFamily;

// Legacy constants for backward compatibility
pub const PF = std.os.linux.PF;
pub const AF = PF;
test "ProtocolFamily - common values match constants" {
    try testing.expectEqual(PF.UNSPEC, @intFromEnum(ProtocolFamily.unspec));
    try testing.expectEqual(PF.LOCAL, @intFromEnum(ProtocolFamily.unix));
    try testing.expectEqual(PF.INET, @intFromEnum(ProtocolFamily.inet));
    try testing.expectEqual(PF.INET6, @intFromEnum(ProtocolFamily.inet6));
    try testing.expectEqual(PF.NETLINK, @intFromEnum(ProtocolFamily.route));
    try testing.expectEqual(PF.PACKET, @intFromEnum(ProtocolFamily.packet));
    try testing.expectEqual(PF.BLUETOOTH, @intFromEnum(ProtocolFamily.bluetooth));
    try testing.expectEqual(PF.VSOCK, @intFromEnum(ProtocolFamily.vsock));
    try testing.expectEqual(PF.XDP, @intFromEnum(ProtocolFamily.xdp));
}

test "ProtocolFamily - all values match constants" {
    try testing.expectEqual(PF.AX25, @intFromEnum(ProtocolFamily.ax25));
    try testing.expectEqual(PF.IPX, @intFromEnum(ProtocolFamily.ipx));
    try testing.expectEqual(PF.APPLETALK, @intFromEnum(ProtocolFamily.appletalk));
    try testing.expectEqual(PF.NETROM, @intFromEnum(ProtocolFamily.netrom));
    try testing.expectEqual(PF.BRIDGE, @intFromEnum(ProtocolFamily.bridge));
    try testing.expectEqual(PF.ATMPVC, @intFromEnum(ProtocolFamily.atmpvc));
    try testing.expectEqual(PF.X25, @intFromEnum(ProtocolFamily.x25));
    try testing.expectEqual(PF.ROSE, @intFromEnum(ProtocolFamily.rose));
    try testing.expectEqual(PF.DECnet, @intFromEnum(ProtocolFamily.decnet));
    try testing.expectEqual(PF.NETBEUI, @intFromEnum(ProtocolFamily.netbeui));
    try testing.expectEqual(PF.SECURITY, @intFromEnum(ProtocolFamily.security));
    try testing.expectEqual(PF.KEY, @intFromEnum(ProtocolFamily.key));
    try testing.expectEqual(PF.ASH, @intFromEnum(ProtocolFamily.ash));
    try testing.expectEqual(PF.ECONET, @intFromEnum(ProtocolFamily.econet));
    try testing.expectEqual(PF.ATMSVC, @intFromEnum(ProtocolFamily.atmsvc));
    try testing.expectEqual(PF.RDS, @intFromEnum(ProtocolFamily.rds));
    try testing.expectEqual(PF.SNA, @intFromEnum(ProtocolFamily.sna));
    try testing.expectEqual(PF.IRDA, @intFromEnum(ProtocolFamily.irda));
    try testing.expectEqual(PF.PPPOX, @intFromEnum(ProtocolFamily.pppox));
    try testing.expectEqual(PF.WANPIPE, @intFromEnum(ProtocolFamily.wanpipe));
    try testing.expectEqual(PF.LLC, @intFromEnum(ProtocolFamily.llc));
    try testing.expectEqual(PF.IB, @intFromEnum(ProtocolFamily.ib));
    try testing.expectEqual(PF.MPLS, @intFromEnum(ProtocolFamily.mpls));
    try testing.expectEqual(PF.CAN, @intFromEnum(ProtocolFamily.can));
    try testing.expectEqual(PF.TIPC, @intFromEnum(ProtocolFamily.tipc));
    try testing.expectEqual(PF.IUCV, @intFromEnum(ProtocolFamily.iucv));
    try testing.expectEqual(PF.RXRPC, @intFromEnum(ProtocolFamily.rxrpc));
    try testing.expectEqual(PF.ISDN, @intFromEnum(ProtocolFamily.isdn));
    try testing.expectEqual(PF.PHONET, @intFromEnum(ProtocolFamily.phonet));
    try testing.expectEqual(PF.IEEE802154, @intFromEnum(ProtocolFamily.ieee802154));
    try testing.expectEqual(PF.CAIF, @intFromEnum(ProtocolFamily.caif));
    try testing.expectEqual(PF.ALG, @intFromEnum(ProtocolFamily.alg));
    try testing.expectEqual(PF.NFC, @intFromEnum(ProtocolFamily.nfc));
    try testing.expectEqual(PF.KCM, @intFromEnum(ProtocolFamily.kcm));
    try testing.expectEqual(PF.QIPCRTR, @intFromEnum(ProtocolFamily.qipcrtr));
    try testing.expectEqual(PF.SMC, @intFromEnum(ProtocolFamily.smc));
    try testing.expectEqual(PF.MAX, @intFromEnum(ProtocolFamily.max));
}

test "ProtocolFamily - aliases" {
    try testing.expectEqual(ProtocolFamily.unix, ProtocolFamily.unix);
    try testing.expectEqual(ProtocolFamily.unix, ProtocolFamily.file);
    try testing.expectEqual(ProtocolFamily.route, ProtocolFamily.route);
    try testing.expectEqual(PF.LOCAL, PF.UNIX);
    try testing.expectEqual(PF.LOCAL, PF.FILE);
    try testing.expectEqual(PF.NETLINK, PF.ROUTE);
}

test "AddressFamily - is same as ProtocolFamily" {
    try testing.expectEqual(AF.INET, @intFromEnum(AddressFamily.inet));
    try testing.expectEqual(AF.INET6, @intFromEnum(AddressFamily.inet6));
    try testing.expectEqual(AF.UNIX, @intFromEnum(AddressFamily.unix));
}

test "ProtocolFamily - convert from u32" {
    const pf: ProtocolFamily = @enumFromInt(PF.INET);
    try testing.expectEqual(ProtocolFamily.inet, pf);

    const pf6: ProtocolFamily = @enumFromInt(AF.INET6);
    try testing.expectEqual(ProtocolFamily.inet6, pf6);
}

test "ProtocolFamily - round trip conversion" {
    const families = [_]ProtocolFamily{
        .unspec, .unix,      .inet,  .inet6, .route,
        .packet, .bluetooth, .vsock, .xdp,   .can,
    };

    for (families) |family| {
        const value: u32 = @intFromEnum(family);
        const restored: ProtocolFamily = @enumFromInt(value);
        try testing.expectEqual(family, restored);
    }
}

test "ProtocolFamily - usage in socket creation" {
    // Example: creating socket parameters
    const family = ProtocolFamily.inet;
    const family_value: u32 = @intFromEnum(family);
    try testing.expectEqual(AF.INET, family_value);
}

test "ProtocolFamily - parse from syscall return" {
    // Simulating parsing a family value from a syscall
    const raw_value: u32 = AF.INET6;
    const family: ProtocolFamily = @enumFromInt(raw_value);

    try testing.expectEqual(ProtocolFamily.inet6, family);

    // Can use switch
    switch (family) {
        .inet => unreachable,
        .inet6 => {},
        else => unreachable,
    }
}

test "AF and PF constants are equal" {
    try testing.expectEqual(PF.INET, AF.INET);
    try testing.expectEqual(PF.INET6, AF.INET6);
    try testing.expectEqual(PF.UNIX, AF.UNIX);
    try testing.expectEqual(PF.NETLINK, AF.NETLINK);
    try testing.expectEqual(PF.BLUETOOTH, AF.BLUETOOTH);
}
