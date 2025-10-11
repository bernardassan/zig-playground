const std = @import("std");
const testing = std.testing;
const builtin = @import("builtin");
const arch = builtin.cpu.arch;
const is_mips = arch.isMIPS();
const is_sparc = arch.isSPARC();

/// Socket option level for setsockopt(2)/getsockopt(2)
// https://github.com/torvalds/linux/blob/0d97f2067c166eb495771fede9f7b73999c67f66/include/linux/socket.h#L347C1-L388C22
pub const Sol = enum(u16) {
    ip = 0,
    socket = if (is_mips or is_sparc) 65535 else 1,
    tcp = 6,
    udp = 17,
    ipv6 = 41,
    icmpv6 = 58,
    sctp = 132,
    /// UDP-Lite (RFC 3828)
    udplite = 136,
    raw = 255,
    ipx = 256,
    ax25 = 257,
    atalk = 258,
    netrom = 259,
    rose = 260,
    decnet = 261,
    x25 = 262,
    packet = 263,
    /// ATM layer (cell level)
    atm = 264,
    /// ATM Adaption Layer (packet level)
    aal = 265,
    irda = 266,
    netbeui = 267,
    llc = 268,
    dccp = 269,
    netlink = 270,
    tipc = 271,
    rxrpc = 272,
    pppol2tp = 273,
    bluetooth = 274,
    pnpipe = 275,
    rds = 276,
    iucv = 277,
    caif = 278,
    alg = 279,
    nfc = 280,
    kcm = 281,
    tls = 282,
    xdp = 283,
    mptcp = 284,
    mctp = 285,
    smc = 286,
    vsock = 287,
    _,

    pub const IP: u16 = @intFromEnum(Sol.ip);
    pub const TCP: u16 = @intFromEnum(Sol.tcp);
    pub const UDP: u16 = @intFromEnum(Sol.udp);
    pub const IPV6: u16 = @intFromEnum(Sol.ipv6);
    pub const ICMPV6: u16 = @intFromEnum(Sol.icmpv6);
    pub const SCTP: u16 = @intFromEnum(Sol.sctp);
    pub const UDPLITE: u16 = @intFromEnum(Sol.udplite);
    pub const RAW: u16 = @intFromEnum(Sol.raw);
    pub const IPX: u16 = @intFromEnum(Sol.ipx);
    pub const AX25: u16 = @intFromEnum(Sol.ax25);
    pub const ATALK: u16 = @intFromEnum(Sol.atalk);
    pub const NETROM: u16 = @intFromEnum(Sol.netrom);
    pub const ROSE: u16 = @intFromEnum(Sol.rose);
    pub const DECNET: u16 = @intFromEnum(Sol.decnet);
    pub const X25: u16 = @intFromEnum(Sol.x25);
    pub const PACKET: u16 = @intFromEnum(Sol.packet);
    pub const ATM: u16 = @intFromEnum(Sol.atm);
    pub const AAL: u16 = @intFromEnum(Sol.aal);
    pub const IRDA: u16 = @intFromEnum(Sol.irda);
    pub const NETBEUI: u16 = @intFromEnum(Sol.netbeui);
    pub const LLC: u16 = @intFromEnum(Sol.llc);
    pub const DCCP: u16 = @intFromEnum(Sol.dccp);
    pub const NETLINK: u16 = @intFromEnum(Sol.netlink);
    pub const TIPC: u16 = @intFromEnum(Sol.tipc);
    pub const RXRPC: u16 = @intFromEnum(Sol.rxrpc);
    pub const PPPOL2TP: u16 = @intFromEnum(Sol.pppol2tp);
    pub const BLUETOOTH: u16 = @intFromEnum(Sol.bluetooth);
    pub const PNPIPE: u16 = @intFromEnum(Sol.pnpipe);
    pub const RDS: u16 = @intFromEnum(Sol.rds);
    pub const IUCV: u16 = @intFromEnum(Sol.iucv);
    pub const CAIF: u16 = @intFromEnum(Sol.caif);
    pub const ALG: u16 = @intFromEnum(Sol.alg);
    pub const NFC: u16 = @intFromEnum(Sol.nfc);
    pub const KCM: u16 = @intFromEnum(Sol.kcm);
    pub const TLS: u16 = @intFromEnum(Sol.tls);
    pub const XDP: u16 = @intFromEnum(Sol.xdp);
    pub const MPTCP: u16 = @intFromEnum(Sol.mptcp);
    pub const MCTP: u16 = @intFromEnum(Sol.mctp);
    pub const SMC: u16 = @intFromEnum(Sol.smc);
    pub const VSOCK: u16 = @intFromEnum(Sol.vsock);
};

// Legacy constants for backward compatibility
pub const SOL = struct {
    pub const IP = 0;
    // SOL_ICMP = 1 cannot be used due to Linux conflict
    pub const TCP = 6;
    pub const UDP = 17;
    pub const IPV6 = 41;
    pub const ICMPV6 = 58;
    pub const SCTP = 132;
    pub const UDPLITE = 136;
    pub const RAW = 255;
    pub const IPX = 256;
    pub const AX25 = 257;
    pub const ATALK = 258;
    pub const NETROM = 259;
    pub const ROSE = 260;
    pub const DECNET = 261;
    pub const X25 = 262;
    pub const PACKET = 263;
    pub const ATM = 264;
    pub const AAL = 265;
    pub const IRDA = 266;
    pub const NETBEUI = 267;
    pub const LLC = 268;
    pub const DCCP = 269;
    pub const NETLINK = 270;
    pub const TIPC = 271;
    pub const RXRPC = 272;
    pub const PPPOL2TP = 273;
    pub const BLUETOOTH = 274;
    pub const PNPIPE = 275;
    pub const RDS = 276;
    pub const IUCV = 277;
    pub const CAIF = 278;
    pub const ALG = 279;
    pub const NFC = 280;
    pub const KCM = 281;
    pub const TLS = 282;
    pub const XDP = 283;
    pub const MPTCP = 284;
    pub const MCTP = 285;
    pub const SMC = 286;
    pub const VSOCK = 287;
};

test "SocketOptionLevel - common levels match constants" {
    try testing.expectEqual(SOL.IP, @intFromEnum(Sol.ip));
    try testing.expectEqual(SOL.TCP, @intFromEnum(Sol.tcp));
    try testing.expectEqual(SOL.UDP, @intFromEnum(Sol.udp));
    try testing.expectEqual(SOL.IPV6, @intFromEnum(Sol.ipv6));
    try testing.expectEqual(SOL.ICMPV6, @intFromEnum(Sol.icmpv6));
    try testing.expectEqual(SOL.SCTP, @intFromEnum(Sol.sctp));
    try testing.expectEqual(SOL.RAW, @intFromEnum(Sol.raw));
}

test "SocketOptionLevel - all values match constants" {
    try testing.expectEqual(SOL.UDPLITE, @intFromEnum(Sol.udplite));
    try testing.expectEqual(SOL.IPX, @intFromEnum(Sol.ipx));
    try testing.expectEqual(SOL.AX25, @intFromEnum(Sol.ax25));
    try testing.expectEqual(SOL.ATALK, @intFromEnum(Sol.atalk));
    try testing.expectEqual(SOL.NETROM, @intFromEnum(Sol.netrom));
    try testing.expectEqual(SOL.ROSE, @intFromEnum(Sol.rose));
    try testing.expectEqual(SOL.DECNET, @intFromEnum(Sol.decnet));
    try testing.expectEqual(SOL.X25, @intFromEnum(Sol.x25));
    try testing.expectEqual(SOL.PACKET, @intFromEnum(Sol.packet));
    try testing.expectEqual(SOL.ATM, @intFromEnum(Sol.atm));
    try testing.expectEqual(SOL.AAL, @intFromEnum(Sol.aal));
    try testing.expectEqual(SOL.IRDA, @intFromEnum(Sol.irda));
    try testing.expectEqual(SOL.NETBEUI, @intFromEnum(Sol.netbeui));
    try testing.expectEqual(SOL.LLC, @intFromEnum(Sol.llc));
    try testing.expectEqual(SOL.DCCP, @intFromEnum(Sol.dccp));
    try testing.expectEqual(SOL.NETLINK, @intFromEnum(Sol.netlink));
    try testing.expectEqual(SOL.TIPC, @intFromEnum(Sol.tipc));
    try testing.expectEqual(SOL.RXRPC, @intFromEnum(Sol.rxrpc));
    try testing.expectEqual(SOL.PPPOL2TP, @intFromEnum(Sol.pppol2tp));
    try testing.expectEqual(SOL.BLUETOOTH, @intFromEnum(Sol.bluetooth));
    try testing.expectEqual(SOL.PNPIPE, @intFromEnum(Sol.pnpipe));
    try testing.expectEqual(SOL.RDS, @intFromEnum(Sol.rds));
    try testing.expectEqual(SOL.IUCV, @intFromEnum(Sol.iucv));
    try testing.expectEqual(SOL.CAIF, @intFromEnum(Sol.caif));
    try testing.expectEqual(SOL.ALG, @intFromEnum(Sol.alg));
    try testing.expectEqual(SOL.NFC, @intFromEnum(Sol.nfc));
    try testing.expectEqual(SOL.KCM, @intFromEnum(Sol.kcm));
    try testing.expectEqual(SOL.TLS, @intFromEnum(Sol.tls));
    try testing.expectEqual(SOL.XDP, @intFromEnum(Sol.xdp));
    try testing.expectEqual(SOL.MPTCP, @intFromEnum(Sol.mptcp));
    try testing.expectEqual(SOL.MCTP, @intFromEnum(Sol.mctp));
    try testing.expectEqual(SOL.SMC, @intFromEnum(Sol.smc));
    try testing.expectEqual(SOL.VSOCK, @intFromEnum(Sol.vsock));
}

test "SocketOptionLevel - convert from u16" {
    const level: Sol = @enumFromInt(SOL.TCP);
    try testing.expectEqual(Sol.tcp, level);

    const level_ipv6: Sol = @enumFromInt(41);
    try testing.expectEqual(Sol.ipv6, level_ipv6);
}

test "SocketOptionLevel - round trip conversion" {
    const levels = [_]Sol{
        .ip,    .tcp,    .udp,       .ipv6, .sctp,
        .raw,   .packet, .netlink,   .tls,  .xdp,
        .mptcp, .vsock,  .bluetooth,
    };

    for (levels) |level| {
        const value: u16 = @intFromEnum(level);
        const restored: Sol = @enumFromInt(value);
        try testing.expectEqual(level, restored);
    }
}

test "SocketOptionLevel - usage in setsockopt" {
    // Example: set TCP option
    const level = Sol.tcp;
    const level_value: u16 = @intFromEnum(level);
    try testing.expectEqual(SOL.TCP, level_value);
}

test "SocketOptionLevel - switch usage" {
    const level = Sol.ipv6;

    switch (level) {
        .ip => unreachable,
        .ipv6 => {},
        .tcp => unreachable,
        else => unreachable,
    }
}

test "SocketOptionLevel - transport protocol levels" {
    try testing.expectEqual(@as(u16, 6), @intFromEnum(Sol.tcp));
    try testing.expectEqual(@as(u16, 17), @intFromEnum(Sol.udp));
    try testing.expectEqual(@as(u16, 132), @intFromEnum(Sol.sctp));
    try testing.expectEqual(@as(u16, 269), @intFromEnum(Sol.dccp));
    try testing.expectEqual(@as(u16, 136), @intFromEnum(Sol.udplite));
}

test "SocketOptionLevel - IP protocol levels" {
    try testing.expectEqual(@as(u16, 0), @intFromEnum(Sol.ip));
    try testing.expectEqual(@as(u16, 41), @intFromEnum(Sol.ipv6));
    try testing.expectEqual(@as(u16, 58), @intFromEnum(Sol.icmpv6));
}

test "SocketOptionLevel - modern protocol levels" {
    try testing.expectEqual(@as(u16, 282), @intFromEnum(Sol.tls));
    try testing.expectEqual(@as(u16, 283), @intFromEnum(Sol.xdp));
    try testing.expectEqual(@as(u16, 284), @intFromEnum(Sol.mptcp));
    try testing.expectEqual(@as(u16, 287), @intFromEnum(Sol.vsock));
}

test "SocketOptionLevel - socket level operations" {
    // SOL_SOCKET is typically 1, but SOL_IP is 0
    // These levels are for protocol-specific options
    const ip_level = Sol.ip;
    try testing.expectEqual(@as(u16, 0), @intFromEnum(ip_level));
}

test "SocketOptionLevel - packet and raw socket levels" {
    try testing.expectEqual(@as(u16, 255), @intFromEnum(Sol.raw));
    try testing.expectEqual(@as(u16, 263), @intFromEnum(Sol.packet));
}

test "SocketOptionLevel - note about SOL_ICMP" {
    // SOL_ICMP = 1 is not defined due to Linux conflict
    // ICMP is handled via SOL_IP for IPv4 and SOL_ICMPV6 for IPv6
    try testing.expectEqual(@as(u16, 58), @intFromEnum(Sol.icmpv6));
}
