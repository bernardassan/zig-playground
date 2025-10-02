const std = @import("std");
const testing = std.testing;

/// IP Protocol numbers
pub const IpProto = enum(u16) {
    ip = 0,
    icmp = 1,
    igmp = 2,
    ipip = 4,
    tcp = 6,
    egp = 8,
    pup = 12,
    udp = 17,
    idp = 22,
    tp = 29,
    dccp = 33,
    ipv6 = 41,
    routing = 43,
    fragment = 44,
    rsvp = 46,
    gre = 47,
    esp = 50,
    ah = 51,
    icmpv6 = 58,
    none = 59,
    dstopts = 60,
    mtp = 92,
    beetph = 94,
    encap = 98,
    pim = 103,
    comp = 108,
    sctp = 132,
    mh = 135,
    udplite = 136,
    mpls = 137,
    raw = 255,
    max = 256,
    _,

    // Aliases
    pub const hopopts = IpProto.ip;
};

// Legacy constants for backward compatibility
pub const IPPROTO = struct {
    pub const IP = 0;
    pub const HOPOPTS = 0;
    pub const ICMP = 1;
    pub const IGMP = 2;
    pub const IPIP = 4;
    pub const TCP = 6;
    pub const EGP = 8;
    pub const PUP = 12;
    pub const UDP = 17;
    pub const IDP = 22;
    pub const TP = 29;
    pub const DCCP = 33;
    pub const IPV6 = 41;
    pub const ROUTING = 43;
    pub const FRAGMENT = 44;
    pub const RSVP = 46;
    pub const GRE = 47;
    pub const ESP = 50;
    pub const AH = 51;
    pub const ICMPV6 = 58;
    pub const NONE = 59;
    pub const DSTOPTS = 60;
    pub const MTP = 92;
    pub const BEETPH = 94;
    pub const ENCAP = 98;
    pub const PIM = 103;
    pub const COMP = 108;
    pub const SCTP = 132;
    pub const MH = 135;
    pub const UDPLITE = 136;
    pub const MPLS = 137;
    pub const RAW = 255;
    pub const MAX = 256;
};

test "IpProtocol - common protocols match constants" {
    try testing.expectEqual(IPPROTO.IP, @intFromEnum(IpProto.ip));
    try testing.expectEqual(IPPROTO.ICMP, @intFromEnum(IpProto.icmp));
    try testing.expectEqual(IPPROTO.TCP, @intFromEnum(IpProto.tcp));
    try testing.expectEqual(IPPROTO.UDP, @intFromEnum(IpProto.udp));
    try testing.expectEqual(IPPROTO.IPV6, @intFromEnum(IpProto.ipv6));
    try testing.expectEqual(IPPROTO.ICMPV6, @intFromEnum(IpProto.icmpv6));
    try testing.expectEqual(IPPROTO.SCTP, @intFromEnum(IpProto.sctp));
    try testing.expectEqual(IPPROTO.RAW, @intFromEnum(IpProto.raw));
}

test "IpProtocol - all values match constants" {
    try testing.expectEqual(IPPROTO.IGMP, @intFromEnum(IpProto.igmp));
    try testing.expectEqual(IPPROTO.IPIP, @intFromEnum(IpProto.ipip));
    try testing.expectEqual(IPPROTO.EGP, @intFromEnum(IpProto.egp));
    try testing.expectEqual(IPPROTO.PUP, @intFromEnum(IpProto.pup));
    try testing.expectEqual(IPPROTO.IDP, @intFromEnum(IpProto.idp));
    try testing.expectEqual(IPPROTO.TP, @intFromEnum(IpProto.tp));
    try testing.expectEqual(IPPROTO.DCCP, @intFromEnum(IpProto.dccp));
    try testing.expectEqual(IPPROTO.ROUTING, @intFromEnum(IpProto.routing));
    try testing.expectEqual(IPPROTO.FRAGMENT, @intFromEnum(IpProto.fragment));
    try testing.expectEqual(IPPROTO.RSVP, @intFromEnum(IpProto.rsvp));
    try testing.expectEqual(IPPROTO.GRE, @intFromEnum(IpProto.gre));
    try testing.expectEqual(IPPROTO.ESP, @intFromEnum(IpProto.esp));
    try testing.expectEqual(IPPROTO.AH, @intFromEnum(IpProto.ah));
    try testing.expectEqual(IPPROTO.NONE, @intFromEnum(IpProto.none));
    try testing.expectEqual(IPPROTO.DSTOPTS, @intFromEnum(IpProto.dstopts));
    try testing.expectEqual(IPPROTO.MTP, @intFromEnum(IpProto.mtp));
    try testing.expectEqual(IPPROTO.BEETPH, @intFromEnum(IpProto.beetph));
    try testing.expectEqual(IPPROTO.ENCAP, @intFromEnum(IpProto.encap));
    try testing.expectEqual(IPPROTO.PIM, @intFromEnum(IpProto.pim));
    try testing.expectEqual(IPPROTO.COMP, @intFromEnum(IpProto.comp));
    try testing.expectEqual(IPPROTO.MH, @intFromEnum(IpProto.mh));
    try testing.expectEqual(IPPROTO.UDPLITE, @intFromEnum(IpProto.udplite));
    try testing.expectEqual(IPPROTO.MPLS, @intFromEnum(IpProto.mpls));
    try testing.expectEqual(IPPROTO.MAX, @intFromEnum(IpProto.max));
}

test "IpProtocol - hopopts alias" {
    try testing.expectEqual(IpProto.ip, IpProto.hopopts);
    try testing.expectEqual(IPPROTO.IP, IPPROTO.HOPOPTS);
}

test "IpProtocol - convert from integer" {
    const proto: IpProto = @enumFromInt(IPPROTO.TCP);
    try testing.expectEqual(IpProto.tcp, proto);

    const proto_udp: IpProto = @enumFromInt(17);
    try testing.expectEqual(IpProto.udp, proto_udp);
}

test "IpProtocol - round trip conversion" {
    const protocols = [_]IpProto{
        .ip,     .icmp, .tcp,     .udp,  .ipv6,
        .icmpv6, .sctp, .dccp,    .gre,  .esp,
        .ah,     .raw,  .udplite, .mpls,
    };

    for (protocols) |proto| {
        const value: u16 = @intFromEnum(proto);
        const restored: IpProto = @enumFromInt(value);
        try testing.expectEqual(proto, restored);
    }
}

test "IpProtocol - switch usage" {
    const proto = IpProto.tcp;

    switch (proto) {
        .tcp => {},
        .udp => unreachable,
        .icmp => unreachable,
        else => unreachable,
    }
}

test "IpProtocol - common transport protocols" {
    // Verify the most commonly used protocols
    try testing.expectEqual(@as(u16, 6), @intFromEnum(IpProto.tcp));
    try testing.expectEqual(@as(u16, 17), @intFromEnum(IpProto.udp));
    try testing.expectEqual(@as(u16, 132), @intFromEnum(IpProto.sctp));
    try testing.expectEqual(@as(u16, 33), @intFromEnum(IpProto.dccp));
}

test "IpProtocol - ICMP variants" {
    try testing.expectEqual(@as(u16, 1), @intFromEnum(IpProto.icmp));
    try testing.expectEqual(@as(u16, 58), @intFromEnum(IpProto.icmpv6));
}

test "IpProtocol - IPsec protocols" {
    try testing.expectEqual(@as(u16, 50), @intFromEnum(IpProto.esp));
    try testing.expectEqual(@as(u16, 51), @intFromEnum(IpProto.ah));
}

test "IpProtocol - IPv6 extension headers" {
    try testing.expectEqual(@as(u16, 0), @intFromEnum(IpProto.hopopts));
    try testing.expectEqual(@as(u16, 43), @intFromEnum(IpProto.routing));
    try testing.expectEqual(@as(u16, 44), @intFromEnum(IpProto.fragment));
    try testing.expectEqual(@as(u16, 60), @intFromEnum(IpProto.dstopts));
}

test "IpProtocol - socket creation example" {
    // Example: create TCP socket
    const proto = IpProto.tcp;
    const proto_value: u16 = @intFromEnum(proto);
    try testing.expectEqual(@as(u16, 6), proto_value);

    // Example: create UDP socket
    const udp_proto = IpProto.udp;
    try testing.expectEqual(@as(u16, 17), @intFromEnum(udp_proto));
}

test "IpProtocol - parse from packet header" {
    // Simulating parsing protocol from IP header
    const raw_protocol: u16 = 6; // TCP
    const proto: IpProto = @enumFromInt(raw_protocol);

    try testing.expectEqual(IpProto.tcp, proto);

    switch (proto) {
        .tcp => {}, // Handle TCP packet
        .udp => unreachable,
        .icmp => unreachable,
        else => unreachable,
    }
}

test "IpProtocol - special values" {
    // NONE is used in IPv6 to indicate no next header
    try testing.expectEqual(@as(u16, 59), @intFromEnum(IpProto.none));

    // RAW is special for raw sockets
    try testing.expectEqual(@as(u16, 255), @intFromEnum(IpProto.raw));

    // MAX is the upper bound
    try testing.expectEqual(@as(u16, 256), @intFromEnum(IpProto.max));
}
