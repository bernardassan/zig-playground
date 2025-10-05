const std = @import("std");
const testing = std.testing;

pub const IPPROTO_ = std.os.linux.IPPROTO;
pub const IPPROTO = IpProto;
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

    // Legacy constants for backward compatibility
    pub const IP: u16 = @intFromEnum(IpProto.ip);
    pub const HOPOPTS: u16 = @intFromEnum(hopopts);
    pub const ICMP: u16 = @intFromEnum(IpProto.icmp);
    pub const IGMP: u16 = @intFromEnum(IpProto.igmp);
    pub const IPIP: u16 = @intFromEnum(IpProto.ipip);
    pub const TCP: u16 = @intFromEnum(IpProto.tcp);
    pub const EGP: u16 = @intFromEnum(IpProto.egp);
    pub const PUP: u16 = @intFromEnum(IpProto.pup);
    pub const UDP: u16 = @intFromEnum(IpProto.udp);
    pub const IDP: u16 = @intFromEnum(IpProto.idp);
    pub const TP: u16 = @intFromEnum(IpProto.tp);
    pub const DCCP: u16 = @intFromEnum(IpProto.dccp);
    pub const IPV6: u16 = @intFromEnum(IpProto.ipv6);
    pub const ROUTING: u16 = @intFromEnum(IpProto.routing);
    pub const FRAGMENT: u16 = @intFromEnum(IpProto.fragment);
    pub const RSVP: u16 = @intFromEnum(IpProto.rsvp);
    pub const GRE: u16 = @intFromEnum(IpProto.gre);
    pub const ESP: u16 = @intFromEnum(IpProto.esp);
    pub const AH: u16 = @intFromEnum(IpProto.ah);
    pub const ICMPV6: u16 = @intFromEnum(IpProto.icmpv6);
    pub const NONE: u16 = @intFromEnum(IpProto.none);
    pub const DSTOPTS: u16 = @intFromEnum(IpProto.DSTOPTS);
    pub const MTP: u16 = @intFromEnum(IpProto.mtp);
    pub const BEETPH: u16 = @intFromEnum(IpProto.beetph);
    pub const ENCAP: u16 = @intFromEnum(IpProto.encap);
    pub const PIM: u16 = @intFromEnum(IpProto.pim);
    pub const COMP: u16 = @intFromEnum(IpProto.comp);
    pub const SCTP: u16 = @intFromEnum(IpProto.sctp);
    pub const MH: u16 = @intFromEnum(IpProto.mh);
    pub const UDPLITE: u16 = @intFromEnum(IpProto.udplite);
    pub const MPLS: u16 = @intFromEnum(IpProto.mpls);
    pub const RAW: u16 = @intFromEnum(IpProto.raw);
    pub const MAX: u16 = @intFromEnum(IpProto.max);
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
