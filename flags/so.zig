const std = @import("std");

const builtin = @import("builtin");
const is_mips = builtin.cpu.arch.isMIPS();
const is_ppc = builtin.cpu.arch.isPowerPC();
const is_sparc = builtin.cpu.arch.isSPARC();

pub const SockOpt = if (is_mips) enum(u16) {
    debug = 1,
    reuseaddr = 0x0004,
    keepalive = 0x0008,
    dontroute = 0x0010,
    broadcast = 0x0020,
    linger = 0x0080,
    oobinline = 0x0100,
    reuseport = 0x0200,
    sndbuf = 0x1001,
    rcvbuf = 0x1002,
    sndlowat = 0x1003,
    rcvlowat = 0x1004,
    sndtimeo = 0x1005,
    rcvtimeo = 0x1006,
    @"error" = 0x1007,
    type = 0x1008,
    acceptconn = 0x1009,
    protocol = 0x1028,
    domain = 0x1029,
    no_check = 11,
    priority = 12,
    bsdcompat = 14,
    passcred = 17,
    peercred = 18,
    peersec = 30,
    sndbufforce = 31,
    rcvbufforce = 33,
    security_authentication = 22,
    security_encryption_transport = 23,
    security_encryption_network = 24,
    bindtodevice = 25,
    attach_filter = 26,
    detach_filter = 27,
    peername = 28,
    timestamp_old = 29,
    passsec = 34,
    timestampns_old = 35,
    mark = 36,
    timestamping_old = 37,
    rxq_ovfl = 40,
    wifi_status = 41,
    peek_off = 42,
    nofcs = 43,
    lock_filter = 44,
    select_err_queue = 45,
    busy_poll = 46,
    max_pacing_rate = 47,
    bpf_extensions = 48,
    incoming_cpu = 49,
    attach_bpf = 50,
    attach_reuseport_cbpf = 51,
    attach_reuseport_ebpf = 52,
    cnx_advice = 53,
    meminfo = 55,
    incoming_napi_id = 56,
    cookie = 57,
    peergroups = 59,
    zerocopy = 60,
    txtime = 61,
    bindtoifindex = 62,
    timestamp_new = 63,
    timestampns_new = 64,
    timestamping_new = 65,
    rcvtimeo_new = 66,
    sndtimeo_new = 67,
    detach_reuseport_bpf = 68,
    _,
} else if (is_ppc) enum(u16) {
    debug = 1,
    reuseaddr = 2,
    type = 3,
    @"error" = 4,
    dontroute = 5,
    broadcast = 6,
    sndbuf = 7,
    rcvbuf = 8,
    keepalive = 9,
    oobinline = 10,
    no_check = 11,
    priority = 12,
    linger = 13,
    bsdcompat = 14,
    reuseport = 15,
    rcvlowat = 16,
    sndlowat = 17,
    rcvtimeo = 18,
    sndtimeo = 19,
    passcred = 20,
    peercred = 21,
    acceptconn = 30,
    peersec = 31,
    sndbufforce = 32,
    rcvbufforce = 33,
    protocol = 38,
    domain = 39,
    security_authentication = 22,
    security_encryption_transport = 23,
    security_encryption_network = 24,
    bindtodevice = 25,
    attach_filter = 26,
    detach_filter = 27,
    peername = 28,
    timestamp_old = 29,
    passsec = 34,
    timestampns_old = 35,
    mark = 36,
    timestamping_old = 37,
    rxq_ovfl = 40,
    wifi_status = 41,
    peek_off = 42,
    nofcs = 43,
    lock_filter = 44,
    select_err_queue = 45,
    busy_poll = 46,
    max_pacing_rate = 47,
    bpf_extensions = 48,
    incoming_cpu = 49,
    attach_bpf = 50,
    attach_reuseport_cbpf = 51,
    attach_reuseport_ebpf = 52,
    cnx_advice = 53,
    meminfo = 55,
    incoming_napi_id = 56,
    cookie = 57,
    peergroups = 59,
    zerocopy = 60,
    txtime = 61,
    bindtoifindex = 62,
    timestamp_new = 63,
    timestampns_new = 64,
    timestamping_new = 65,
    rcvtimeo_new = 66,
    sndtimeo_new = 67,
    detach_reuseport_bpf = 68,
    _,
} else if (is_sparc) enum(u16) {
    debug = 1,
    reuseaddr = 4,
    type = 4104,
    @"error" = 4103,
    dontroute = 16,
    broadcast = 32,
    sndbuf = 4097,
    rcvbuf = 4098,
    keepalive = 8,
    oobinline = 256,
    no_check = 11,
    priority = 12,
    linger = 128,
    bsdcompat = 1024,
    reuseport = 512,
    passcred = 2,
    peercred = 64,
    rcvlowat = 2048,
    sndlowat = 4096,
    rcvtimeo = 8192,
    sndtimeo = 16384,
    acceptconn = 32768,
    peersec = 30,
    sndbufforce = 4106,
    rcvbufforce = 4107,
    protocol = 4136,
    domain = 4137,
    security_authentication = 20481,
    security_encryption_transport = 20482,
    security_encryption_network = 20484,
    bindtodevice = 13,
    attach_filter = 26,
    detach_filter = 27,
    peername = 28,
    timestamp_old = 29,
    passsec = 31,
    timestampns_old = 33,
    mark = 34,
    timestamping_old = 35,
    rxq_ovfl = 36,
    wifi_status = 37,
    peek_off = 38,
    nofcs = 39,
    lock_filter = 40,
    select_err_queue = 41,
    busy_poll = 48,
    max_pacing_rate = 49,
    bpf_extensions = 50,
    incoming_cpu = 51,
    attach_bpf = 52,
    attach_reuseport_cbpf = 53,
    attach_reuseport_ebpf = 54,
    cnx_advice = 55,
    meminfo = 57,
    incoming_napi_id = 58,
    cookie = 59,
    peergroups = 61,
    zerocopy = 62,
    txtime = 63,
    bindtoifindex = 65,
    timestamp_new = 70,
    timestampns_new = 66,
    timestamping_new = 67,
    rcvtimeo_new = 68,
    sndtimeo_new = 69,
    detach_reuseport_bpf = 71,
    _,
} else enum(u16) {
    debug = 1,
    reuseaddr = 2,
    type = 3,
    @"error" = 4,
    dontroute = 5,
    broadcast = 6,
    sndbuf = 7,
    rcvbuf = 8,
    keepalive = 9,
    oobinline = 10,
    no_check = 11,
    priority = 12,
    linger = 13,
    bsdcompat = 14,
    reuseport = 15,
    passcred = 16,
    peercred = 17,
    rcvlowat = 18,
    sndlowat = 19,
    rcvtimeo = 20,
    sndtimeo = 21,
    acceptconn = 30,
    peersec = 31,
    sndbufforce = 32,
    rcvbufforce = 33,
    passsec = 34,
    timestampns_old = 35,
    mark = 36,
    timestamping_old = 37,
    protocol = 38,
    domain = 39,
    rxq_ovfl = 40,
    wifi_status = 41,
    peek_off = 42,
    nofcs = 43,
    lock_filter = 44,
    select_err_queue = 45,
    busy_poll = 46,
    max_pacing_rate = 47,
    bpf_extensions = 48,
    incoming_cpu = 49,
    attach_bpf = 50,
    attach_reuseport_cbpf = 51,
    attach_reuseport_ebpf = 52,
    cnx_advice = 53,
    meminfo = 55,
    incoming_napi_id = 56,
    cookie = 57,
    peergroups = 59,
    zerocopy = 60,
    txtime = 61,
    bindtoifindex = 62,
    timestamp_new = 63,
    timestampns_new = 64,
    timestamping_new = 65,
    rcvtimeo_new = 66,
    sndtimeo_new = 67,
    detach_reuseport_bpf = 68,
    security_authentication = 22,
    security_encryption_transport = 23,
    security_encryption_network = 24,
    bindtodevice = 25,
    attach_filter = 26,
    detach_filter = 27,
    peername = 28,
    timestamp_old = 29,
    _,
};

/// Backwards-compatible SO_* constants per-architecture.
pub const SO = struct {
    pub const DEBUG: u16 = @intFromEnum(SockOpt.debug);
    pub const REUSEADDR: u16 = @intFromEnum(SockOpt.reuseaddr);
    pub const KEEPALIVE: u16 = @intFromEnum(SockOpt.keepalive);
    pub const DONTROUTE: u16 = @intFromEnum(SockOpt.dontroute);
    pub const BROADCAST: u16 = @intFromEnum(SockOpt.broadcast);
    pub const LINGER: u16 = @intFromEnum(SockOpt.linger);
    pub const OOBINLINE: u16 = @intFromEnum(SockOpt.oobinline);
    pub const REUSEPORT: u16 = @intFromEnum(SockOpt.reuseport);
    pub const SNDBUF: u16 = @intFromEnum(SockOpt.sndbuf);
    pub const RCVBUF: u16 = @intFromEnum(SockOpt.rcvbuf);
    pub const SNDLOWAT: u16 = @intFromEnum(SockOpt.sndlowat);
    pub const RCVLOWAT: u16 = @intFromEnum(SockOpt.rcvlowat);
    pub const RCVTIMEO: u16 = @intFromEnum(SockOpt.rcvtimeo);
    pub const SNDTIMEO: u16 = @intFromEnum(SockOpt.sndtimeo);
    pub const ERROR: u16 = @intFromEnum(SockOpt.@"error");
    pub const TYPE: u16 = @intFromEnum(SockOpt.type);
    pub const ACCEPTCONN: u16 = @intFromEnum(SockOpt.acceptconn);
    pub const PROTOCOL: u16 = @intFromEnum(SockOpt.protocol);
    pub const DOMAIN: u16 = @intFromEnum(SockOpt.domain);
    pub const NO_CHECK: u16 = @intFromEnum(SockOpt.no_check);
    pub const PRIORITY: u16 = @intFromEnum(SockOpt.priority);
    pub const BSDCOMPAT: u16 = @intFromEnum(SockOpt.bsdcompat);
    pub const PASSCRED: u16 = @intFromEnum(SockOpt.passcred);
    pub const PEERCRED: u16 = @intFromEnum(SockOpt.peercred);
    pub const PEERSEC: u16 = @intFromEnum(SockOpt.peersec);
    pub const SNDBUFFORCE: u16 = @intFromEnum(SockOpt.sndbufforce);
    pub const RCVBUFFORCE: u16 = @intFromEnum(SockOpt.rcvbufforce);
    pub const SECURITY_AUTHENTICATION: u16 = @intFromEnum(SockOpt.security_authentication);
    pub const SECURITY_ENCRYPTION_TRANSPORT: u16 = @intFromEnum(SockOpt.security_encryption_transport);
    pub const SECURITY_ENCRYPTION_NETWORK: u16 = @intFromEnum(SockOpt.security_encryption_network);
    pub const BINDTODEVICE: u16 = @intFromEnum(SockOpt.bindtodevice);
    pub const ATTACH_FILTER: u16 = @intFromEnum(SockOpt.attach_filter);
    pub const DETACH_FILTER: u16 = @intFromEnum(SockOpt.detach_filter);
    pub const GET_FILTER: u16 = ATTACH_FILTER; // alias
    pub const PEERNAME: u16 = @intFromEnum(SockOpt.peername);
    pub const TIMESTAMP_OLD: u16 = @intFromEnum(SockOpt.timestamp_old);
    pub const PASSSEC: u16 = @intFromEnum(SockOpt.passsec);
    pub const TIMESTAMPNS_OLD: u16 = @intFromEnum(SockOpt.timestampns_old);
    pub const MARK: u16 = @intFromEnum(SockOpt.mark);
    pub const TIMESTAMPING_OLD: u16 = @intFromEnum(SockOpt.timestamping_old);
    pub const RXQ_OVFL: u16 = @intFromEnum(SockOpt.rxq_ovfl);
    pub const WIFI_STATUS: u16 = @intFromEnum(SockOpt.wifi_status);
    pub const PEEK_OFF: u16 = @intFromEnum(SockOpt.peek_off);
    pub const NOFCS: u16 = @intFromEnum(SockOpt.nofcs);
    pub const LOCK_FILTER: u16 = @intFromEnum(SockOpt.lock_filter);
    pub const SELECT_ERR_QUEUE: u16 = @intFromEnum(SockOpt.select_err_queue);
    pub const BUSY_POLL: u16 = @intFromEnum(SockOpt.busy_poll);
    pub const MAX_PACING_RATE: u16 = @intFromEnum(SockOpt.max_pacing_rate);
    pub const BPF_EXTENSIONS: u16 = @intFromEnum(SockOpt.bpf_extensions);
    pub const INCOMING_CPU: u16 = @intFromEnum(SockOpt.incoming_cpu);
    pub const ATTACH_BPF: u16 = @intFromEnum(SockOpt.attach_bpf);
    pub const DETACH_BPF: u16 = DETACH_FILTER; // alias in original
    pub const ATTACH_REUSEPORT_CBPF: u16 = @intFromEnum(SockOpt.attach_reuseport_cbpf);
    pub const ATTACH_REUSEPORT_EBPF: u16 = @intFromEnum(SockOpt.attach_reuseport_ebpf);
    pub const CNX_ADVICE: u16 = @intFromEnum(SockOpt.cnx_advice);
    pub const MEMINFO: u16 = @intFromEnum(SockOpt.meminfo);
    pub const INCOMING_NAPI_ID: u16 = @intFromEnum(SockOpt.incoming_napi_id);
    pub const COOKIE: u16 = @intFromEnum(SockOpt.cookie);
    pub const PEERGROUPS: u16 = @intFromEnum(SockOpt.peergroups);
    pub const ZEROCOPY: u16 = @intFromEnum(SockOpt.zerocopy);
    pub const TXTIME: u16 = @intFromEnum(SockOpt.txtime);
    pub const BINDTOIFINDEX: u16 = @intFromEnum(SockOpt.bindtoifindex);
    pub const TIMESTAMP_NEW: u16 = @intFromEnum(SockOpt.timestamp_new);
    pub const TIMESTAMPNS_NEW: u16 = @intFromEnum(SockOpt.timestampns_new);
    pub const TIMESTAMPING_NEW: u16 = @intFromEnum(SockOpt.timestamping_new);
    pub const RCVTIMEO_NEW: u16 = @intFromEnum(SockOpt.rcvtimeo_new);
    pub const SNDTIMEO_NEW: u16 = @intFromEnum(SockOpt.sndtimeo_new);
    pub const DETACH_REUSEPORT_BPF: u16 = @intFromEnum(SockOpt.detach_reuseport_bpf);
};

test "constants match SockOpt" {
    try std.testing.expectEqual(SO.DEBUG, @intFromEnum(SockOpt.debug));
    try std.testing.expectEqual(SO.REUSEADDR, @intFromEnum(SockOpt.reuseaddr));
    try std.testing.expectEqual(SO.KEEPALIVE, @intFromEnum(SockOpt.keepalive));
    try std.testing.expectEqual(SO.DONTROUTE, @intFromEnum(SockOpt.dontroute));
    try std.testing.expectEqual(SO.BROADCAST, @intFromEnum(SockOpt.broadcast));
    try std.testing.expectEqual(SO.LINGER, @intFromEnum(SockOpt.linger));
    try std.testing.expectEqual(SO.OOBINLINE, @intFromEnum(SockOpt.oobinline));
    try std.testing.expectEqual(SO.REUSEPORT, @intFromEnum(SockOpt.reuseport));
    try std.testing.expectEqual(SO.SNDBUF, @intFromEnum(SockOpt.sndbuf));
    try std.testing.expectEqual(SO.RCVBUF, @intFromEnum(SockOpt.rcvbuf));
    try std.testing.expectEqual(SO.SNDLOWAT, @intFromEnum(SockOpt.sndlowat));
    try std.testing.expectEqual(SO.RCVLOWAT, @intFromEnum(SockOpt.rcvlowat));
    try std.testing.expectEqual(SO.RCVTIMEO, @intFromEnum(SockOpt.rcvtimeo));
    try std.testing.expectEqual(SO.SNDTIMEO, @intFromEnum(SockOpt.sndtimeo));
    try std.testing.expectEqual(SO.ERROR, @intFromEnum(SockOpt.@"error"));
    try std.testing.expectEqual(SO.TYPE, @intFromEnum(SockOpt.type));
    try std.testing.expectEqual(SO.ACCEPTCONN, @intFromEnum(SockOpt.acceptconn));
    try std.testing.expectEqual(SO.PROTOCOL, @intFromEnum(SockOpt.protocol));
    try std.testing.expectEqual(SO.DOMAIN, @intFromEnum(SockOpt.domain));
    try std.testing.expectEqual(SO.NO_CHECK, @intFromEnum(SockOpt.no_check));
    try std.testing.expectEqual(SO.PRIORITY, @intFromEnum(SockOpt.priority));
    try std.testing.expectEqual(SO.BSDCOMPAT, @intFromEnum(SockOpt.bsdcompat));
    try std.testing.expectEqual(SO.PASSCRED, @intFromEnum(SockOpt.passcred));
    try std.testing.expectEqual(SO.PEERCRED, @intFromEnum(SockOpt.peercred));
    try std.testing.expectEqual(SO.PEERSEC, @intFromEnum(SockOpt.peersec));
    try std.testing.expectEqual(SO.SNDBUFFORCE, @intFromEnum(SockOpt.sndbufforce));
    try std.testing.expectEqual(SO.RCVBUFFORCE, @intFromEnum(SockOpt.rcvbufforce));
    try std.testing.expectEqual(SO.SECURITY_AUTHENTICATION, @intFromEnum(SockOpt.security_authentication));
    try std.testing.expectEqual(SO.SECURITY_ENCRYPTION_TRANSPORT, @intFromEnum(SockOpt.security_encryption_transport));
    try std.testing.expectEqual(SO.SECURITY_ENCRYPTION_NETWORK, @intFromEnum(SockOpt.security_encryption_network));
    try std.testing.expectEqual(SO.BINDTODEVICE, @intFromEnum(SockOpt.bindtodevice));
    try std.testing.expectEqual(SO.ATTACH_FILTER, @intFromEnum(SockOpt.attach_filter));
    try std.testing.expectEqual(SO.DETACH_FILTER, @intFromEnum(SockOpt.detach_filter));
    try std.testing.expectEqual(SO.GET_FILTER, SO.ATTACH_FILTER);
    try std.testing.expectEqual(SO.PEERNAME, @intFromEnum(SockOpt.peername));
    try std.testing.expectEqual(SO.TIMESTAMP_OLD, @intFromEnum(SockOpt.timestamp_old));
    try std.testing.expectEqual(SO.PASSSEC, @intFromEnum(SockOpt.passsec));
    try std.testing.expectEqual(SO.TIMESTAMPNS_OLD, @intFromEnum(SockOpt.timestampns_old));
    try std.testing.expectEqual(SO.MARK, @intFromEnum(SockOpt.mark));
    try std.testing.expectEqual(SO.TIMESTAMPING_OLD, @intFromEnum(SockOpt.timestamping_old));
    try std.testing.expectEqual(SO.RXQ_OVFL, @intFromEnum(SockOpt.rxq_ovfl));
    try std.testing.expectEqual(SO.WIFI_STATUS, @intFromEnum(SockOpt.wifi_status));
    try std.testing.expectEqual(SO.PEEK_OFF, @intFromEnum(SockOpt.peek_off));
    try std.testing.expectEqual(SO.NOFCS, @intFromEnum(SockOpt.nofcs));
    try std.testing.expectEqual(SO.LOCK_FILTER, @intFromEnum(SockOpt.lock_filter));
    try std.testing.expectEqual(SO.SELECT_ERR_QUEUE, @intFromEnum(SockOpt.select_err_queue));
    try std.testing.expectEqual(SO.BUSY_POLL, @intFromEnum(SockOpt.busy_poll));
    try std.testing.expectEqual(SO.MAX_PACING_RATE, @intFromEnum(SockOpt.max_pacing_rate));
    try std.testing.expectEqual(SO.BPF_EXTENSIONS, @intFromEnum(SockOpt.bpf_extensions));
    try std.testing.expectEqual(SO.INCOMING_CPU, @intFromEnum(SockOpt.incoming_cpu));
    try std.testing.expectEqual(SO.ATTACH_BPF, @intFromEnum(SockOpt.attach_bpf));
    try std.testing.expectEqual(SO.DETACH_BPF, SO.DETACH_FILTER);
    try std.testing.expectEqual(SO.ATTACH_REUSEPORT_CBPF, @intFromEnum(SockOpt.attach_reuseport_cbpf));
    try std.testing.expectEqual(SO.ATTACH_REUSEPORT_EBPF, @intFromEnum(SockOpt.attach_reuseport_ebpf));
    try std.testing.expectEqual(SO.CNX_ADVICE, @intFromEnum(SockOpt.cnx_advice));
    try std.testing.expectEqual(SO.MEMINFO, @intFromEnum(SockOpt.meminfo));
    try std.testing.expectEqual(SO.INCOMING_NAPI_ID, @intFromEnum(SockOpt.incoming_napi_id));
    try std.testing.expectEqual(SO.COOKIE, @intFromEnum(SockOpt.cookie));
    try std.testing.expectEqual(SO.PEERGROUPS, @intFromEnum(SockOpt.peergroups));
    try std.testing.expectEqual(SO.ZEROCOPY, @intFromEnum(SockOpt.zerocopy));
    try std.testing.expectEqual(SO.TXTIME, @intFromEnum(SockOpt.txtime));
    try std.testing.expectEqual(SO.BINDTOIFINDEX, @intFromEnum(SockOpt.bindtoifindex));
    try std.testing.expectEqual(SO.TIMESTAMP_NEW, @intFromEnum(SockOpt.timestamp_new));
    try std.testing.expectEqual(SO.TIMESTAMPNS_NEW, @intFromEnum(SockOpt.timestampns_new));
    try std.testing.expectEqual(SO.TIMESTAMPING_NEW, @intFromEnum(SockOpt.timestamping_new));
    try std.testing.expectEqual(SO.RCVTIMEO_NEW, @intFromEnum(SockOpt.rcvtimeo_new));
    try std.testing.expectEqual(SO.SNDTIMEO_NEW, @intFromEnum(SockOpt.sndtimeo_new));
    try std.testing.expectEqual(SO.DETACH_REUSEPORT_BPF, @intFromEnum(SockOpt.detach_reuseport_bpf));
}
