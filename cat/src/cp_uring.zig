//! https://github.com/tigerbeetle/tigerbeetle/blob/62ab3805a6e78b03c86cf61690873b47a9a6b935/src/io/linux.zig
//! https://unixism.net/2020/04/io-uring-by-example-part-2-queuing-multiple-requests/
const std = @import("std");
const posix = std.posix;
const linux = std.os.linux;
const IoUring = linux.IoUring;
const Io = std.Io;
const fs = std.fs;
const mem = std.mem;

const queue_depth = 2;
const block_sz = 16 * 1024;

pub const std_options: std.Options = .{ .log_level = .debug };
const log = std.log.scoped(.cp_uring);

const io_data = struct {
    read: bool,
    first_offset: usize,
    offset: usize,
    first_len: usize,
    iov: posix.iovec,
};

fn setup_context(entries: u16, flags: u32) !IoUring {
    const uring = try IoUring.init(entries, flags);
    return uring;
}

fn queue_prepped(ring: *IoUring, infile: fs.File, outfile: fs.File, data: *io_data) !void {
    const sqe = try ring.get_sqe();

    if (data.read) {
        sqe.prep_readv(infile.handle, &.{data.iov}, data.offset);
    } else {
        sqe.prep_writev(outfile.handle, &.{@bitCast(data.iov)}, data.offset);
    }
    dump_sqe(sqe);
    sqe_set_data(sqe, data);
}

fn sqe_set_data(sqe: *linux.io_uring_sqe, data: *anyopaque) void {
    sqe.user_data = @intFromPtr(data);
}

fn queue_read(ring: *IoUring, allocator: std.mem.Allocator, infile: fs.File, size: usize, offset: usize) !void {
    // data = malloc(size + sizeof(*data));
    const data = try allocator.create(io_data);
    errdefer allocator.destroy(data);

    const sqe = try ring.get_sqe();

    data.read = true;
    data.offset = offset;
    data.first_offset = offset;

    data.iov.base = @as([*]u8, @ptrCast(data)) + 1;
    data.iov.len = size;
    data.first_len = size;

    sqe.prep_readv(infile.handle, &.{data.iov}, offset);
    dump_sqe(sqe);
    sqe_set_data(sqe, data);
}

fn queue_write(ring: *IoUring, infile: fs.File, outfile: fs.File, data: *io_data) !u32 {
    data.read = false;
    data.offset = data.first_offset;

    data.iov.base = @as([*]u8, @ptrCast(data)) + 1;
    data.iov.len = data.first_len;

    try queue_prepped(ring, infile, outfile, data);
    return try ring.submit();
}

fn copy_file(ring: *IoUring, allocator: mem.Allocator, infile: fs.File, outfile: fs.File, insize: usize) !void {
    var write_left: usize = insize;
    const end = 0;
    var insize_ = insize;
    while (insize_ != end or write_left != end) {
        var offset: usize = 0;
        var reads = offset;
        var writes = offset;
        // Queue up as many reads as we can
        const had_reads = reads;

        while (insize_ != 0) : (reads += 1) {
            if (reads + writes >= queue_depth) break;

            const this_size = if (insize_ > block_sz) block_sz else if (insize_ == 0) break else insize_;
            defer insize_ -= this_size;
            defer offset += this_size;

            try queue_read(ring, allocator, infile, this_size, offset);
        }

        if (had_reads != reads) {
            _ = try ring.submit();
        }

        // Queue is full at this point. Let's find at least one completion
        while (write_left != 0) {
            const cqe = try ring.copy_cqe();

            const data = cqe_get_data(io_data, &cqe);
            if (cqe.err() != .SUCCESS) {
                const err = cqe.err();
                if (err == .AGAIN) {
                    try queue_prepped(ring, infile, outfile, data);
                    // ring.cqe_seen(cqe); // not needed with copy_cqe
                    continue;
                }
                log.err("cqe failed: {t}", .{err});
                std.process.exit(@intCast(@intFromEnum(err)));
            } else if (cqe.res != data.iov.len) {
                // short read/write; adjust and requeue
                data.iov.base += @intCast(cqe.res);
                data.iov.len -= @intCast(cqe.res);
                try queue_prepped(ring, infile, outfile, data);
                // ring.cqe_seen(cqe); // not needed with copy_cqe
                continue;
            }

            // All done. If write, nothing else to do. If read,
            // queue up corresponding write.
            if (data.read) {
                // TOOD: use written bytes from `queue_write`
                _ = try queue_write(ring, infile, outfile, data);
                write_left -= data.first_len;
                reads -= 1;
                writes += 1;
            } else {
                allocator.destroy(data);
                writes -= 1;
            }
            // ring.cqe_seen(cqe);
        }
    }
}

fn cqe_get_data(comptime T: type, cqe: *const linux.io_uring_cqe) *T {
    return @as(*T, @ptrFromInt(cqe.*.user_data));
}

fn dump_sqe(sqe: *linux.io_uring_sqe) void {
    log.debug(
        \\
        \\sqe->opcode = {t}
        \\sqe->flags = Ox{x}
        \\sqe->ioprio = {d}
        \\sqe->fd = {d}
        \\sqe->off = {d}
        \\sqe->addr = Ox{x}
        \\sqe->len = {d}
        \\sqe->rw_flags = {d}
        \\sqe->user_data = Ox{x}
        \\sqe->buf_index = {d}
        \\sqe->personality = {d}
        \\sqe->splice_fd_in = {d}
        \\sqe->addr3 = {d}
        \\sqe->resv = {d}
    , .{
        sqe.opcode,
        sqe.flags,
        sqe.ioprio,
        sqe.fd,
        sqe.off,
        sqe.addr,
        sqe.len,
        sqe.rw_flags,
        sqe.user_data,
        sqe.buf_index,
        sqe.personality,
        sqe.splice_fd_in,
        sqe.addr3,
        sqe.resv,
    });
}

pub fn main() !u8 {
    var dbg_alloc: std.heap.DebugAllocator(.{}) = .init;
    const dbga = dbg_alloc.allocator();

    const argv = try std.process.argsAlloc(dbga);
    const argc = argv.len;
    defer std.process.argsFree(dbga, argv);

    var stderr_buf: [1024]u8 = undefined;
    var stderr = std.fs.File.stderr().writer(&stderr_buf);
    const stderr_w = &stderr.interface;
    defer stderr_w.flush() catch unreachable;

    if (argc < 3) {
        try stderr_w.print("Usage: {s} <infile> <outfile>\n", .{argv[0]});
        return 3;
    }

    const cwd = fs.cwd();
    const infile = try cwd.openFile(argv[1], .{ .mode = .read_only });
    defer infile.close();

    const outfile = try cwd.createFile(argv[2], .{ .mode = 0o644, .truncate = true });
    defer outfile.close();

    const flags = 0;
    var ring = try setup_context(queue_depth, flags);
    defer ring.deinit();

    const insize = (try infile.stat()).size;

    try copy_file(&ring, dbga, infile, outfile, insize);

    return 0;
}
