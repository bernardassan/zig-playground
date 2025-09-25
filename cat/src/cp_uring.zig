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

const IoData = struct {
    read: bool,
    offset: u32,
    iov: posix.iovec,
};

fn setup_context(entries: u16, flags: u32) !IoUring {
    const uring = try IoUring.init(entries, flags);
    return uring;
}

fn queue_prepped(ring: *IoUring, infile: ?fs.File, outfile: ?fs.File, io_data: *IoData) !void {
    const sqe = try ring.get_sqe();

    if (io_data.read) {
        sqe.prep_readv(infile.?.handle, @ptrCast(&io_data.iov), io_data.offset);
    } else {
        sqe.prep_writev(outfile.?.handle, @ptrCast(&io_data.iov), io_data.offset);
    }
    dump_sqe(sqe);
    sqe_set_data(sqe, io_data);
}

fn sqe_set_data(sqe: *linux.io_uring_sqe, io_data: *anyopaque) void {
    sqe.user_data = @intFromPtr(io_data);
}

fn queue_read(ring: *IoUring, arena: std.mem.Allocator, infile: fs.File, size: u64, offset: u32) !void {
    const memory = try arena.alloc(u8, @sizeOf(IoData) + size);
    errdefer arena.free(memory);

    const io_data: *IoData = @ptrCast(@alignCast(memory[0..@sizeOf(IoData)]));
    const iov_mem: []u8 = @ptrCast(memory[@sizeOf(IoData)..]);

    io_data.* = .{
        .read = true,
        .offset = offset,
        .iov = .{ .base = iov_mem.ptr, .len = iov_mem.len },
    };

    try queue_prepped(ring, infile, null, io_data);
}

fn queue_write(ring: *IoUring, outfile: fs.File, io_data: *IoData) !u32 {
    io_data.* = .{
        .read = false,
        .offset = io_data.offset,
        .iov = .{
            .base = io_data.iov.base,
            .len = io_data.iov.len,
        },
    };

    try queue_prepped(ring, null, outfile, io_data);
    return try ring.submit();
}

fn copy_file(ring: *IoUring, allocator: mem.Allocator, infile: fs.File, outfile: fs.File) !void {
    const empty = 0;

    var reads_left = (try infile.stat()).size;
    var writes_left = reads_left;

    while (reads_left != empty or writes_left != empty) {
        var offset: u32 = 0;
        var reads: u32 = 0;
        var writes: u32 = 0;

        // Queue up as many reads as we can
        while (reads_left != empty) : (reads += 1) {
            if (reads + writes >= queue_depth) break;

            const read_size = if (reads_left > block_sz) block_sz else if (reads_left == 0) break else reads_left;
            defer reads_left -= read_size;
            defer offset += @intCast(read_size);

            try queue_read(ring, allocator, infile, read_size, offset);
        }

        if (reads != empty) {
            _ = try ring.submit();
        }

        // Queue is full at this point. Let's find at least one completion
        while (writes_left != empty) {
            const cqe = try ring.copy_cqe();

            const io_data = cqe_get_data(IoData, &cqe);
            if (cqe.err() != .SUCCESS) {
                const err = cqe.err();
                if (err == .AGAIN) {
                    try queue_prepped(ring, infile, outfile, io_data);
                    continue;
                }
                log.err("cqe failed: {t}", .{err});
                std.process.exit(@intCast(@intFromEnum(err)));
            } else if (cqe.res != io_data.iov.len) {
                // short read/write; adjust and requeue
                io_data.iov.base += @intCast(cqe.res);
                io_data.iov.len -= @intCast(cqe.res);
                try queue_prepped(ring, infile, outfile, io_data);
                continue;
            }

            // All done. If read, queue up corresponding write.
            // If write, nothing else to do than cleanup.
            if (io_data.read) {
                _ = try queue_write(ring, outfile, io_data);
                defer reads -= 1;
                defer writes += 1;

                writes_left -= io_data.iov.len;
            } else {
                defer writes -= 1;

                allocator.destroy(io_data);
            }
        }
    }
    std.debug.assert(reads_left == empty and writes_left == empty);
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
        \\
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

    try copy_file(&ring, dbga, infile, outfile);

    return 0;
}
