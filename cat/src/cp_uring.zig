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

const io_data = struct {
    read: i32,
    first_offset: usize,
    offset: usize,
    first_len: usize,
    iov: posix.iovec,
};

fn setup_context(entries: u16, flags: u32) !IoUring {
    const uring = try IoUring.init(entries, flags);
    return uring;
}

fn queue_prepped(ring: *IoUring, infd: fs.File, outfd: fs.File, data: *io_data) void {
    const sqe = try ring.get_sqe();

    if (data.read) {
        sqe.prep_read_fixed(infd.handle, &data.iov, 1, data.offset);
    } else {
        sqe.prep_writev(outfd.handle, &data.iov, 1, data.offset);
    }
    sqe_set_data(sqe, data);
}

fn sqe_set_data(sqe: *linux.io_uring_sqe, data: *anyopaque) void {
    sqe.user_data = @intFromPtr(data);
}

fn queue_read(ring: *IoUring, allocator: std.mem.Allocator, infd: fs.File, size: usize, offset: posix.off_t) !void {
    // data = malloc(size + sizeof(*data));
    const data = try allocator.create(io_data);
    errdefer allocator.free(data);

    const sqe = try ring.get_sqe();

    data.read = 1;
    data.offset = offset;
    data.first_offset = offset;

    data.iov.base = data + 1;
    data.iov.len = size;
    data.first_len = size;

    sqe.prep_readv(infd.handle, &data.iov, 1, offset);
    sqe_set_data(sqe, data);
}

fn queue_write(ring: *IoUring, data: *io_data) u32 {
    data.read = 0;
    data.offset = data.first_offset;

    data.iov.iov_base = data + 1;
    data.iov.iov_len = data.first_len;

    queue_prepped(ring, data);
    return try ring.submit();
}

fn copy_file(ring: *IoUring, stderr: *Io.Writer, allocator: mem.Allocator, insize: posix.off_t) !i32 {
    const write_left = insize;
    const offset = 0;
    const writes = offset;
    const reads = offset;

    while (insize || write_left) {
        // Queue up as many reads as we can
        const had_reads = reads;

        while (insize) {
            const this_size = insize;

            if (reads + writes >= queue_depth)
                break;
            if (this_size > block_sz) {
                this_size = block_sz;
            } else if (!this_size)
                break;

            if (queue_read(ring, this_size, offset))
                break;

            insize -= this_size;
            offset += this_size;
            reads += 1;
        }

        if (had_reads != reads) {
            const ret = try ring.submit();
            const err = std.posix.errno(@as(isize, ret));
            if (err != .SUCCESS) {
                std.debug.print("io_uring_submit: {t}\n", .{err});
                break;
            }
        }

        // Queue is full at this point. Let's find at least one completion
        while (write_left) {
            const cqe = try ring.copy_cqe();

            const data = cqe_get_data(io_data, cqe);
            if (cqe.res < 0) {
                if (cqe.res == -linux.E.AGAIN) {
                    queue_prepped(ring, data);
                    // ring.cqe_seen(cqe); // not needed with copy_cqe
                    continue;
                }
                try stderr.print("cqe failed: {s}\n", .{-cqe.res});
                return 1;
            } else if (cqe.res != data.iov.len) {
                // short read/write; adjust and requeue
                data.iov.iov_base += cqe.res;
                data.iov.iov_len -= cqe.res;
                queue_prepped(ring, data);
                // ring.cqe_seen(cqe); // not needed with copy_cqe
                continue;
            }

            // All done. If write, nothing else to do. If read,
            // queue up corresponding write.

            if (data.read) {
                queue_write(ring, data);
                write_left -= data.first_len;
                reads -= 1;
                writes += 1;
            } else {
                allocator.free(data);
                writes -= 1;
            }
            // ring.cqe_seen(cqe);
        }
    }

    return 0;
}

fn cqe_get_data(comptime T: type, cqe: *const linux.io_uring_cqe) *T {
    return @as(*T, @ptrFromInt(cqe.*.user_data));
}

pub fn main() !void {
    var dbg_alloc: std.heap.DebugAllocator(.{}) = .init;
    const dbga = dbg_alloc.allocator();

    const argv = try std.process.argsAlloc(dbga);
    const argc = argv.len;
    defer std.process.argsFree(dbga, argv);

    var stderr_buf: [1024]u8 = undefined;
    var stderr_w = std.fs.File.stderr().writer(&stderr_buf);
    var stderr = &stderr_w.interface;
    defer stderr.flush() catch unreachable;

    if (argc < 3) {
        try stderr_w.print("Usage: {s} <infile> <outfile>\n", .{argv[0]});
    }

    const cwd = fs.cwd();
    const infd = try cwd.openFile(argv[1], .{ .mode = .read_only });
    defer infd.close();

    const outfd = try cwd.openFile(argv[2], .{ .mode = .read_write }); //O_WRONLY | O_CREAT | O_TRUNC, 0644
    defer outfd.close();

    const flags = 0;
    var ring = try setup_context(queue_depth, flags);
    defer ring.deinit();

    const insize = (try infd.stat()).size;

    const ret = try copy_file(&ring, stderr, dbga, insize);

    return ret;
}
