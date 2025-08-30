const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;
const process = std.process;

const queue_depth = 1;
const block_sz = 4096;

const Allocator = std.mem.Allocator;

// This is x86 specific
fn read_barrier() void {
    asm volatile ("" ::: .{ .memory = true });
}
fn write_barrier() void {
    asm volatile ("" ::: .{ .memory = true });
}
const app_io_sq_ring = struct {
    head: *u32,
    tail: *u32,
    ring_mask: *u32,
    ring_entries: *u32,
    flags: *u32,
    array: [*]u32,
};

const app_io_cq_ring = struct {
    head: *u32,
    tail: *u32,
    ring_mask: *u32,
    ring_entries: *u32,
    cqes: [*]linux.io_uring_cqe,
};

const submitter = struct {
    ring_fd: i32,
    sq_ring: app_io_sq_ring,
    sqes: [*]linux.io_uring_sqe,
    cq_ring: app_io_cq_ring,
};

const file_info = struct {
    file_sz: usize,
    iovecs: []std.posix.iovec, //Referred by readv/writev
};

// io_uring requires a lot of setup which looks pretty hairy, but isn't all
// that difficult to understand. Because of all this boilerplate code,
// io_uring's author has created liburing, which is relatively easy to use.
// However, you should take your time and understand this code. It is always
// good to know how it all works underneath. Apart from bragging rights,
// it does offer you a certain strange geeky peace.
fn app_setup_uring(stderr: *std.Io.Writer, sub: *submitter) !void {
    // We need to pass in the io_uring_params structure to the io_uring_setup()
    // call zeroed out. We could set any flags if we need to, but for this
    // example, we don't.
    var params = std.mem.zeroes(linux.io_uring_params);
    const ret = linux.io_uring_setup(queue_depth, &params);
    const err = posix.errno(ret);
    if (err != .SUCCESS) {
        try stderr.print("io_uring_setup error: {t}\n", .{err});
        process.exit(@intCast(@intFromEnum(err)));
    }
    sub.ring_fd = @intCast(ret);
    // io_uring communication happens via 2 shared kernel-user space ring buffers,
    // which can be jointly mapped with a single mmap() call in recent kernels.
    // While the completion queue is directly manipulated, the submission queue
    // has an indirection array in between. We map that in as well.

    const sring_sz = params.sq_off.array + (params.sq_entries * @sizeOf(u32));
    const cring_sz =
        params.cq_off.cqes + (params.cq_entries * @sizeOf(linux.io_uring_cqe));
    // In kernel version 5.4 and above, it is possible to map the submission and
    // completion buffers with a single mmap() call. Rather than check for
    // kernel versions, the recommended way is to just check the features field
    // of the io_uring_params structure, which is a bit mask. If the
    // IORING_FEAT_SINGLE_MMAP is set, then we can do away with the second
    // mmap() call to map the completion ring.
    const cq_map, const sq_map = blk: {
        const ring_sz = @max(cring_sz, sring_sz);
        // Map in the submission and completion queue ring buffers.
        // Older kernels only map in the submission queue, though.
        const sq_map = try posix.mmap(null, ring_sz, posix.PROT.READ | posix.PROT.WRITE, .{ .TYPE = .SHARED, .POPULATE = true }, sub.ring_fd, linux.IORING_OFF_SQ_RING);

        if (params.features & linux.IORING_FEAT_SINGLE_MMAP != 0) {
            const cq_map = sq_map;
            break :blk .{ cq_map, sq_map };
        } else {
            // Map in the completion queue ring buffer in older kernels separately
            const cq_map = try posix.mmap(null, cring_sz, posix.PROT.READ | posix.PROT.WRITE, .{ .TYPE = .SHARED, .POPULATE = true }, sub.ring_fd, linux.IORING_OFF_CQ_RING);
            break :blk .{ cq_map, sq_map };
        }
    };
    const sring = &sub.sq_ring;

    // Save useful fields in a global app_io_sq_ring struct for later easy reference
    sring.head = @ptrCast(@alignCast(sq_map.ptr + params.sq_off.head));
    sring.tail = @ptrCast(@alignCast(sq_map.ptr + params.sq_off.tail));
    sring.ring_mask = @ptrCast(@alignCast(sq_map.ptr + params.sq_off.ring_mask));
    sring.ring_entries = @ptrCast(@alignCast(sq_map.ptr + params.sq_off.ring_entries));
    sring.flags = @ptrCast(@alignCast(sq_map.ptr + params.sq_off.flags));
    sring.array = @ptrCast(@alignCast(sq_map.ptr + params.sq_off.array));

    // Map in the submission queue entries array
    sub.sqes = @ptrCast(try posix.mmap(null, params.sq_entries * @sizeOf(linux.io_uring_sqe), posix.PROT.READ | posix.PROT.WRITE, .{ .TYPE = .SHARED, .POPULATE = true }, sub.ring_fd, linux.IORING_OFF_SQES));

    const cring = &sub.cq_ring;
    // Save useful fields in a global app_io_cq_ring struct for later
    //  easy reference
    cring.head = @ptrCast(@alignCast(cq_map.ptr + params.cq_off.head));
    cring.tail = @ptrCast(@alignCast(cq_map.ptr + params.cq_off.tail));
    cring.ring_mask = @ptrCast(@alignCast(cq_map.ptr + params.cq_off.ring_mask));
    cring.ring_entries = @ptrCast(@alignCast(cq_map.ptr + params.cq_off.ring_entries));
    cring.cqes = @ptrCast(@alignCast(cq_map.ptr + params.cq_off.cqes));
}

// Read from completion queue.
// In this function, we read completion events from the completion queue, get
// the data buffer that will have the file data and print it to the console.
fn read_from_cq(stderr: *std.Io.Writer, stdout: *std.Io.Writer, sub: *submitter) !void {
    const cring = &sub.cq_ring;
    var head = cring.head.*;

    while (true) {
        read_barrier();
        // Remember, this is a ring buffer. If head == tail, it means that the
        // buffer is empty.
        if (head == cring.tail.*) {
            break;
        }

        // Get the entry
        const index = head & sub.cq_ring.ring_mask.*;
        const cqe = &cring.cqes[index];
        const err = posix.errno(@as(isize, @intCast(cqe.res)));
        if (err != .SUCCESS) {
            try stderr.print("Error: {t}\n", .{err});
            process.exit(@intCast(@intFromEnum(err)));
        }

        const fileinfo: *file_info = @ptrFromInt(cqe.user_data);
        var blocks = fileinfo.file_sz / block_sz;
        if (fileinfo.file_sz % block_sz != 0) {
            blocks += 1;
        }

        var block: usize = 0;
        while (block < blocks) : (block += 1) {
            try stdout.print("{s}", .{fileinfo.iovecs[block].base[0..fileinfo.iovecs[block].len]});
        }
        head += 1;
    }

    cring.head.* = head;
    write_barrier();
}

// Submit to submission queue.
// In this function, we submit requests to the submission queue. You can submit
// many types of requests. Ours is going to be the readv() request, which we
// specify via IORING_OP_READV.
fn submit_to_sq(arena: Allocator, stderr: *std.Io.Writer, file_path: []const u8, sub: *submitter) !void {
    const file_fd = try std.fs.cwd().openFile(file_path, .{ .mode = .read_only });

    const file_sz = (try file_fd.stat()).size;
    var bytes_remaining = file_sz;
    var blocks = file_sz / block_sz;
    if (file_sz % block_sz != 0) {
        blocks += 1;
    }

    const fileinfo = try arena.create(file_info);
    fileinfo.iovecs = try arena.alloc(posix.iovec, blocks);

    fileinfo.file_sz = file_sz;

    // For each block of the file we need to read, we allocate an iovec struct
    // which is indexed into the iovecs array. This array is passed in as part
    // of the submission. If you don't understand this, then you need to look
    // up how the readv() and writev() system calls work.
    var current_block: usize = 0;
    while (bytes_remaining != 0) : (current_block += 1) {
        var bytes_to_read = bytes_remaining;
        if (bytes_to_read > block_sz) {
            bytes_to_read = block_sz;
        }

        const buf = try arena.alignedAlloc(u8, .fromByteUnits(block_sz), block_sz);
        fileinfo.iovecs[current_block] = .{ .base = buf.ptr, .len = bytes_to_read };

        bytes_remaining -= bytes_to_read;
    }

    const sring = &sub.sq_ring;
    // Add our submission queue entry to the tail of the SQE ring buffer
    var tail = sring.tail.*;
    var next_tail = tail;
    next_tail += 1;
    read_barrier();
    const index = tail & sub.sq_ring.ring_mask.*;
    const sqe = &sub.sqes[index];
    sqe.fd = file_fd.handle;
    sqe.flags = 0;
    sqe.opcode = linux.IORING_OP.READV;
    sqe.addr = @intFromPtr(fileinfo.iovecs.ptr);
    sqe.len = @intCast(blocks);
    sqe.off = 0;
    sqe.user_data = @intFromPtr(fileinfo);
    sring.array[index] = index;
    tail = next_tail;

    // Umap the tail so the kernel can see it.
    if (sring.tail.* != tail) {
        sring.tail.* = tail;
        write_barrier();
    }

    // Tell the kernel we have submitted events with the io_uring_enter() system
    // call. We also pass in the IOURING_ENTER_GETEVENTS flag which causes the
    // io_uring_enter() call to wait until min_complete events (the 3rd param)
    // complete.
    const ret = linux.io_uring_enter(sub.ring_fd, 1, 1, linux.IORING_ENTER_GETEVENTS, null);
    const err = posix.errno(ret);
    if (err != .SUCCESS) {
        try stderr.print("io_uring_enter error: {t}", .{err});
        process.exit(@intCast(@intFromEnum(err)));
    }
}

pub fn main() !void {
    var dbg_alloc: std.heap.DebugAllocator(.{}) = .init;
    const allocator = dbg_alloc.allocator();

    const argv = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, argv);

    var stdout_buf: [1024]u8 = undefined;
    var stdout_w = std.fs.File.stdout().writer(&stdout_buf);
    var stdout = &stdout_w.interface;
    defer stdout.flush() catch unreachable;

    var stderr_buf: [1024]u8 = undefined;
    var stderr_w = std.fs.File.stderr().writer(&stderr_buf);
    var stderr = &stderr_w.interface;
    defer stderr.flush() catch unreachable;

    if (argv.len < 2) {
        try stderr.print("Usage: {s} <filename>\n", .{argv[0]});
        process.exit(1);
    }

    var sub: submitter = undefined;
    try app_setup_uring(stderr, &sub);

    for (1..argv.len) |argc| {
        try submit_to_sq(allocator, stderr, argv[argc], &sub);
        try read_from_cq(stderr, stdout, &sub);
    }
}
