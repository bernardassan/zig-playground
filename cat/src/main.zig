const std = @import("std");
const fs = std.fs;

const block_size = 4096;

pub fn main() !void {
    var stdout_buf: [1024]u8 = undefined;
    var alloc: std.heap.DebugAllocator(.{}) = .init;
    const smp_alloc = alloc.allocator();

    var stdout = std.fs.File.stdout().writer(&stdout_buf);
    var stdout_w = &stdout.interface;
    defer stdout_w.flush() catch unreachable;

    const args = try std.process.argsAlloc(smp_alloc);
    defer std.process.argsFree(smp_alloc, args);

    if (args.len < 2) {
        return try stdout_w.writeAll("Usage: zig build run -- <filename1> [<filename2>...]\n");
    }

    for (1..args.len) |arg_index| {
        _ = try readAndPrintFile(smp_alloc, stdout_w, args[arg_index]);
    }
}

fn readAndPrintFile(allocator: std.mem.Allocator, stdout: *std.Io.Writer, file_path: []const u8) !usize {
    const file = try fs.cwd().openFile(file_path, .{ .mode = .read_only });

    const size = (try file.stat()).size;

    var blocks = size / block_size;
    if (size % block_size != 0) blocks += 1;

    var iovec = try allocator.alloc(std.posix.iovec, blocks);
    var current_block: usize = 0;
    var bytes_remaining = size;
    while (bytes_remaining != 0) : (current_block += 1) {
        const bytes_to_read = if (bytes_remaining > block_size) block_size else bytes_remaining;
        const buf = try allocator.alignedAlloc(u8, .fromByteUnits(block_size), bytes_to_read);
        iovec[current_block] = .{ .base = buf.ptr, .len = buf.len };
        bytes_remaining -= bytes_to_read;
    }

    const amt = try std.posix.readv(file.handle, iovec);
    for (iovec[0..]) |value| {
        try stdout.print("{s}", .{value.base[0..value.len]});
    }
    return amt;
}
