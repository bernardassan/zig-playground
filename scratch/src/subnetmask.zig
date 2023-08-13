const std = @import("std");

fn sumation(start: usize, end: usize, comptime op: fn (usize) usize) usize {
    var sum: usize = 0;
    var current_start = start;
    while (current_start <= end) : (current_start += 1) {
        sum += op(current_start);
    }
    return sum;
}

fn subnetmask(subnet: u5) void {
    const number_of_octets_with_filled_bits = @divFloor(subnet, 8);
    const subnet_on_bits = @mod(subnet, 8);
    const op = struct {
        pub fn op(power: usize) usize {
            return std.math.pow(usize, 2, power);
        }
    }.op;
    const next_octet_value = sumation(8 - subnet_on_bits, 7, op);

    std.debug.print("{s}{d}\n", .{ switch (number_of_octets_with_filled_bits) {
        1 => "255:",
        2 => "255:255:",
        3 => "255:255:255:",
        4 => "255:255:255:255",
        else => "",
    }, next_octet_value });
}
pub fn main() void {
    subnetmask(21);
}
