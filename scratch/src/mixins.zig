const std = @import("std");

pub fn Mixin(comptime T: type, field_name: []const u8) type {
    return struct {
        _parent: *T,

        pub fn increment(counter: @This()) void {
            @field(counter._parent, field_name) += 1;
        }

        pub fn get(couter: @This()) *T {
            return couter._parent;
        }
    };
}

const SomeType = struct {
    field: usize,

    // https://zigbin.io/25c171
    // https://github.com/ziglang/zig/issues/20663#issuecomment-2277909762
    // https://github.com/ziglang/zig/issues/20663#issue-2413680718
    pub fn init(allocator: std.mem.Allocator, val: usize) Mixin(@This(), "field") {
        var value = allocator.create(@This()) catch unreachable;
        value.field = val;
        return .{ ._parent = value };
    }
};

pub fn CounterMixin(comptime T: type) type {
    return struct {
        const Self = @This();
        fn getParent(mixin: *Self) *T {
            return @alignCast(@fieldParentPtr("counter", mixin));
        }

        pub fn increment(m: *Self) void {
            m.getParent()._counter += 1;
        }
        pub fn reset(m: *@This()) void {
            m.getParent()._counter = 0;
        }
    };
}

pub const Type = struct {
    _counter: u32 = 0,
    counter: CounterMixin(Type) = .{},
};

pub fn main() !void {
    var a_type: Type = .{ ._counter = 0 };
    a_type.counter.increment();
    a_type.counter.increment();

    var some_type = SomeType.init(std.heap.smp_allocator, 0);
    some_type.increment();
    some_type.increment();
    std.debug.assert(some_type.get().field == a_type._counter);
}
