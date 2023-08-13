const std = @import("std");

//xq @ UTC+2 (MasterQ32 @ GitHub) — ayer a las 7:44
// tl;dr:
// it callls a function more than once, where suspend is a return that saves state, and resume is a calls the function again
// async foo() initializes the function frame (the permanent state of a async function), and calls the function
// await checks if the function has returned, and will either return its value or suspends

const Frame = struct {
    state: usize = 0,
    result: []const u8 = undefined,
    local: u32 = 0,
    done: bool = false,
};

// async fn func() []const u8 {
//   var local = 1;
//   suspend;
//   return "Hello, World!";
// }
//
fn asyncFunc(frame: *Frame) void {
    std.debug.assert(!frame.done);
    switch (frame.state) {
        0 => {
            frame.state = 1;
            frame.local = 1;
        },
        1 => {
            frame.result = "Hello, World!";
            frame.done = true;
        },
    }
}
fn useAsync() void {

    // frame = async func();
    var frame = Frame{};
    asyncFunc(&frame);

    // resume frame
    asyncFunc(&frame);

    // result = await frame;
    var result = frame.result;
    _ = result;
}
