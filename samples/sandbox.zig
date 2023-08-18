// Copyright 2023 - Corentin Godeau and the zice contributors
// SPDX-License-Identifier: MIT

const std = @import("std");
const xev = @import("xev");
const zice = @import("zice");

const StopHandler = struct {
    storage: [@sizeOf(std.os.linux.signalfd_siginfo)]u8,
    fd: std.os.fd_t,
    mask: std.os.sigset_t,
    completion: xev.Completion = .{},

    //userdata: ?*anyopaque,
    //callback: *const fn (userdata: ?*anyopaque, loop: *xev.Loop) void = fn (userdata: ?*anyopaque, loop: *xev.Loop) void{},

    pub fn init() !StopHandler {
        var self: StopHandler = undefined;
        self.mask = m: {
            var mask = std.os.empty_sigset;
            std.os.linux.sigaddset(&mask, std.os.SIG.INT);
            break :m mask;
        };
        self.fd = try std.os.signalfd(-1, &self.mask, 0);
        errdefer std.os.close(self);

        return self;
    }

    pub fn deinit(self: StopHandler) void {
        std.os.close(self.fd);
    }

    pub fn register(self: *StopHandler, loop: *xev.Loop, comptime Userdata: type, userdata: ?*Userdata, comptime callback: *const fn (userdata: ?*Userdata, loop: *xev.Loop) void) void {
        self.completion = xev.Completion{
            .op = .{
                .read = .{
                    .fd = self.fd,
                    .buffer = .{ .slice = &self.storage },
                },
            },
            .callback = (struct {
                fn cb(
                    ud: ?*anyopaque,
                    inner_loop: *xev.Loop,
                    _: *xev.Completion,
                    _: xev.Result,
                ) xev.CallbackAction {
                    const inner_userdata: ?*Userdata = @ptrCast(@alignCast(ud));
                    @call(.always_inline, callback, .{ inner_userdata, inner_loop });

                    return .disarm;
                }
            }).cb,
            .userdata = userdata,
        };
        loop.add(&self.completion);
        std.os.sigprocmask(std.os.SIG.BLOCK, &self.mask, null);
    }
};

pub const CandidatePair = struct {
    local: usize,
    remote: usize,
};

pub const CandidatePairData = struct {
    data: [10]u8 = undefined,
};

fn stopHandlerCallback(userdata: ?*Context, loop: *xev.Loop) void {
    _ = loop;
    const context = userdata.?;
    std.log.info("Received SIGINT", .{});

    if (context.zice_context) |zice_context| {
        zice_context.stop();
    }
}

const Context = struct {
    zice_context: ?*zice.Context = null,
};

pub fn main() !void {
    std.log.info("Starting", .{});
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();

    var loop = try xev.Loop.init(.{});
    defer loop.deinit();

    var stop_handle = try StopHandler.init();
    defer stop_handle.deinit();

    var context = Context{};

    stop_handle.register(&loop, Context, &context, stopHandlerCallback);

    var zice_context = try zice.Context.init(gpa.allocator());
    defer zice_context.deinit();

    context.zice_context = &zice_context;

    try zice_context.start(&loop);

    try loop.run(.until_done);
}
