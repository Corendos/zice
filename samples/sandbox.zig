// Copyright 2023 - Corentin Godeau and the zice contributors
// SPDX-License-Identifier: MIT

const std = @import("std");
const xev = @import("xev");
const zice = @import("zice");
const utils = @import("utils");

const StopHandler = utils.StopHandler;

pub const std_options = struct {
    pub const log_scope_levels = &.{
        //std.log.ScopeLevel{ .scope = .default, .level = .info },
        //std.log.ScopeLevel{ .scope = .zice, .level = .debug },
    };
    pub const logFn = utils.logFn;
};

pub const CandidatePair = struct {
    local: usize,
    remote: usize,
};

pub const CandidatePairData = struct {
    data: [10]u8 = undefined,
};

fn stopHandlerCallback(userdata: ?*anyopaque, loop: *xev.Loop, result: utils.StopHandler.Result) void {
    _ = result catch unreachable;
    _ = loop;
    const context: *Context = @ptrCast(@alignCast(userdata.?));
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

    var stop_handler = try StopHandler.init();
    defer stop_handler.deinit();

    var context = Context{};

    stop_handler.register(&loop, &context, stopHandlerCallback);

    var zice_context = try zice.Context.init(gpa.allocator());
    defer zice_context.deinit();

    context.zice_context = &zice_context;

    var t = try std.Thread.spawn(.{}, (struct {
        pub fn f(inner_context: *Context) !void {
            try inner_context.zice_context.?.run();
        }
    }).f, .{&context});
    defer t.join();

    try loop.run(.until_done);
}
