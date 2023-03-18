// Copyright 2023 - Corentin Godeau and the zice contributors
// SPDX-License-Identifier: MIT

const std = @import("std");

const xev = @import("xev");
const zice = @import("zice");

const Context = struct {
    socket: std.os.fd_t,
    write_c: xev.Completion = undefined,
    read_c: xev.Completion = undefined,

    read_buffer: []u8,
};

pub fn writeCallback(
    userdata: ?*anyopaque,
    loop: *xev.Loop,
    completion: *xev.Completion,
    result: xev.Result,
) xev.CallbackAction {
    var context = @ptrCast(*Context, @alignCast(@alignOf(Context), userdata.?));
    _ = result;
    _ = completion;

    context.read_c = xev.Completion{
        .op = .{
            .read = .{
                .fd = context.socket,
                .buffer = .{ .slice = context.read_buffer },
            },
        },
        .userdata = context,
        .callback = readCallback,
    };
    loop.add(&context.read_c);

    return .disarm;
}

pub fn readCallback(
    userdata: ?*anyopaque,
    loop: *xev.Loop,
    completion: *xev.Completion,
    result: xev.Result,
) xev.CallbackAction {
    var context = @ptrCast(*Context, @alignCast(@alignOf(Context), userdata.?));
    _ = completion;
    _ = loop;
    const bytes_read = result.read catch unreachable;
    std.log.debug("{any}", .{context.read_buffer[0..bytes_read]});
    return .disarm;
}

pub const SignalContext = struct {
    fd: std.os.fd_t = -1,
    completion: xev.Completion = undefined,
    read_buffer: [@sizeOf(std.os.linux.signalfd_siginfo)]u8 = undefined,

    pub fn callback(
        userdata: ?*anyopaque,
        loop: *xev.Loop,
        completion: *xev.Completion,
        result: xev.Result,
    ) xev.CallbackAction {
        var context = @ptrCast(*SignalContext, @alignCast(@alignOf(SignalContext), userdata.?));
        _ = context;
        _ = completion;
        std.log.debug("Received signal", .{});
        const bytes_read = result.read catch unreachable;
        _ = bytes_read;
        loop.stop();
        return .disarm;
    }
};

pub fn setupSignalHandling(event_loop: *xev.Loop, context: *SignalContext) !void {
    var new_mask = std.os.empty_sigset;
    var old_mask = std.os.empty_sigset;
    std.os.linux.sigaddset(&new_mask, std.os.linux.SIG.INT);
    // Add SIGINT to list of blocked signals
    std.os.sigprocmask(std.os.linux.SIG.BLOCK, &new_mask, &old_mask);

    // Create a fd monitoring SIGINT
    context.fd = try std.os.signalfd(-1, &new_mask, 0);

    context.completion = xev.Completion{
        .op = .{
            .read = .{
                .fd = context.fd,
                .buffer = .{
                    .slice = &context.read_buffer,
                },
            },
        },
        .userdata = context,
        .callback = SignalContext.callback,
    };
    event_loop.add(&context.completion);
}

pub fn main() !void {
    var event_loop = try xev.Loop.init(.{});
    defer event_loop.deinit();

    var signal_context = SignalContext{};
    try setupSignalHandling(&event_loop, &signal_context);

    //var arena_state = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    //defer arena_state.deinit();

    //var arena = arena_state.allocator();

    //const socket = try std.os.socket(std.os.linux.AF.NETLINK, std.os.SOCK.RAW, std.os.linux.NETLINK.ROUTE);
    //defer std.os.close(socket);

    //const address = std.os.linux.sockaddr.nl{ .pid = 0, .groups = 0 };

    //try std.os.bind(socket, @ptrCast(*const std.os.linux.sockaddr, &address), @sizeOf(std.os.linux.sockaddr.nl));

    //var context = Context{
    //    .socket = socket,
    //    .read_buffer = try arena.alloc(u8, 4096),
    //};

    //const request_header = std.os.linux.nlmsghdr{
    //    .len = zice.nl.nlmsg_length(@sizeOf(std.os.linux.ifinfomsg)),
    //    .type = std.os.linux.NetlinkMessageType.RTM_GETLINK,
    //    .flags = std.os.linux.NLM_F_DUMP | std.os.linux.NLM_F_REQUEST,
    //    .seq = 1,
    //    .pid = 0,
    //};

    //const request_payload = std.os.linux.ifinfomsg{
    //    .family = std.os.linux.AF.UNSPEC,
    //    .type = 0,
    //    .index = 0,
    //    .flags = 0,
    //    .change = 0xFFFFFFFF,
    //};

    //const request_buffer = blk: {
    //    var buffer = try arena.alloc(u8, zice.nl.nlmsg_space(@sizeOf(std.os.linux.ifinfomsg)));

    //    var stream = std.io.fixedBufferStream(buffer);
    //    var writer = stream.writer();
    //    try writer.writeStruct(request_header);
    //    try writer.writeStruct(request_payload);

    //    break :blk buffer;
    //};

    //context.write_c = xev.Completion{
    //    .op = .{
    //        .write = .{
    //            .fd = socket,
    //            .buffer = .{ .slice = request_buffer },
    //        },
    //    },
    //    .userdata = &context,
    //    .callback = writeCallback,
    //};
    //event_loop.add(&context.write_c);

    try event_loop.run(.until_done);
}
