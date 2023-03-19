// Copyright 2023 - Corentin Godeau and the zice contributors
// SPDX-License-Identifier: MIT

const std = @import("std");

const xev = @import("xev");

fn socketClosingWorker(socket: i32) void {
    std.time.sleep(5 * std.time.ns_per_s);
    std.os.close(socket);
}

fn readCallback(userdata: ?*anyopaque, loop: *xev.Loop, c: *xev.Completion, result: xev.Result) xev.CallbackAction {
    _ = result;
    _ = c;
    _ = loop;
    _ = userdata;

    return .disarm;
}

pub fn main() !void {
    var socket = try std.os.socket(std.os.linux.AF.INET, std.os.linux.SOCK.DGRAM, 0);
    //defer std.os.close(socket);

    const address = try std.net.Address.parseIp4("127.0.0.1", 12345);

    try std.os.bind(socket, &address.any, address.getOsSockLen());

    var t = try std.Thread.spawn(.{}, socketClosingWorker, .{socket});
    defer t.join();

    var loop = try xev.Loop.init(.{});
    defer loop.deinit();

    var buffer: [4096]u8 = undefined;

    var read_completion = xev.Completion{
        .op = .{
            .read = .{
                .fd = socket,
                .buffer = xev.ReadBuffer{ .slice = &buffer },
            },
        },
        .userdata = null,
        .callback = readCallback,
    };

    loop.add(&read_completion);

    try loop.run(.once);
}
