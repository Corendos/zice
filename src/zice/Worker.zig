// Copyright 2023 - Corentin Godeau and the zice contributors
// SPDX-License-Identifier: MIT

const std = @import("std");
const xev = @import("xev");

const zice = @import("../main.zig");

const Self = @This();

loop: xev.Loop,
stopped: bool = false,
mutex: std.Thread.Mutex = .{},
async_poster: xev.Async,
async_poster_completion: xev.Completion = .{},

loop_completions: zice.Intrusive(xev.Completion) = .{},
worker_completions: zice.Intrusive(Completion) = .{},

pub const Completion = struct {
    userdata: ?*anyopaque = null,
    callback: *const fn (userdata: ?*anyopaque, worker: *Self, completion: *Completion) void = noop,

    next: ?*Completion = null,

    pub fn noop(userdata: ?*anyopaque, worker: *Self, completion: *Completion) void {
        _ = completion;
        _ = worker;
        _ = userdata;
    }
};

pub fn init() !Self {
    return Self{
        .loop = try xev.Loop.init(.{}),
        .async_poster = try xev.Async.init(),
    };
}

pub fn deinit(self: *Self) void {
    self.stop();
    self.loop.deinit();
    self.async_poster.deinit();
}

pub fn stop(self: *Self) void {
    self.mutex.lock();
    defer self.mutex.unlock();
    if (self.stopped) return;

    self.stopped = true;
    self.async_poster.notify() catch unreachable;
}

pub fn run(self: *Self) void {
    self.async_poster.wait(&self.loop, &self.async_poster_completion, Self, self, asyncPosterCallback);
    while (true) {
        {
            self.mutex.lock();
            defer self.mutex.unlock();
            if (self.stopped) {
                break;
            }
        }

        while (self.loop_completions.pop()) |c| {
            self.loop.add(c);
        }

        while (self.worker_completions.pop()) |c| {
            c.callback(c.userdata, self, c);
        }

        self.loop.run(.once) catch break;
    }

    self.loop.stop();
}

pub fn postCompletion(self: *Self, completion: *xev.Completion) void {
    self.loop_completions.push(completion);
    self.async_poster.notify() catch unreachable;
}

pub fn post(self: *Self, completion: *Completion) void {
    self.worker_completions.push(completion);
    self.async_poster.notify() catch unreachable;
}

fn asyncPosterCallback(userdata: ?*Self, loop: *xev.Loop, completion: *xev.Completion, result: xev.Async.WaitError!void) xev.CallbackAction {
    _ = completion;
    _ = loop;
    _ = userdata;
    _ = result catch unreachable;
    return .rearm;
}

test "worker lifecycle" {
    var worker = try Self.init();
    defer worker.deinit();

    var t = try std.Thread.spawn(.{}, (struct {
        pub fn callback(w: *Self) void {
            w.run();
        }
    }).callback, .{&worker});
    defer t.join();

    worker.stop();
}
