// Copyright 2023 - Corentin Godeau and the zice contributors
// SPDX-License-Identifier: MIT

const std = @import("std");
const xev = @import("xev");

const zice = @import("zice");

pub fn wakerNoopCallback(
    ud: ?*WorkerContext,
    l: *xev.Loop,
    c: *xev.Completion,
    r: xev.Async.WaitError!void,
) xev.CallbackAction {
    _ = ud;
    _ = r catch unreachable;
    _ = c;
    _ = l;
    return .disarm;
}

const WorkerContext = struct {
    event_loop: xev.Loop,
    stopped_mutex: std.Thread.Mutex = .{},
    stopped: bool = false,
    waker: xev.Async,
    waker_completion: xev.Completion = .{},

    submissions: zice.Intrusive(xev.Completion) = .{},

    pub fn init() !WorkerContext {
        return WorkerContext{
            .event_loop = try xev.Loop.init(.{}),
            .waker = try xev.Async.init(),
        };
    }

    pub fn deinit(self: *WorkerContext) void {
        self.stop();
        self.event_loop.deinit();
        self.waker.deinit();
    }

    pub fn stop(self: *WorkerContext) void {
        self.stopped_mutex.lock();
        defer self.stopped_mutex.unlock();
        if (self.stopped) return;

        self.stopped = true;

        self.waker.notify() catch unreachable;
    }

    pub fn add(self: *WorkerContext, c: *xev.Completion) void {
        self.submissions.push(c);
        self.waker.notify() catch unreachable;
    }

    pub fn run(self: *WorkerContext) !void {
        while (true) {
            {
                self.stopped_mutex.lock();
                defer self.stopped_mutex.unlock();

                if (self.stopped) {
                    self.event_loop.stop();
                    return;
                }
            }

            while (self.submissions.pop()) |c| {
                self.event_loop.add(c);
            }

            self.waker.wait(&self.event_loop, &self.waker_completion, WorkerContext, self, wakerNoopCallback);

            try self.event_loop.run(.until_done);
        }
    }
};

pub const Context = struct {
    barrier: std.Thread.ResetEvent,
    result: zice.nl.ListLinkError!zice.nl.ListLinkResult,
};

pub fn main() !void {
    const socket = try std.os.socket(std.os.linux.AF.NETLINK, std.os.SOCK.RAW, std.os.linux.NETLINK.ROUTE);
    defer std.os.close(socket);

    const address = std.os.linux.sockaddr.nl{ .pid = 0, .groups = 0 };

    try std.os.bind(socket, @ptrCast(*const std.os.linux.sockaddr, &address), @sizeOf(std.os.linux.sockaddr.nl));

    var worker_context = try WorkerContext.init();
    defer worker_context.deinit();

    const t = try std.Thread.spawn(.{}, (struct {
        pub fn callback(context: *WorkerContext) !void {
            try context.run();
        }
    }).callback, .{&worker_context});
    defer t.join();
    defer worker_context.stop();

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();

    var allocator = gpa.allocator();

    var context = Context{
        .barrier = std.Thread.ResetEvent{},
        .result = undefined,
    };

    const start = std.time.nanoTimestamp();
    var list_link_context = zice.nl.ListLinkContext.init(
        socket,
        allocator,
        &context,
        (struct {
            pub fn callback(userdata: ?*anyopaque, r: zice.nl.ListLinkError!zice.nl.ListLinkResult) void {
                var context_ptr = @ptrCast(*Context, @alignCast(@alignOf(Context), userdata.?));
                context_ptr.result = r;
                context_ptr.barrier.set();
            }
        }).callback,
    );
    try zice.nl.listLinkAsync(&list_link_context, &worker_context);

    context.barrier.wait();
    const result = try context.result;
    defer {
        allocator.free(result.links);
        result.storage.deinit();
    }

    const end = std.time.nanoTimestamp();
    for (result.links) |link| {
        std.log.debug("{}", .{link});
    }
    std.log.debug("Took {d}us", .{@intToFloat(f64, end - start) / @intToFloat(f64, std.time.ns_per_us)});
}
