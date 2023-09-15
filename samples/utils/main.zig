// Copyright 2023 - Corentin Godeau and the zice contributors
// SPDX-License-Identifier: MIT

const std = @import("std");
const xev = @import("xev");

pub const time = @import("time.zig");

pub const LogColor = enum(u8) {
    black,
    red,
    green,
    yellow,
    blue,
    magenta,
    cyan,
    white,

    pub inline fn escapeString(self: LogColor) [:0]const u8 {
        return switch (self) {
            .black => "\x1b[30m",
            .red => "\x1b[31m",
            .green => "\x1b[32m",
            .yellow => "\x1b[33m",
            .blue => "\x1b[34m",
            .magenta => "\x1b[35m",
            .cyan => "\x1b[36m",
            .white => "\x1b[37m",
        };
    }

    pub inline fn fromLogLevel(level: std.log.Level) LogColor {
        return switch (level) {
            .err => .red,
            .warn => .yellow,
            .info => .green,
            .debug => .blue,
        };
    }
};

const Datetime = struct {
    value: std.os.linux.timeval,

    pub fn now() Datetime {
        var tv: std.os.linux.timeval = undefined;
        var tz: std.os.linux.timezone = undefined;
        _ = std.os.linux.gettimeofday(&tv, &tz);
        return Datetime{ .value = tv };
    }

    pub fn format(self: Datetime, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
        _ = options;
        _ = fmt;

        const local_time = time.localTime(self.value.tv_sec) catch unreachable;

        var value: u64 = @intCast(self.value.tv_usec);
        const us = value % 1000;
        value /= 1000;
        const ms = value % 1000;

        try writer.print("{:0>2}-{:0>2}-{:0>4} {:0>2}:{:0>2}:{:0>2}.{:0>3}.{:0>3}", .{
            @as(u64, @intCast(local_time.tm_mday)),
            @as(u64, @intCast(local_time.tm_mon + 1)),
            @as(u64, @intCast(1900 + local_time.tm_year)),
            @as(u64, @intCast(local_time.tm_hour)),
            @as(u64, @intCast(local_time.tm_min)),
            @as(u64, @intCast(local_time.tm_sec)),
            ms,
            us,
        });
    }
};

pub fn logFn(
    comptime message_level: std.log.Level,
    comptime scope: @TypeOf(.enum_literal),
    comptime format: []const u8,
    args: anytype,
) void {
    const level_txt = comptime message_level.asText();
    const level_color_escape = comptime LogColor.fromLogLevel(message_level);
    const prefix2 = if (scope == .default) ": " else "(" ++ @tagName(scope) ++ "): ";
    const stderr = std.io.getStdErr().writer();
    std.debug.getStderrMutex().lock();
    defer std.debug.getStderrMutex().unlock();

    const datetime = Datetime.now();

    nosuspend stderr.print(level_color_escape.escapeString() ++ "[{}] ", .{datetime}) catch return;
    nosuspend stderr.print(level_txt ++ prefix2 ++ format ++ "\n" ++ "\x1b[0m", args) catch return;
}

pub const StopHandler = struct {
    pub const Error = xev.ReadError;
    pub const Result = Error!void;
    pub const StopHandlerCallback = *const fn (userdata: ?*anyopaque, loop: *xev.Loop, result: Result) void;

    fn noopCallback(userdata: ?*anyopaque, loop: *xev.Loop, result: Result) void {
        _ = result catch {};
        _ = loop;
        _ = userdata;
    }

    storage: [@sizeOf(std.os.linux.signalfd_siginfo)]u8 = undefined,
    fd: std.os.fd_t = undefined,
    mask: std.os.sigset_t = undefined,
    completion: xev.Completion = .{},
    cancel_completion: xev.Completion = .{},

    flags: packed struct {
        is_canceled: bool = false,
    } = .{},

    result: ?Result = null,
    userdata: ?*anyopaque = null,
    callback: StopHandlerCallback = noopCallback,

    pub fn init() !StopHandler {
        var self: StopHandler = .{};
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

    pub fn register(self: *StopHandler, loop: *xev.Loop, userdata: ?*anyopaque, cb: StopHandlerCallback) void {
        self.userdata = userdata;
        self.callback = cb;

        self.completion = xev.Completion{
            .op = .{
                .read = .{
                    .fd = self.fd,
                    .buffer = .{ .slice = &self.storage },
                },
            },
            .callback = callback,
            .userdata = self,
        };
        loop.add(&self.completion);
        std.os.sigprocmask(std.os.SIG.BLOCK, &self.mask, null);
    }

    fn callback(userdata: ?*anyopaque, loop: *xev.Loop, c: *xev.Completion, result: xev.Result) xev.CallbackAction {
        _ = c;
        const self: *StopHandler = @ptrCast(@alignCast(userdata.?));

        const actual_result: Result = if (result.read) |_| {} else |err| err;
        if (self.result == null) {
            self.result = actual_result;
        }

        if (self.completion.state() == .dead and self.cancel_completion.state() == .dead) {
            self.callback(self.userdata, loop, self.result.?);
        }
        return .disarm;
    }

    fn cancelCallback(userdata: ?*anyopaque, loop: *xev.Loop, c: *xev.Completion, result: xev.Result) xev.CallbackAction {
        _ = c;
        const self: *StopHandler = @ptrCast(@alignCast(userdata.?));

        const actual_result: Result = if (result.cancel) |_| error.Canceled else |e| {
            std.log.err("{}", .{e});
            unreachable;
        };
        if (self.result == null) {
            self.result = actual_result;
        }

        if (self.completion.state() == .dead and self.cancel_completion.state() == .dead) {
            self.callback(self.userdata, loop, self.result.?);
        }
        return .disarm;
    }

    pub fn cancel(self: *StopHandler, loop: *xev.Loop) void {
        if (self.completion.state() == .dead) return;
        self.cancel_completion = .{
            .op = .{ .cancel = .{ .c = &self.completion } },
            .userdata = self,
            .callback = cancelCallback,
        };
        self.flags.is_canceled = true;
        loop.add(&self.cancel_completion);
    }
};
