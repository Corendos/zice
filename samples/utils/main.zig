const std = @import("std");
const xev = @import("xev");

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
    ns: u16,
    us: u16,
    ms: u16,
    s: u8,
    m: u8,
    h: u64,

    pub inline fn fromTimestamp(timestamp: i128) Datetime {
        var t: u128 = @intCast(timestamp);
        const ns = t % 1000;
        t = t / 1000;
        const us = t % 1000;
        t = t / 1000;
        const ms = t % 1000;
        t = t / 1000;
        const s = t % 60;
        t = t / 60;
        const m = t % 60;
        t = t / 60;
        const h = t;
        return Datetime{
            .ns = @intCast(ns),
            .us = @intCast(us),
            .ms = @intCast(ms),
            .s = @intCast(s),
            .m = @intCast(m),
            .h = @intCast(h),
        };
    }

    pub fn format(self: Datetime, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
        _ = options;
        _ = fmt;
        try writer.print("{}:{:0>2}:{:0>2}.{:0>3}.{:0>3}.{:0>3}", .{
            self.h, self.m, self.s, self.ms, self.us, self.ns,
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

    const datetime = Datetime.fromTimestamp(std.time.nanoTimestamp());

    nosuspend stderr.print(level_color_escape.escapeString() ++ "{} ", .{datetime}) catch return;
    nosuspend stderr.print(level_txt ++ prefix2 ++ format ++ "\n" ++ "\x1b[0m", args) catch return;
}

pub const StopHandler = struct {
    storage: [@sizeOf(std.os.linux.signalfd_siginfo)]u8,
    fd: std.os.fd_t,
    mask: std.os.sigset_t,
    completion: xev.Completion = .{},

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
