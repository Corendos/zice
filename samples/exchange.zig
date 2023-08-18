// Copyright 2023 - Corentin Godeau and the zice contributors
// SPDX-License-Identifier: MIT

const std = @import("std");
const xev = @import("xev");

const zice = @import("zice");

const LogColor = enum(u8) {
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

pub const std_options = struct {
    pub const log_scope_levels = &.{
        //std.log.ScopeLevel{ .scope = .default, .level = .info },
        //std.log.ScopeLevel{ .scope = .zice, .level = .debug },
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
};

const StopHandler = struct {
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

    pub fn register(self: *StopHandler, loop: *xev.Loop) void {
        self.completion = xev.Completion{
            .op = .{
                .read = .{
                    .fd = self.fd,
                    .buffer = .{ .slice = &self.storage },
                },
            },
            .callback = (struct {
                fn callback(
                    _: ?*anyopaque,
                    l: *xev.Loop,
                    _: *xev.Completion,
                    _: xev.Result,
                ) xev.CallbackAction {
                    std.log.info("Received SIGINT", .{});
                    l.stop();
                    return .disarm;
                }
            }).callback,
            .userdata = null,
        };
        loop.add(&self.completion);
        std.os.sigprocmask(std.os.SIG.BLOCK, &self.mask, null);
    }
};

pub fn controllingCandidateCallback(userdata: ?*anyopaque, agent_index: u32, result: zice.CandidateResult) void {
    const context: *Context = @alignCast(@ptrCast(userdata.?));
    if (result == .candidate) {
        std.log.info("Agent {} new candidate: ({s}) {} {}", .{ agent_index, @tagName(result.candidate.type), result.candidate.foundation.asNumber(), result.candidate.transport_address });
        context.controlling_agent_candidates.append(result.candidate) catch unreachable;
    } else if (result == .done) {
        const parameters = zice.RemoteCandidateParameters{ .candidates = context.controlling_agent_candidates.items, .username_fragment = context.controlling_agent_username, .password = context.controlling_agent_password };
        context.zice_context.setRemoteCandidates(&context.controlled_set_remote_candidate_completion, context.controlled_agent, parameters) catch unreachable;
    }
}

pub fn controllingStateChangeCallback(userdata: ?*anyopaque, agent_index: u32, state: zice.AgentState) void {
    const context: *Context = @alignCast(@ptrCast(userdata.?));
    std.log.info("Agent {} new state: {any}", .{ agent_index, state });
    if (state == .completed) {
        context.controlling_agent_event.set();
    }
}

pub fn controlledCandidateCallback(userdata: ?*anyopaque, agent_index: u32, result: zice.CandidateResult) void {
    const context: *Context = @alignCast(@ptrCast(userdata.?));
    if (result == .candidate) {
        std.log.info("Agent {} new candidate: ({s}) {} {}", .{ agent_index, @tagName(result.candidate.type), result.candidate.foundation.asNumber(), result.candidate.transport_address });
        context.controlled_agent_candidates.append(result.candidate) catch unreachable;
    } else if (result == .done) {
        const parameters = zice.RemoteCandidateParameters{ .candidates = context.controlled_agent_candidates.items, .username_fragment = context.controlled_agent_username, .password = context.controlled_agent_password };
        context.zice_context.setRemoteCandidates(&context.controlling_set_remote_candidate_completion, context.controlling_agent, parameters) catch unreachable;
    }
}

pub fn controlledStateChangeCallback(userdata: ?*anyopaque, agent_index: u32, state: zice.AgentState) void {
    const context: *Context = @alignCast(@ptrCast(userdata.?));
    std.log.info("Agent {} new state: {any}", .{ agent_index, state });
    if (state == .completed) {
        context.controlled_agent_event.set();
    }
}

pub fn dataCallback(userdata: ?*anyopaque, agent_index: u32, component_id: u8, data: []const u8) void {
    _ = userdata;
    std.log.info("Agent {} received data for component {}: {any}", .{ agent_index, component_id, data });
}

const Context = struct {
    zice_context: *zice.Context,
    controlling_agent: u32 = 0,
    controlled_agent: u32 = 0,

    controlling_set_remote_candidate_completion: zice.Completion = .{},
    controlled_set_remote_candidate_completion: zice.Completion = .{},

    controlling_agent_candidates: std.ArrayList(zice.Candidate),
    controlled_agent_candidates: std.ArrayList(zice.Candidate),

    controlling_agent_username: [8]u8 = undefined,
    controlling_agent_password: [24]u8 = undefined,

    controlled_agent_username: [8]u8 = undefined,
    controlled_agent_password: [24]u8 = undefined,

    controlling_agent_event: std.Thread.ResetEvent = .{},
    controlled_agent_event: std.Thread.ResetEvent = .{},
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{ .enable_memory_limit = true }){};
    defer _ = gpa.deinit();

    var allocator = gpa.allocator();

    //var allocator_state = std.heap.loggingAllocator(gpa.allocator());
    //var allocator = allocator_state.allocator();

    var network_loop = try xev.Loop.init(.{});
    defer network_loop.deinit();

    var stop_handler = try StopHandler.init();
    defer stop_handler.deinit();

    stop_handler.register(&network_loop);

    var zice_context = try zice.Context.init(allocator);
    defer zice_context.deinit();

    try zice_context.start(&network_loop);

    var network_loop_thread = try std.Thread.spawn(.{}, (struct {
        fn callback(l: *xev.Loop) !void {
            try l.run(.until_done);
        }
    }).callback, .{&network_loop});

    var context = Context{
        .zice_context = &zice_context,
        .controlling_agent_candidates = std.ArrayList(zice.Candidate).init(allocator),
        .controlled_agent_candidates = std.ArrayList(zice.Candidate).init(allocator),
    };
    defer context.controlling_agent_candidates.deinit();
    defer context.controlled_agent_candidates.deinit();

    var controlling_agent = try zice_context.newAgent(zice.CreateAgentOptions{
        .userdata = &context,
        .on_candidate_callback = controllingCandidateCallback,
        .on_state_change_callback = controllingStateChangeCallback,
        .on_data_callback = dataCallback,
    });
    defer zice_context.deleteAgent(controlling_agent);
    const controlling_agent_result = try zice_context.getAgentUsernameAndPassword(controlling_agent);
    context.controlling_agent_username = controlling_agent_result.username;
    context.controlling_agent_password = controlling_agent_result.password;

    var controlled_agent = try zice_context.newAgent(zice.CreateAgentOptions{
        .userdata = &context,
        .on_candidate_callback = controlledCandidateCallback,
        .on_state_change_callback = controlledStateChangeCallback,
        .on_data_callback = dataCallback,
    });
    defer zice_context.deleteAgent(controlled_agent);
    const controlled_agent_result = try zice_context.getAgentUsernameAndPassword(controlled_agent);
    context.controlled_agent_username = controlled_agent_result.username;
    context.controlled_agent_password = controlled_agent_result.password;

    context.controlling_agent = controlling_agent;
    context.controlled_agent = controlled_agent;

    var gather_completion: zice.Completion = .{};

    try zice_context.gatherCandidates(&gather_completion, controlling_agent);

    context.controlling_agent_event.wait();
    context.controlled_agent_event.wait();

    var send_completion: zice.Completion = undefined;
    var send_event = std.Thread.ResetEvent{};

    try zice_context.send(&send_completion, &send_event, (struct {
        pub fn callback(userdata: ?*anyopaque, result: zice.Result) void {
            _ = result;
            std.log.debug("Agent 1024 - Message sent!", .{});
            const inner_send_event: *std.Thread.ResetEvent = @ptrCast(@alignCast(userdata.?));
            inner_send_event.set();
        }
    }).callback, context.controlling_agent, 1, 1, "Hello");

    network_loop_thread.join();
}
