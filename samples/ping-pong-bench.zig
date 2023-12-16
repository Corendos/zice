// Copyright 2023 - Corentin Godeau and the zice contributors
// SPDX-License-Identifier: MIT

const std = @import("std");
const xev = zice.xev;

const zice = @import("zice");
const utils = @import("utils");

pub const std_options = struct {
    pub const log_scope_levels = &.{
        std.log.ScopeLevel{ .scope = .default, .level = .info },
        std.log.ScopeLevel{ .scope = .zice, .level = .info },
    };
    pub const logFn = utils.logFn;
};

const message_size = 2048;
pub const message = [_]u8{1} ** message_size;

pub fn controllingCandidateCallback(userdata: ?*anyopaque, agent: *zice.AgentContext, result: zice.CandidateResult) void {
    const context: *Context = @alignCast(@ptrCast(userdata.?));
    if (result == .candidate) {
        std.log.info("Agent {} new candidate: ({s}) {} {}", .{ agent.id, @tagName(result.candidate.type), result.candidate.foundation.asNumber(), result.candidate.transport_address });
        context.controlling_agent_data.?.candidates.append(result.candidate) catch unreachable;
    } else if (result == .done) {
        context.event_fifo_mutex.lock();
        defer context.event_fifo_mutex.unlock();

        context.event_fifo.push(ContextEvent{ .gathering_done = .controlling }) catch unreachable;
        context.async_handle.notify() catch unreachable;
    }
}

pub fn controllingStateChangeCallback(userdata: ?*anyopaque, agent: *zice.AgentContext, state: zice.AgentState) void {
    const context: *Context = @alignCast(@ptrCast(userdata.?));
    std.log.info("Agent {} new state: {any}", .{ agent.id, state });
    if (state == .completed) {
        context.event_fifo_mutex.lock();
        defer context.event_fifo_mutex.unlock();

        context.event_fifo.push(ContextEvent{ .ice_completed = .controlling }) catch unreachable;
        context.async_handle.notify() catch unreachable;
    }
}

pub fn controlledCandidateCallback(userdata: ?*anyopaque, agent: *zice.AgentContext, result: zice.CandidateResult) void {
    const context: *Context = @alignCast(@ptrCast(userdata.?));
    if (result == .candidate) {
        std.log.info("Agent {} new candidate: ({s}) {} {}", .{ agent.id, @tagName(result.candidate.type), result.candidate.foundation.asNumber(), result.candidate.transport_address });
        context.controlled_agent_data.?.candidates.append(result.candidate) catch unreachable;
    } else if (result == .done) {
        context.event_fifo_mutex.lock();
        defer context.event_fifo_mutex.unlock();

        context.event_fifo.push(ContextEvent{ .gathering_done = .controlled }) catch unreachable;
        context.async_handle.notify() catch unreachable;
    }
}

pub fn controlledStateChangeCallback(userdata: ?*anyopaque, agent: *zice.AgentContext, state: zice.AgentState) void {
    const context: *Context = @alignCast(@ptrCast(userdata.?));
    std.log.info("Agent {} new state: {any}", .{ agent.id, state });
    if (state == .completed) {
        context.event_fifo_mutex.lock();
        defer context.event_fifo_mutex.unlock();

        context.event_fifo.push(ContextEvent{ .ice_completed = .controlled }) catch unreachable;
        context.async_handle.notify() catch unreachable;
    }
}

pub fn controllingDataCallback(userdata: ?*anyopaque, agent: *zice.AgentContext, component_id: u8, data: []const u8) void {
    _ = component_id;

    std.debug.assert(data.len == message_size);

    std.log.debug("Agent {} - Received message \"{s}\"", .{ agent.id, data });

    const context: *Context = @alignCast(@ptrCast(userdata.?));

    context.event_fifo_mutex.lock();
    defer context.event_fifo_mutex.unlock();

    context.event_fifo.push(ContextEvent{ .message_received = .controlling }) catch unreachable;
    context.async_handle.notify() catch unreachable;
}

pub fn controlledDataCallback(userdata: ?*anyopaque, agent: *zice.AgentContext, component_id: u8, data: []const u8) void {
    _ = component_id;

    std.debug.assert(data.len == message_size);

    std.log.debug("Agent {} - Received message \"{s}\"", .{ agent.id, data });

    const context: *Context = @alignCast(@ptrCast(userdata.?));

    context.event_fifo_mutex.lock();
    defer context.event_fifo_mutex.unlock();

    context.event_fifo.push(ContextEvent{ .message_received = .controlled }) catch unreachable;
    context.async_handle.notify() catch unreachable;
}

fn gatherCandidateCallback(userdata: ?*anyopaque, result: zice.ContextResult) void {
    _ = result;
    _ = userdata;
}

const AgentData = struct {
    id: zice.AgentId,
    candidates: std.ArrayList(zice.Candidate),
    completed: bool = false,

    pub fn init(id: zice.AgentId, allocator: std.mem.Allocator) !AgentData {
        var candidates = std.ArrayList(zice.Candidate).init(allocator);
        errdefer candidates.deinit();

        return AgentData{
            .id = id,
            .candidates = candidates,
        };
    }

    pub fn deinit(self: *AgentData) void {
        self.candidates.deinit();
    }
};

const BenchmarkState = struct {
    start_timestamp: ?i128 = null,
    end_timestamp: ?i128 = null,

    message_sent: u64 = 0,
};

const Context = struct {
    zice_context: ?*zice.Context = null,
    controlling_agent_data: ?AgentData = null,
    controlled_agent_data: ?AgentData = null,

    stop_handler: utils.StopHandler,

    event_fifo_mutex: std.Thread.Mutex = .{},
    event_fifo: zice.BoundedFifo(ContextEvent, 16) = .{},

    async_handle: xev.Async,
    async_completion: xev.Completion = .{},

    timer: xev.Timer,
    timer_completion: xev.Completion = .{},
    timer_cancel_completion: xev.Completion = .{},

    benchmark_state: BenchmarkState = .{},

    flags: packed struct {
        stopped: bool = false,
    } = .{},

    fn init() !Context {
        const stop_handler = try utils.StopHandler.init();
        errdefer stop_handler.deinit();

        const async_handle = try xev.Async.init();
        errdefer async_handle.deinit();

        const timer = try xev.Timer.init();
        errdefer timer.deinit();

        return Context{
            .stop_handler = stop_handler,
            .async_handle = async_handle,
            .timer = timer,
        };
    }

    fn deinit(self: *Context) void {
        if (self.controlling_agent_data) |*data| {
            data.deinit();
        }

        if (self.controlled_agent_data) |*data| {
            data.deinit();
        }

        self.async_handle.deinit();
        self.timer.deinit();
        self.stop_handler.deinit();
    }

    pub fn stop(self: *Context, loop: *xev.Loop) void {
        if (self.flags.stopped) return;
        self.flags.stopped = true;

        self.benchmark_state.end_timestamp = std.time.nanoTimestamp();

        self.zice_context.?.deleteAgent(self.controlling_agent_data.?.id) catch {};
        self.zice_context.?.deleteAgent(self.controlled_agent_data.?.id) catch {};
        self.zice_context.?.stop();

        self.async_handle.notify() catch unreachable;

        if (self.timer_completion.state() == .active) {
            self.timer.cancel(loop, &self.timer_completion, &self.timer_cancel_completion, Context, self, timerCancelCallback);
        }

        self.stop_handler.cancel(loop);
    }
};

const AgentType = enum {
    controlling,
    controlled,
};

const ContextEventType = enum {
    gathering_done,
    ice_completed,
    message_received,
};

const ContextEvent = union(ContextEventType) {
    gathering_done: AgentType,
    ice_completed: AgentType,
    message_received: AgentType,
};

fn stopHandlerCallback(userdata: ?*anyopaque, loop: *xev.Loop, result: utils.StopHandler.Result) void {
    _ = result catch unreachable;
    const context: *Context = @ptrCast(@alignCast(userdata.?));
    std.log.info("Received SIGINT", .{});

    context.stop(loop);
}

fn timerCallback(
    ud: ?*Context,
    l: *xev.Loop,
    c: *xev.Completion,
    r: xev.Timer.RunError!void,
) xev.CallbackAction {
    _ = c;
    _ = r catch |err| switch (err) {
        .Canceled => return .disarm,
        else => unreachable,
    };

    const context = ud.?;

    context.stop(l);

    return .disarm;
}

fn timerCancelCallback(
    ud: ?*Context,
    l: *xev.Loop,
    c: *xev.Completion,
    r: xev.Timer.CancelError!void,
) xev.CallbackAction {
    _ = r catch unreachable;
    _ = c;
    _ = l;
    _ = ud;

    return .disarm;
}

const WaitableResult = struct {
    barrier: std.Thread.ResetEvent = .{},
    result: ?zice.ContextResult = null,
};

fn setRemoteCandidates(context: *Context, source_agent_data: *AgentData, destination_agent_data: *AgentData) zice.InvalidError!void {
    var result: WaitableResult = .{};

    const source_agent_context = context.zice_context.?.getAgentContext(source_agent_data.id) catch unreachable;

    const parameters = zice.RemoteCandidateParameters{
        .candidates = source_agent_data.candidates.items,
        .username_fragment = source_agent_context.local_auth.username_fragment,
        .password = source_agent_context.local_auth.password,
    };

    var completion: zice.ContextCompletion = undefined;

    context.zice_context.?.setRemoteCandidates(
        destination_agent_data.id,
        &completion,
        parameters,
        &result,
        (struct {
            fn callback(userdata: ?*anyopaque, completion_result: zice.ContextResult) void {
                var inner_result: *WaitableResult = @ptrCast(@alignCast(userdata.?));
                inner_result.result = completion_result;
                inner_result.barrier.set();
            }
        }).callback,
    ) catch unreachable;

    result.barrier.wait();

    return result.result.?.set_remote_candidates;
}

fn send(context: *Context, agent_data: *AgentData, data_stream_id: u8, component_id: u8, data: []const u8) zice.SendError!usize {
    var result: WaitableResult = .{};

    var completion: zice.ContextCompletion = undefined;
    context.zice_context.?.send(agent_data.id, &completion, data_stream_id, component_id, data, &result, (struct {
        pub fn callback(userdata: ?*anyopaque, completion_result: zice.ContextResult) void {
            var inner_result: *WaitableResult = @ptrCast(@alignCast(userdata.?));
            inner_result.result = completion_result;
            inner_result.barrier.set();
        }
    }).callback) catch unreachable;

    result.barrier.wait();

    return result.result.?.send;
}

fn asyncCallback(userdata: ?*Context, loop: *xev.Loop, c: *xev.Completion, result: xev.Async.WaitError!void) xev.CallbackAction {
    const context = userdata.?;
    _ = result catch unreachable;

    if (context.flags.stopped) return .disarm;

    _ = c;
    _ = loop;

    var temp_fifo: zice.BoundedFifo(ContextEvent, 16) = .{};

    {
        context.event_fifo_mutex.lock();
        defer context.event_fifo_mutex.unlock();
        while (context.event_fifo.pop()) |event| {
            temp_fifo.push(event) catch unreachable;
        }
    }

    while (temp_fifo.pop()) |event| {
        switch (event) {
            .gathering_done => |agent_type| {
                const source_agent_data = if (agent_type == .controlling) &context.controlling_agent_data.? else &context.controlled_agent_data.?;
                const destination_agent_data = if (agent_type == .controlling) &context.controlled_agent_data.? else &context.controlling_agent_data.?;

                setRemoteCandidates(context, source_agent_data, destination_agent_data) catch unreachable;
            },
            .ice_completed => |agent_type| {
                switch (agent_type) {
                    .controlling => context.controlling_agent_data.?.completed = true,
                    .controlled => context.controlled_agent_data.?.completed = true,
                }

                if (context.controlling_agent_data.?.completed and context.controlled_agent_data.?.completed) {
                    context.benchmark_state.start_timestamp = std.time.nanoTimestamp();
                    _ = send(context, &context.controlling_agent_data.?, 1, 1, &message) catch unreachable;
                    context.benchmark_state.message_sent += 1;
                }
            },
            .message_received => |agent_type| {
                if (agent_type == .controlled) {
                    _ = send(context, &context.controlled_agent_data.?, 1, 1, &message) catch unreachable;
                    context.benchmark_state.message_sent += 1;
                } else if (agent_type == .controlling) {
                    _ = send(context, &context.controlling_agent_data.?, 1, 1, &message) catch unreachable;
                    context.benchmark_state.message_sent += 1;
                }
            },
        }
    }
    return .rearm;
}

pub fn main() !void {
    std.log.info("My PID is {}", .{std.os.linux.getpid()});

    var gpa = std.heap.GeneralPurposeAllocator(.{ .enable_memory_limit = true }){};
    defer _ = gpa.deinit();

    const allocator = gpa.allocator();

    var loop = try xev.Loop.init(.{});
    defer loop.deinit();

    var context = try Context.init();
    defer context.deinit();

    context.stop_handler.register(&loop, &context, stopHandlerCallback);

    var zice_context = try zice.Context.init(allocator);
    defer zice_context.deinit();

    context.zice_context = &zice_context;

    var t = try std.Thread.spawn(.{}, (struct {
        pub fn f(inner_context: *Context) !void {
            try inner_context.zice_context.?.run();
        }
    }).f, .{&context});
    defer t.join();

    const controlling_agent = try zice_context.createAgent(.{
        .userdata = &context,
        .on_candidate_callback = controllingCandidateCallback,
        .on_state_change_callback = controllingStateChangeCallback,
        .on_data_callback = controllingDataCallback,
    });

    const controlled_agent = try zice_context.createAgent(.{
        .userdata = &context,
        .on_candidate_callback = controlledCandidateCallback,
        .on_state_change_callback = controlledStateChangeCallback,
        .on_data_callback = controlledDataCallback,
    });

    context.controlling_agent_data = try AgentData.init(controlling_agent, allocator);
    context.controlled_agent_data = try AgentData.init(controlled_agent, allocator);

    var gather_completion: zice.ContextCompletion = undefined;
    try zice_context.gatherCandidates(controlling_agent, &gather_completion, null, gatherCandidateCallback);

    context.async_handle.wait(&loop, &context.async_completion, Context, &context, asyncCallback);

    try loop.run(.until_done);

    const elapsed_ns = context.benchmark_state.end_timestamp.? - context.benchmark_state.start_timestamp.?;
    const elapsed_s = @as(f64, @floatFromInt(elapsed_ns)) / 1e9;

    const message_per_s = @as(f64, @floatFromInt(context.benchmark_state.message_sent)) / elapsed_s;

    std.log.info("{d} msg/s ({d} MB/s)", .{ message_per_s, message_per_s * message.len / 1e6 });
}
