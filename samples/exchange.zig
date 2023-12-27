// Copyright 2023 - Corentin Godeau and the zice contributors
// SPDX-License-Identifier: MIT

const std = @import("std");
const xev = zice.xev;

const zice = @import("zice");
const utils = @import("utils");

pub const std_options = struct {
    pub const log_scope_levels = &.{
        //std.log.ScopeLevel{ .scope = .default, .level = .info },
        //std.log.ScopeLevel{ .scope = .zice, .level = .debug },
    };
    pub const logFn = utils.logFn;
};

pub fn candidateCallback(userdata: ?*anyopaque, agent: *zice.AgentContext, event: zice.CandidateEvent) void {
    const context: *Context = @alignCast(@ptrCast(userdata.?));
    switch (event) {
        .candidate => |candidate_event| {
            std.log.info("Agent {} new candidate for media stream {}: ({s}) {} {}", .{
                agent.id,
                candidate_event.media_stream_id,
                @tagName(candidate_event.candidate.type),
                candidate_event.candidate.foundation.asNumber(),
                candidate_event.candidate.transport_address,
            });
        },
        .done => {
            context.event_fifo_mutex.lock();
            defer context.event_fifo_mutex.unlock();

            const agent_type: AgentType = if (agent.id.eql(context.controlling_agent_id.?)) .controlling else .controlled;

            context.event_fifo.push(ContextEvent{ .gathering_done = agent_type }) catch unreachable;
            context.async_handle.notify() catch unreachable;
        },
    }
}

pub fn stateChangeCallback(userdata: ?*anyopaque, agent: *zice.AgentContext, state: zice.AgentState) void {
    const context: *Context = @alignCast(@ptrCast(userdata.?));
    std.log.info("Agent {} new state: {any}", .{ agent.id, state });
    if (state == .completed) {
        context.event_fifo_mutex.lock();
        defer context.event_fifo_mutex.unlock();

        const agent_type: AgentType = if (agent.id.eql(context.controlling_agent_id.?)) .controlling else .controlled;

        context.event_fifo.push(ContextEvent{ .ice_completed = agent_type }) catch unreachable;
        context.async_handle.notify() catch unreachable;
    }
}

pub fn dataCallback(userdata: ?*anyopaque, agent: *zice.AgentContext, media_stream_id: usize, component_id: u8, data: []const u8) void {
    std.log.info("Agent {} - Received message on component {} of Media Stream {}: \"{s}\"", .{ agent.id, component_id, media_stream_id, data });

    const context: *Context = @alignCast(@ptrCast(userdata.?));

    context.event_fifo_mutex.lock();
    defer context.event_fifo_mutex.unlock();

    const agent_type: AgentType = if (agent.id.eql(context.controlling_agent_id.?)) .controlling else .controlled;
    context.event_fifo.push(ContextEvent{ .message_received = agent_type }) catch unreachable;
    context.async_handle.notify() catch unreachable;
}

const Context = struct {
    zice_context: ?*zice.Context = null,
    controlling_agent_id: ?zice.AgentId = null,
    controlled_agent_id: ?zice.AgentId = null,

    event_fifo_mutex: std.Thread.Mutex = .{},
    event_fifo: zice.BoundedFifo(ContextEvent, 16) = .{},

    async_handle: xev.Async,
    async_completion: xev.Completion = .{},

    allocator: std.mem.Allocator,

    flags: packed struct {
        stopped: bool = false,
    } = .{},

    fn init(allocator: std.mem.Allocator) !Context {
        return Context{
            .async_handle = try xev.Async.init(),
            .allocator = allocator,
        };
    }

    fn deinit(self: *Context) void {
        self.async_handle.deinit();
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
    _ = loop;
    const context: *Context = @ptrCast(@alignCast(userdata.?));
    std.log.info("Received SIGINT", .{});

    context.zice_context.?.deleteAgent(context.controlling_agent_id.?) catch {};
    context.zice_context.?.deleteAgent(context.controlled_agent_id.?) catch {};
    context.zice_context.?.stop();

    context.flags.stopped = true;
    context.async_handle.notify() catch unreachable;
}

const WaitableResult = struct {
    barrier: std.Thread.ResetEvent = .{},
    result: ?zice.ContextResult = null,
};

fn setRemoteCandidates(context: *Context, source_agent_id: zice.AgentId, destination_agent_id: zice.AgentId) zice.InvalidError!void {
    var arena_state = std.heap.ArenaAllocator.init(context.allocator);
    defer arena_state.deinit();

    const arena = arena_state.allocator();
    const description = context.zice_context.?.getLocalDescription(arena, source_agent_id) catch unreachable;

    return context.zice_context.?.setRemoteDescription(destination_agent_id, description);
}

fn send(context: *Context, agent_id: zice.AgentId, data_stream_id: u8, component_id: u8, data: []const u8) zice.SendError!usize {
    var result: WaitableResult = .{};

    var completion: zice.ContextCompletion = undefined;
    context.zice_context.?.send(agent_id, &completion, data_stream_id, component_id, data, &result, (struct {
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
                const source_agent_id = if (agent_type == .controlling) context.controlling_agent_id.? else context.controlled_agent_id.?;
                const destination_agent_id = if (agent_type == .controlling) context.controlled_agent_id.? else context.controlling_agent_id.?;

                setRemoteCandidates(context, source_agent_id, destination_agent_id) catch unreachable;
            },
            .ice_completed => |agent_type| {
                if (agent_type == .controlling) {
                    _ = send(context, context.controlling_agent_id.?, 1, 1, "Ping!") catch unreachable;
                }
            },
            .message_received => |agent_type| {
                if (agent_type == .controlled) {
                    _ = send(context, context.controlled_agent_id.?, 1, 1, "Pong!") catch unreachable;
                }
            },
        }
    }
    return .rearm;
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{ .enable_memory_limit = true }){};
    defer _ = gpa.deinit();

    const allocator = gpa.allocator();

    var loop = try xev.Loop.init(.{});
    defer loop.deinit();

    var stop_handler = try utils.StopHandler.init();
    defer stop_handler.deinit();

    var context = try Context.init(allocator);
    defer context.deinit();

    stop_handler.register(&loop, &context, stopHandlerCallback);

    var zice_context = try zice.Context.init(allocator);
    defer zice_context.deinit();

    context.zice_context = &zice_context;

    var t = try std.Thread.spawn(.{}, (struct {
        pub fn f(inner_context: *Context) !void {
            try inner_context.zice_context.?.run();
        }
    }).f, .{&context});
    defer t.join();

    // NOTE(Corendos,@Temporary): horrible hack until there is an initial interface/address discovery mechanism
    std.time.sleep(10 * std.time.ns_per_ms);

    const controlling_agent = try zice_context.createAgent(.{
        .userdata = &context,
        .on_candidate_callback = candidateCallback,
        .on_state_change_callback = stateChangeCallback,
        .on_data_callback = dataCallback,
    });

    const controlled_agent = try zice_context.createAgent(.{
        .userdata = &context,
        .on_candidate_callback = candidateCallback,
        .on_state_change_callback = stateChangeCallback,
        .on_data_callback = dataCallback,
    });

    context.controlling_agent_id = controlling_agent;
    context.controlled_agent_id = controlled_agent;

    context.zice_context.?.addMediaStream(controlling_agent, 1, 1) catch unreachable;

    try zice_context.gatherCandidates(controlling_agent);

    context.async_handle.wait(&loop, &context.async_completion, Context, &context, asyncCallback);

    try loop.run(.until_done);
}
