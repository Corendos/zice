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

pub fn candidateCallback(userdata: ?*anyopaque, agent: *zice.AgentContext, index: usize, event: zice.CandidateEvent) void {
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

            context.event_fifo.push(ContextEvent{ .gathering_done = index }) catch unreachable;
            context.async_handle.notify() catch unreachable;
        },
    }
}

pub fn stateChangeCallback(userdata: ?*anyopaque, agent: *zice.AgentContext, index: usize, state: zice.AgentState) void {
    const context: *Context = @alignCast(@ptrCast(userdata.?));
    std.log.info("Agent {} new state: {any}", .{ agent.id, state });
    if (state == .completed) {
        context.event_fifo_mutex.lock();
        defer context.event_fifo_mutex.unlock();

        context.event_fifo.push(ContextEvent{ .ice_completed = index }) catch unreachable;
        context.async_handle.notify() catch unreachable;
    }
}

fn gatherCandidateCallback(userdata: ?*anyopaque, result: zice.ContextResult) void {
    _ = result;
    _ = userdata;
}

const Context = struct {
    zice_context: ?*zice.Context = null,
    agent_ids: [2]zice.AgentId = .{ undefined, undefined },

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

const ContextEventType = enum {
    gathering_done,
    ice_completed,
    message_received,
};

const ContextEvent = union(ContextEventType) {
    gathering_done: usize,
    ice_completed: usize,
    message_received: usize,
};

fn stopHandlerCallback(userdata: ?*anyopaque, loop: *xev.Loop, result: utils.StopHandler.Result) void {
    _ = result catch unreachable;
    _ = loop;
    const context: *Context = @ptrCast(@alignCast(userdata.?));
    std.log.info("Received SIGINT", .{});

    for (context.agent_ids[0..]) |id| {
        context.zice_context.?.deleteAgent(id) catch {};
    }
    context.zice_context.?.stop();

    context.flags.stopped = true;
    context.async_handle.notify() catch unreachable;
}

fn setRemoteCandidates(context: *Context, source_agent_id: zice.AgentId, destination_agent_id: zice.AgentId) zice.InvalidError!void {
    var arena_state = std.heap.ArenaAllocator.init(context.allocator);
    defer arena_state.deinit();

    const arena = arena_state.allocator();
    const description = context.zice_context.?.getLocalDescription(arena, source_agent_id) catch unreachable;

    return context.zice_context.?.setRemoteDescription(destination_agent_id, description);
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
            .gathering_done => |agent_index| {
                const source_agent_id = context.agent_ids[agent_index];
                const destination_agent_id = context.agent_ids[1 - agent_index];

                setRemoteCandidates(context, source_agent_id, destination_agent_id) catch unreachable;
            },
            .ice_completed => |_| {},
            .message_received => |_| {},
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

    const agent_1 = try zice_context.createAgent(.{
        .userdata = &context,
        .on_candidate_callback = (struct {
            pub fn callback(userdata: ?*anyopaque, agent: *zice.AgentContext, result: zice.CandidateEvent) void {
                return candidateCallback(userdata, agent, 0, result);
            }
        }).callback,
        .on_state_change_callback = (struct {
            pub fn callback(userdata: ?*anyopaque, agent: *zice.AgentContext, state: zice.AgentState) void {
                return stateChangeCallback(userdata, agent, 0, state);
            }
        }).callback,
    });
    context.agent_ids[0] = agent_1;

    const agent_2 = try zice_context.createAgent(.{
        .userdata = &context,
        .on_candidate_callback = (struct {
            pub fn callback(userdata: ?*anyopaque, agent: *zice.AgentContext, result: zice.CandidateEvent) void {
                return candidateCallback(userdata, agent, 1, result);
            }
        }).callback,
        .on_state_change_callback = (struct {
            pub fn callback(userdata: ?*anyopaque, agent: *zice.AgentContext, state: zice.AgentState) void {
                return stateChangeCallback(userdata, agent, 1, state);
            }
        }).callback,
    });
    context.agent_ids[1] = agent_2;

    zice_context.addMediaStream(context.agent_ids[0], 1, 1) catch unreachable;
    zice_context.addMediaStream(context.agent_ids[1], 1, 1) catch unreachable;

    try zice_context.gatherCandidates(context.agent_ids[0]);
    try zice_context.gatherCandidates(context.agent_ids[1]);

    context.async_handle.wait(&loop, &context.async_completion, Context, &context, asyncCallback);

    try loop.run(.until_done);
}
