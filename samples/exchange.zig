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

pub fn controllingCandidateCallback(userdata: ?*anyopaque, agent: *zice.AgentContext, event: zice.CandidateEvent) void {
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
            context.controlling_agent_data.?.addCandidate(candidate_event.media_stream_id, candidate_event.candidate) catch unreachable;
        },
        .done => {
            context.event_fifo_mutex.lock();
            defer context.event_fifo_mutex.unlock();

            context.event_fifo.push(ContextEvent{ .gathering_done = .controlling }) catch unreachable;
            context.async_handle.notify() catch unreachable;
        },
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

pub fn controlledCandidateCallback(userdata: ?*anyopaque, agent: *zice.AgentContext, event: zice.CandidateEvent) void {
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
            context.controlled_agent_data.?.addCandidate(candidate_event.media_stream_id, candidate_event.candidate) catch unreachable;
        },
        .done => {
            context.event_fifo_mutex.lock();
            defer context.event_fifo_mutex.unlock();

            context.event_fifo.push(ContextEvent{ .gathering_done = .controlled }) catch unreachable;
            context.async_handle.notify() catch unreachable;
        },
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

pub fn controllingDataCallback(userdata: ?*anyopaque, agent: *zice.AgentContext, media_stream_id: usize, component_id: u8, data: []const u8) void {
    std.log.info("Agent {} - Received message on component {} of Media Stream {}: \"{s}\"", .{ agent.id, component_id, media_stream_id, data });

    const context: *Context = @alignCast(@ptrCast(userdata.?));

    context.event_fifo_mutex.lock();
    defer context.event_fifo_mutex.unlock();

    context.event_fifo.push(ContextEvent{ .message_received = .controlling }) catch unreachable;
    context.async_handle.notify() catch unreachable;
}

pub fn controlledDataCallback(userdata: ?*anyopaque, agent: *zice.AgentContext, media_stream_id: usize, component_id: u8, data: []const u8) void {
    std.log.info("Agent {} - Received message on component {} of Media Stream {}: \"{s}\"", .{ agent.id, component_id, media_stream_id, data });

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
    allocator: std.mem.Allocator,
    candidate_map: std.AutoArrayHashMap(usize, std.ArrayList(zice.Candidate)),

    pub fn init(id: zice.AgentId, allocator: std.mem.Allocator) !AgentData {
        var candidate_map = std.AutoArrayHashMap(usize, std.ArrayList(zice.Candidate)).init(allocator);
        errdefer candidate_map.deinit();

        return AgentData{
            .id = id,
            .allocator = allocator,
            .candidate_map = candidate_map,
        };
    }

    pub fn addCandidate(self: *AgentData, media_stream_id: usize, candidate: zice.Candidate) !void {
        const gop = try self.candidate_map.getOrPut(media_stream_id);
        if (!gop.found_existing) {
            gop.value_ptr.* = std.ArrayList(zice.Candidate).init(self.allocator);
        }

        try gop.value_ptr.append(candidate);
    }

    pub fn deinit(self: *AgentData) void {
        var it = self.candidate_map.iterator();
        while (it.next()) |entry| {
            entry.value_ptr.deinit();
        }
        self.candidate_map.deinit();
    }
};

const Context = struct {
    zice_context: ?*zice.Context = null,
    controlling_agent_data: ?AgentData = null,
    controlled_agent_data: ?AgentData = null,

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
        if (self.controlling_agent_data) |*data| {
            data.deinit();
        }

        if (self.controlled_agent_data) |*data| {
            data.deinit();
        }
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

    context.zice_context.?.deleteAgent(context.controlling_agent_data.?.id) catch {};
    context.zice_context.?.deleteAgent(context.controlled_agent_data.?.id) catch {};
    context.zice_context.?.stop();

    context.flags.stopped = true;
    context.async_handle.notify() catch unreachable;
}

const WaitableResult = struct {
    barrier: std.Thread.ResetEvent = .{},
    result: ?zice.ContextResult = null,
};

fn setRemoteCandidates(context: *Context, source_agent_data: *AgentData, destination_agent_data: *AgentData) zice.InvalidError!void {
    var result: WaitableResult = .{};

    var source_agent_context = context.zice_context.?.getAgentContext(source_agent_data.id) catch unreachable;

    var arena_state = std.heap.ArenaAllocator.init(context.allocator);
    defer arena_state.deinit();

    var arena = arena_state.allocator();

    var media_stream_parameters = arena.alloc(zice.MediaStreamRemoteParameters, source_agent_data.candidate_map.count()) catch unreachable;
    var it = source_agent_data.candidate_map.iterator();
    var index: usize = 0;
    while (it.next()) |entry| : (index += 1) {
        media_stream_parameters[index] = .{
            .media_stream_id = entry.key_ptr.*,
            .candidates = arena.dupe(zice.Candidate, entry.value_ptr.items) catch unreachable,
            .username_fragment = source_agent_context.local_auth.username_fragment,
            .password = source_agent_context.local_auth.password,
        };
    }

    const parameters = zice.RemoteCandidateParameters{
        .media_stream_parameters = media_stream_parameters,
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
                if (agent_type == .controlling) {
                    _ = send(context, &context.controlling_agent_data.?, 1, 1, "Ping!") catch unreachable;
                }
            },
            .message_received => |agent_type| {
                if (agent_type == .controlled) {
                    _ = send(context, &context.controlled_agent_data.?, 1, 1, "Pong!") catch unreachable;
                }
            },
        }
    }
    return .rearm;
}

fn addMediaStream(context: *zice.Context, agent_id: zice.AgentId, media_stream_id: usize, component_count: u8) !void {
    var future = zice.Future(zice.AddMediaStreamError!void){};
    var c: zice.ContextCompletion = undefined;

    context.addMediaStream(agent_id, &c, media_stream_id, component_count, &future, (struct {
        fn callback(userdata: ?*anyopaque, result: zice.ContextResult) void {
            var inner_future: *@TypeOf(future) = @ptrCast(@alignCast(userdata.?));
            inner_future.set(result.add_media_stream);
        }
    }).callback) catch unreachable;

    return future.get();
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{ .enable_memory_limit = true }){};
    defer _ = gpa.deinit();

    var allocator = gpa.allocator();

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

    const controlling_agent = try zice_context.createAgent(.{
        .userdata = &context,
        .on_candidate_callback = controllingCandidateCallback,
        .on_state_change_callback = controllingStateChangeCallback,
        .on_data_callback = controllingDataCallback,
    });

    var controlled_agent = try zice_context.createAgent(.{
        .userdata = &context,
        .on_candidate_callback = controlledCandidateCallback,
        .on_state_change_callback = controlledStateChangeCallback,
        .on_data_callback = controlledDataCallback,
    });

    context.controlling_agent_data = try AgentData.init(controlling_agent, allocator);
    context.controlled_agent_data = try AgentData.init(controlled_agent, allocator);

    for (0..2) |i| {
        addMediaStream(context.zice_context.?, controlling_agent, i + 1, 5) catch unreachable;
        addMediaStream(context.zice_context.?, controlled_agent, i + 1, 5) catch unreachable;
    }

    var gather_completion: zice.ContextCompletion = undefined;
    try zice_context.gatherCandidates(controlling_agent, &gather_completion, null, gatherCandidateCallback);

    context.async_handle.wait(&loop, &context.async_completion, Context, &context, asyncCallback);

    try loop.run(.until_done);
}
