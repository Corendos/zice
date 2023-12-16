// Copyright 2023 - Corentin Godeau and the zice contributors
// SPDX-License-Identifier: MIT

const std = @import("std");
const xev = zice.xev;
const zice = @import("zice");
const utils = @import("utils");
const websocket = @import("websocket");

const StopHandler = utils.StopHandler;

pub const std_options = struct {
    pub const log_scope_levels = &.{
        //std.log.ScopeLevel{ .scope = .default, .level = .info },
        //std.log.ScopeLevel{ .scope = .zice, .level = .debug },
    };
    pub const logFn = utils.logFn;
};

const tracker_host = "localhost";
const tracker_url = std.fmt.comptimePrint("http://{s}:5000", .{tracker_host});

fn stopHandlerCallback(userdata: ?*anyopaque, loop: *xev.Loop, result: utils.StopHandler.Result) void {
    _ = result catch unreachable;
    _ = loop;
    const context: *Context = @ptrCast(@alignCast(userdata.?));
    std.log.info("Received SIGINT", .{});

    if (context.zice_context) |zice_context| {
        if (context.agent) |agent_id| {
            zice_context.deleteAgent(agent_id) catch unreachable;
        }
        zice_context.stop();
    }
    context.flags.stopped = true;
    context.async_handle.notify() catch unreachable;
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
            .gathering_done => {
                var arena_state = std.heap.ArenaAllocator.init(context.allocator);
                defer arena_state.deinit();

                const arena = arena_state.allocator();

                const message = SignalingMessage{
                    .peer_id = context.other_peer_id.?,
                    .sdp = context.sdp.?,
                    .type = if (context.agent_type.? == .controlling) .offer else .answer,
                };

                const payload: []u8 = @constCast(std.json.stringifyAlloc(arena, message, .{}) catch unreachable);

                context.websocket_handler.?.client.write(payload) catch unreachable;
            },
            .ice_completed => |agent_type| {
                _ = agent_type;
            },
            .message_received => |agent_type| {
                _ = agent_type;
            },
        }
    }
    return .rearm;
}

pub fn candidateCallback(userdata: ?*anyopaque, agent: *zice.AgentContext, result: zice.CandidateResult) void {
    const context: *Context = @alignCast(@ptrCast(userdata.?));
    if (result == .candidate) {
        std.log.info("Agent {} new candidate: ({s}) {} {}", .{ agent.id, @tagName(result.candidate.type), result.candidate.foundation.asNumber(), result.candidate.transport_address });
    } else if (result == .done) {
        context.sdp = zice.sdp.makeSdp(agent.local_auth.password, agent.local_auth.username_fragment, agent.local_candidates.items, context.agent_type.? == .controlling, context.allocator) catch unreachable;
        context.event_fifo_mutex.lock();
        defer context.event_fifo_mutex.unlock();

        context.event_fifo.push(ContextEvent{ .gathering_done = {} }) catch unreachable;
        context.async_handle.notify() catch unreachable;
    }
}

pub fn stateChangeCallback(userdata: ?*anyopaque, agent: *zice.AgentContext, state: zice.AgentState) void {
    const context: *Context = @alignCast(@ptrCast(userdata.?));
    _ = context;
    std.log.info("Agent {} new state: {any}", .{ agent.id, state });
    if (state == .completed) {}
}

fn gatherCandidateCallback(userdata: ?*anyopaque, result: zice.ContextResult) void {
    _ = result;
    _ = userdata;
}

fn remoteDescriptionCallback(userdata: ?*anyopaque, result: zice.ContextResult) void {
    const context: *Context = @alignCast(@ptrCast(userdata.?));
    if (context.remote_description) |d| {
        context.allocator.free(d.candidates);
        context.allocator.free(d.username_fragment);
        context.allocator.free(d.password);
    }
    _ = result;
}

const Context = struct {
    zice_context: ?*zice.Context = null,
    agent: ?zice.AgentId = null,
    allocator: std.mem.Allocator,

    gathering_completion: zice.ContextCompletion = undefined,
    remote_description_completion: zice.ContextCompletion = undefined,
    remote_description: ?RemoteDescription = null,

    event_fifo_mutex: std.Thread.Mutex = .{},
    event_fifo: zice.BoundedFifo(ContextEvent, 16) = .{},

    async_handle: xev.Async,
    async_completion: xev.Completion = .{},

    sdp: ?[]const u8 = null,
    other_peer_id: ?u64 = null,
    agent_type: ?AgentType = null,

    websocket_handler: ?Handler = null,

    flags: packed struct {
        stopped: bool = false,
    } = .{},

    fn init(allocator: std.mem.Allocator) !Context {
        return Context{
            .allocator = allocator,
            .async_handle = try xev.Async.init(),
        };
    }

    fn deinit(self: *Context) void {
        if (self.sdp) |sdp| {
            self.allocator.free(sdp);
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
    gathering_done: void,
    ice_completed: AgentType,
    message_received: AgentType,
};

const InitResponse = struct {
    peer_id: u64,
};

const SourcesResponse = struct {
    peers: []const u64,
};

const MessageType = enum {
    offer,
    answer,
};

const SignalingMessage = struct {
    peer_id: u64,
    type: MessageType,
    sdp: []const u8,
};

const RemoteDescription = struct {
    password: []const u8,
    username_fragment: []const u8,
    candidates: []const zice.Candidate,
};

fn candidateFromAttribute(attribute: zice.sdp.CandidateAttribute) !zice.Candidate {
    const foundation = std.fmt.parseInt(zice.Foundation.IntType, attribute.foundation, 10) catch return error.FoundationParseError;

    const component_id = std.fmt.parseInt(u8, attribute.component_id, 10) catch return error.ComponentIdParseError;

    const priority = std.fmt.parseInt(u32, attribute.priority, 10) catch return error.PriorityParseError;

    const candidate_type = zice.CandidateType.fromString(attribute.type) orelse return error.CandidateTypeParseError;

    const port = std.fmt.parseInt(u16, attribute.port, 10) catch return error.PortParseError;
    const address = std.net.Address.parseIp(attribute.address, port) catch return error.AddressParseError;

    return zice.Candidate{
        .type = candidate_type,
        .priority = priority,
        .component_id = component_id,
        .foundation = @bitCast(foundation),
        .transport_address = address,
        .base_address = address,
    };
}

fn parseRemoteDescription(sdp: []const u8, allocator: std.mem.Allocator) !?RemoteDescription {
    var maybe_password: ?[]const u8 = null;
    var maybe_username_fragment: ?[]const u8 = null;

    var candidate_list = std.ArrayList(zice.Candidate).init(allocator);
    defer candidate_list.deinit();

    var parser = zice.sdp.Parser.init(sdp);
    while (parser.next()) |attribute| {
        switch (attribute) {
            .ice_pwd => |ice_pwd_attribute| {
                maybe_password = ice_pwd_attribute.value;
            },
            .ice_ufrag => |ice_ufrag_attribute| {
                maybe_username_fragment = ice_ufrag_attribute.value;
            },
            .candidate => |c| {
                const candidate = candidateFromAttribute(c) catch |err| {
                    std.log.err("Failed to parse candidate: {}", .{err});
                    continue;
                };
                candidate_list.append(candidate) catch unreachable;
            },
            else => {},
        }
    }

    if (maybe_password == null or maybe_username_fragment == null) {
        return null;
    }

    const password = try allocator.dupe(u8, maybe_password.?);
    const username_fragment = try allocator.dupe(u8, maybe_username_fragment.?);

    return RemoteDescription{
        .password = password,
        .username_fragment = username_fragment,
        .candidates = try candidate_list.toOwnedSlice(),
    };
}

fn initTracker(client: *std.http.Client, allocator: std.mem.Allocator) !u64 {
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();

    const arena = arena_state.allocator();
    const url = std.fmt.allocPrint(arena, "{s}/init", .{tracker_url}) catch unreachable;

    const result = try client.fetch(arena, std.http.Client.FetchOptions{
        .method = .POST,
        .location = .{ .url = url },
    });

    if (result.status != .ok) return error.InvalidResponse;

    const body = result.body orelse return error.MissingBody;

    const response = try std.json.parseFromSliceLeaky(InitResponse, arena, body, .{});

    return response.peer_id;
}

fn byeTracker(client: *std.http.Client, peer_id: u64, allocator: std.mem.Allocator) !void {
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();

    const arena = arena_state.allocator();
    const url = std.fmt.allocPrint(arena, "{s}/bye", .{tracker_url}) catch unreachable;

    const body = try std.json.stringifyAlloc(arena, .{ .peer_id = peer_id }, .{});

    const result = try client.fetch(arena, std.http.Client.FetchOptions{
        .method = .POST,
        .location = .{ .url = url },
        .payload = .{ .string = body },
    });
    _ = result;
}

fn getSources(client: *std.http.Client, peer_id: u64, allocator: std.mem.Allocator) ![]u64 {
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();

    const arena = arena_state.allocator();
    const url = std.fmt.allocPrint(arena, "{s}/sources", .{tracker_url}) catch unreachable;

    const result = try client.fetch(arena, std.http.Client.FetchOptions{
        .method = .GET,
        .location = .{ .url = url },
    });

    if (result.status != .ok) return error.InvalidResponse;

    const body = result.body orelse return error.MissingBody;

    const response = try std.json.parseFromSliceLeaky(SourcesResponse, arena, body, .{});

    var peer_list = try std.ArrayList(u64).initCapacity(allocator, response.peers.len);
    defer peer_list.deinit();

    for (response.peers) |current_peer_id| {
        if (current_peer_id != peer_id) {
            peer_list.appendAssumeCapacity(current_peer_id);
        }
    }

    return peer_list.toOwnedSlice();
}

fn initSignaling(allocator: std.mem.Allocator, peer_id: u64) !websocket.Client {
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();

    const arena = arena_state.allocator();

    var ws_client = try websocket.connect(allocator, "localhost", 5001, .{});

    const peer_id_header = try std.fmt.allocPrint(arena, "Peer-ID: {}", .{peer_id});

    const path = std.fmt.allocPrint(arena, "/{}", .{peer_id}) catch unreachable;
    try ws_client.handshake(path, .{ .headers = peer_id_header });

    return ws_client;
}

const Handler = struct {
    client: *websocket.Client,
    context: ?*Context = null,

    pub fn handle(self: Handler, message: websocket.Message) !void {
        const context = self.context.?;

        var arena_state = std.heap.ArenaAllocator.init(context.allocator);
        defer arena_state.deinit();

        const arena = arena_state.allocator();

        const signaling_message = std.json.parseFromSliceLeaky(SignalingMessage, arena, message.data, .{}) catch unreachable;

        switch (signaling_message.type) {
            .offer => {
                std.debug.assert(context.agent_type == null);
                context.agent_type = .controlled;
                context.other_peer_id = signaling_message.peer_id;
            },
            .answer => {
                std.debug.assert(context.agent_type.? == .controlling);
            },
        }

        context.remote_description = parseRemoteDescription(signaling_message.sdp, context.allocator) catch unreachable;

        context.zice_context.?.setRemoteCandidates(
            context.agent.?,
            &context.remote_description_completion,
            zice.RemoteCandidateParameters{
                .username_fragment = context.remote_description.?.username_fragment,
                .password = context.remote_description.?.password,
                .candidates = context.remote_description.?.candidates,
            },
            context,
            remoteDescriptionCallback,
        ) catch unreachable;
    }

    pub fn close(_: Handler) void {}
};

pub fn main() !void {
    std.log.info("Starting", .{});
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();

    var loop = try xev.Loop.init(.{});
    defer loop.deinit();

    var stop_handler = try StopHandler.init();
    defer stop_handler.deinit();

    var context = try Context.init(gpa.allocator());
    defer context.deinit();

    stop_handler.register(&loop, &context, stopHandlerCallback);

    var zice_context = try zice.Context.init(gpa.allocator());
    defer zice_context.deinit();

    context.zice_context = &zice_context;

    var http_client = std.http.Client{ .allocator = gpa.allocator() };
    defer http_client.deinit();

    const peer_id = try initTracker(&http_client, gpa.allocator());
    defer byeTracker(&http_client, peer_id, gpa.allocator()) catch @panic("Bye failed");

    std.log.info("Got Peer ID: {}", .{peer_id});

    var ws_client = try initSignaling(gpa.allocator(), peer_id);
    defer ws_client.deinit();

    context.websocket_handler = Handler{ .client = &ws_client, .context = &context };
    const thread = try ws_client.readLoopInNewThread(&context.websocket_handler.?);
    thread.detach();

    var zice_thread = try std.Thread.spawn(.{}, (struct {
        pub fn f(inner_context: *Context) !void {
            try inner_context.zice_context.?.run();
        }
    }).f, .{&context});
    defer zice_thread.join();

    const agent = try zice_context.createAgent(.{
        .userdata = &context,
        .on_candidate_callback = candidateCallback,
        .on_state_change_callback = stateChangeCallback,
    });
    context.agent = agent;

    const other_peers = try getSources(&http_client, peer_id, gpa.allocator());
    defer gpa.allocator().free(other_peers);

    if (other_peers.len != 0) {
        context.other_peer_id = other_peers[0];
        context.agent_type = .controlling;
        try context.zice_context.?.gatherCandidates(context.agent.?, &context.gathering_completion, &context, gatherCandidateCallback);
    }

    context.async_handle.wait(
        &loop,
        &context.async_completion,
        Context,
        &context,
        asyncCallback,
    );

    try loop.run(.until_done);
}
