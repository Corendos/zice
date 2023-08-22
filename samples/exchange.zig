// Copyright 2023 - Corentin Godeau and the zice contributors
// SPDX-License-Identifier: MIT

const std = @import("std");
const xev = @import("xev");

const zice = @import("zice");
const utils = @import("utils");

pub const std_options = struct {
    pub const log_scope_levels = &.{
        //std.log.ScopeLevel{ .scope = .default, .level = .info },
        //std.log.ScopeLevel{ .scope = .zice, .level = .debug },
    };
    pub const logFn = utils.logFn;
};

pub fn controllingCandidateCallback(userdata: ?*anyopaque, agent: *zice.AgentContext, result: zice.CandidateResult) void {
    const context: *Context = @alignCast(@ptrCast(userdata.?));
    if (result == .candidate) {
        std.log.info("Agent {} new candidate: ({s}) {} {}", .{ agent.id, @tagName(result.candidate.type), result.candidate.foundation.asNumber(), result.candidate.transport_address });
        context.controlling_agent_candidates.append(result.candidate) catch unreachable;
    } else if (result == .done) {
        const parameters = zice.RemoteCandidateParameters{
            .candidates = context.controlling_agent_candidates.items,
            .username_fragment = context.controlling_agent.?.username_fragment,
            .password = context.controlling_agent.?.password,
        };
        context.controlled_agent.?.setRemoteCandidates(&context.controlling_set_remote_candidate_completion, parameters, null, setRemoteCandidatesCallback) catch unreachable;
    }
}

pub fn controllingStateChangeCallback(userdata: ?*anyopaque, agent: *zice.AgentContext, state: zice.AgentState) void {
    const context: *Context = @alignCast(@ptrCast(userdata.?));
    std.log.info("Agent {} new state: {any}", .{ agent.id, state });
    if (state == .completed) {
        context.controlling_agent_event.set();
    }
}

pub fn controlledCandidateCallback(userdata: ?*anyopaque, agent: *zice.AgentContext, result: zice.CandidateResult) void {
    const context: *Context = @alignCast(@ptrCast(userdata.?));
    if (result == .candidate) {
        std.log.info("Agent {} new candidate: ({s}) {} {}", .{ agent.id, @tagName(result.candidate.type), result.candidate.foundation.asNumber(), result.candidate.transport_address });
        context.controlled_agent_candidates.append(result.candidate) catch unreachable;
    } else if (result == .done) {
        const parameters = zice.RemoteCandidateParameters{
            .candidates = context.controlled_agent_candidates.items,
            .username_fragment = context.controlled_agent.?.username_fragment,
            .password = context.controlled_agent.?.password,
        };
        context.controlling_agent.?.setRemoteCandidates(&context.controlled_set_remote_candidate_completion, parameters, null, setRemoteCandidatesCallback) catch unreachable;
    }
}

pub fn controlledStateChangeCallback(userdata: ?*anyopaque, agent: *zice.AgentContext, state: zice.AgentState) void {
    const context: *Context = @alignCast(@ptrCast(userdata.?));
    std.log.info("Agent {} new state: {any}", .{ agent.id, state });
    if (state == .completed) {
        context.controlled_agent_event.set();
    }
}

pub fn dataCallback(userdata: ?*anyopaque, agent: *zice.AgentContext, component_id: u8, data: []const u8) void {
    _ = userdata;
    std.log.info("Agent {} received data for component {}: {any}", .{ agent.id, component_id, data });
}

fn gatherCandidateCallback(userdata: ?*anyopaque, result: zice.AgentResult) void {
    _ = result;
    _ = userdata;
    std.log.debug("Started candidate gathering", .{});
}

fn setRemoteCandidatesCallback(userdata: ?*anyopaque, result: zice.AgentResult) void {
    _ = result;
    _ = userdata;
    std.log.debug("Set remote candidates", .{});
}

const Context = struct {
    zice_context: ?*zice.Context = null,
    controlling_agent: ?*zice.AgentContext = null,
    controlled_agent: ?*zice.AgentContext = null,

    controlling_set_remote_candidate_completion: zice.AgentCompletion = undefined,
    controlled_set_remote_candidate_completion: zice.AgentCompletion = undefined,

    controlling_agent_candidates: std.ArrayList(zice.Candidate),
    controlled_agent_candidates: std.ArrayList(zice.Candidate),

    controlling_agent_event: std.Thread.ResetEvent = .{},
    controlled_agent_event: std.Thread.ResetEvent = .{},
};

fn stopHandlerCallback(userdata: ?*Context, loop: *xev.Loop) void {
    _ = loop;
    const context = userdata.?;
    std.log.info("Received SIGINT", .{});

    if (context.controlling_agent) |agent| {
        agent.stop();
    }

    if (context.controlled_agent) |agent| {
        agent.stop();
    }

    if (context.zice_context) |zice_context| {
        zice_context.stop();
    }
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{ .enable_memory_limit = true }){};
    defer _ = gpa.deinit();

    var allocator = gpa.allocator();

    //var allocator_state = std.heap.loggingAllocator(gpa.allocator());
    //var allocator = allocator_state.allocator();

    var network_loop = try xev.Loop.init(.{});
    defer network_loop.deinit();

    var stop_handler = try utils.StopHandler.init();
    defer stop_handler.deinit();

    var context = Context{
        .controlling_agent_candidates = std.ArrayList(zice.Candidate).init(allocator),
        .controlled_agent_candidates = std.ArrayList(zice.Candidate).init(allocator),
    };
    defer context.controlling_agent_candidates.deinit();
    defer context.controlled_agent_candidates.deinit();

    stop_handler.register(&network_loop, Context, &context, stopHandlerCallback);

    var zice_context = try zice.Context.init(allocator);
    defer zice_context.deinit();

    try zice_context.start(&network_loop);

    var network_loop_thread = try std.Thread.spawn(.{}, (struct {
        fn callback(l: *xev.Loop) !void {
            try l.run(.until_done);
        }
    }).callback, .{&network_loop});

    var controlling_agent = try zice.AgentContext.init(
        &zice_context,
        &network_loop,
        .{
            .userdata = &context,
            .on_candidate_callback = controllingCandidateCallback,
            .on_state_change_callback = controllingStateChangeCallback,
            .on_data_callback = dataCallback,
        },
        gpa.allocator(),
    );
    defer controlling_agent.deinit();

    var controlled_agent = try zice.AgentContext.init(
        &zice_context,
        &network_loop,
        .{
            .userdata = &context,
            .on_candidate_callback = controlledCandidateCallback,
            .on_state_change_callback = controlledStateChangeCallback,
            .on_data_callback = dataCallback,
        },
        gpa.allocator(),
    );
    defer controlled_agent.deinit();

    context.zice_context = &zice_context;
    context.controlling_agent = &controlling_agent;
    context.controlled_agent = &controlled_agent;

    std.time.sleep(50_000_000);

    var gather_completion: zice.AgentCompletion = undefined;
    try controlling_agent.gatherCandidates(&gather_completion, null, gatherCandidateCallback);

    //context.controlling_agent_event.wait();
    //context.controlled_agent_event.wait();

    //var send_completion: zice.Completion = undefined;
    //var send_event = std.Thread.ResetEvent{};

    //try zice_context.send(&send_completion, &send_event, (struct {
    //    pub fn callback(userdata: ?*anyopaque, result: zice.Result) void {
    //        _ = result;
    //        std.log.debug("Agent 1024 - Message sent!", .{});
    //        const inner_send_event: *std.Thread.ResetEvent = @ptrCast(@alignCast(userdata.?));
    //        inner_send_event.set();
    //    }
    //}).callback, context.controlling_agent, 1, 1, "Hello");

    network_loop_thread.join();
}
