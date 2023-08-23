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
            .username_fragment = agent.local_auth.username_fragment,
            .password = agent.local_auth.password,
        };

        context.zice_context.?.setRemoteCandidates(
            context.controlled_agent.?,
            &context.controlling_set_remote_candidate_completion,
            parameters,
            null,
            setRemoteCandidatesCallback,
        ) catch unreachable;
    }
}

pub fn controllingStateChangeCallback(userdata: ?*anyopaque, agent: *zice.AgentContext, state: zice.AgentState) void {
    const context: *Context = @alignCast(@ptrCast(userdata.?));
    std.log.info("Agent {} new state: {any}", .{ agent.id, state });
    if (state == .completed) {
        context.zice_context.?.send(context.controlling_agent.?, &context.controlling_send_completion, 1, 1, "Ping!", null, (struct {
            pub fn callback(ud: ?*anyopaque, result: zice.ContextResult) void {
                _ = ud;
                _ = result;
                std.log.debug("Agent 1024 - Message sent!", .{});
            }
        }).callback) catch unreachable;
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
            .username_fragment = agent.local_auth.username_fragment,
            .password = agent.local_auth.password,
        };

        context.zice_context.?.setRemoteCandidates(
            context.controlling_agent.?,
            &context.controlled_set_remote_candidate_completion,
            parameters,
            null,
            setRemoteCandidatesCallback,
        ) catch unreachable;
    }
}

pub fn controlledStateChangeCallback(userdata: ?*anyopaque, agent: *zice.AgentContext, state: zice.AgentState) void {
    const context: *Context = @alignCast(@ptrCast(userdata.?));
    _ = context;
    std.log.info("Agent {} new state: {any}", .{ agent.id, state });
    if (state == .completed) {}
}

pub fn controllingDataCallback(userdata: ?*anyopaque, agent: *zice.AgentContext, component_id: u8, data: []const u8) void {
    _ = userdata;
    std.log.info("Agent {} received data for component {}: {s}", .{ agent.id, component_id, data });
}

pub fn controlledDataCallback(userdata: ?*anyopaque, agent: *zice.AgentContext, component_id: u8, data: []const u8) void {
    const context: *Context = @alignCast(@ptrCast(userdata.?));
    std.log.info("Agent {} received data for component {}: {s}", .{ agent.id, component_id, data });
    context.zice_context.?.send(context.controlled_agent.?, &context.controlled_send_completion, 1, 1, "Pong!", null, (struct {
        pub fn callback(ud: ?*anyopaque, result: zice.ContextResult) void {
            _ = ud;
            _ = result;
            std.log.debug("Agent 1025 - Message sent!", .{});
        }
    }).callback) catch unreachable;
}

fn gatherCandidateCallback(userdata: ?*anyopaque, result: zice.ContextResult) void {
    _ = result;
    _ = userdata;
    std.log.debug("Started candidate gathering", .{});
}

fn setRemoteCandidatesCallback(userdata: ?*anyopaque, result: zice.ContextResult) void {
    _ = result;
    _ = userdata;
    std.log.debug("Set remote candidates", .{});
}

const Context = struct {
    zice_context: ?*zice.Context = null,
    controlling_agent: ?zice.AgentId = null,
    controlled_agent: ?zice.AgentId = null,

    controlling_set_remote_candidate_completion: zice.ContextCompletion = undefined,
    controlled_set_remote_candidate_completion: zice.ContextCompletion = undefined,

    controlling_agent_candidates: std.ArrayList(zice.Candidate),
    controlled_agent_candidates: std.ArrayList(zice.Candidate),

    controlling_send_completion: zice.ContextCompletion = undefined,
    controlled_send_completion: zice.ContextCompletion = undefined,
};

fn stopHandlerCallback(userdata: ?*Context, loop: *xev.Loop) void {
    _ = loop;
    const context = userdata.?;
    std.log.info("Received SIGINT", .{});

    context.zice_context.?.deleteAgent(context.controlling_agent.?) catch {};
    context.zice_context.?.deleteAgent(context.controlled_agent.?) catch {};
    context.zice_context.?.stop();
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{ .enable_memory_limit = true }){};
    defer _ = gpa.deinit();

    var allocator = gpa.allocator();

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

    var zice_context = try zice.Context.init(&network_loop, allocator);
    defer zice_context.deinit();

    var network_loop_thread = try std.Thread.spawn(.{}, (struct {
        fn callback(l: *xev.Loop, inner_zice_context: *zice.Context) !void {
            try inner_zice_context.start();
            try l.run(.until_done);
        }
    }).callback, .{ &network_loop, &zice_context });

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

    context.zice_context = &zice_context;
    context.controlling_agent = controlling_agent;
    context.controlled_agent = controlled_agent;

    var gather_completion: zice.ContextCompletion = undefined;
    try zice_context.gatherCandidates(controlling_agent, &gather_completion, null, gatherCandidateCallback);

    network_loop_thread.join();
}
