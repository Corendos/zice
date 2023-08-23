// Copyright 2023 - Corentin Godeau and the zice contributors
// SPDX-License-Identifier: MIT

const std = @import("std");
const xev = @import("xev");
const utils = @import("utils");

const zice = @import("zice");

pub const std_options = struct {
    pub const log_scope_levels = &.{
        //std.log.ScopeLevel{ .scope = .default, .level = .info },
        std.log.ScopeLevel{ .scope = .zice, .level = .debug },
    };
    pub const logFn = utils.logFn;
};

pub fn candidateCallback(userdata: ?*anyopaque, agent_index: u32, result: zice.CandidateResult) void {
    _ = userdata;
    if (result == .candidate) {
        std.log.info("Agent {} new candidate: ({s}) {} {}", .{ agent_index, @tagName(result.candidate.type), result.candidate.foundation.as_number(), result.candidate.transport_address });
    }
}

pub fn stateChangeCallback(userdata: ?*anyopaque, agent_index: u32, state: zice.GatheringState) void {
    _ = userdata;
    std.log.info("Agent {} new gathering state: {any}", .{ agent_index, state });
}

const Context = struct {
    zice_context: ?*zice.Context = null,
    agent: ?zice.AgentId = null,
};

fn stopHandlerCallback(userdata: ?*Context, loop: *xev.Loop) void {
    _ = loop;
    const context = userdata.?;
    std.log.info("Received SIGINT", .{});

    context.zice_context.?.deleteAgent(context.agent.?) catch {};
    context.zice_context.?.stop();
}

fn gatherCandidateCallback(userdata: ?*anyopaque, result: zice.ContextResult) void {
    _ = result;
    _ = userdata;
    std.log.debug("Started candidate gathering", .{});
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{ .enable_memory_limit = true }){};
    defer _ = gpa.deinit();

    var network_loop = try xev.Loop.init(.{});
    defer network_loop.deinit();

    var stop_handler = try utils.StopHandler.init();
    defer stop_handler.deinit();

    var context = Context{};
    stop_handler.register(&network_loop, Context, &context, stopHandlerCallback);

    var zice_context = try zice.Context.init(&network_loop, gpa.allocator());
    defer zice_context.deinit();

    context.zice_context = &zice_context;

    var network_loop_thread = try std.Thread.spawn(.{}, (struct {
        fn callback(inner_context: *Context, l: *xev.Loop) !void {
            try inner_context.zice_context.?.start();
            try l.run(.until_done);
        }
    }).callback, .{ &context, &network_loop });

    const agent = try zice_context.createAgent(.{});
    context.agent = agent;

    var gather_completion: zice.ContextCompletion = undefined;
    try zice_context.gatherCandidates(agent, &gather_completion, null, gatherCandidateCallback);

    network_loop_thread.join();
}
