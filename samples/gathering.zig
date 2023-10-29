// Copyright 2023 - Corentin Godeau and the zice contributors
// SPDX-License-Identifier: MIT

const std = @import("std");
const xev = zice.xev;
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

fn stopHandlerCallback(userdata: ?*anyopaque, loop: *xev.Loop, result: utils.StopHandler.Result) void {
    _ = result catch unreachable;
    _ = loop;
    const context: *Context = @ptrCast(@alignCast(userdata.?));
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

    var loop = try xev.Loop.init(.{});
    defer loop.deinit();

    var stop_handler = try utils.StopHandler.init();
    defer stop_handler.deinit();

    var context = Context{};
    stop_handler.register(&loop, &context, stopHandlerCallback);

    var zice_context = try zice.Context.init(gpa.allocator());
    defer zice_context.deinit();

    context.zice_context = &zice_context;

    var t = try std.Thread.spawn(.{}, (struct {
        pub fn f(inner_context: *Context) !void {
            try inner_context.zice_context.?.run();
        }
    }).f, .{&context});
    defer t.join();

    const agent = try zice_context.createAgent(.{});
    context.agent = agent;

    var gather_completion: zice.ContextCompletion = undefined;
    try zice_context.gatherCandidates(agent, &gather_completion, null, gatherCandidateCallback);

    try loop.run(.until_done);
}
