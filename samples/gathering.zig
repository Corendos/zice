// Copyright 2023 - Corentin Godeau and the zice contributors
// SPDX-License-Identifier: MIT

const std = @import("std");
const xev = zice.xev;
const utils = @import("utils");

const zice = @import("zice");

pub const std_options = struct {
    pub const log_scope_levels = &.{
        std.log.ScopeLevel{ .scope = .default, .level = .info },
        //std.log.ScopeLevel{ .scope = .zice, .level = .debug },
    };
    pub const logFn = utils.logFn;
};

pub fn candidateCallback(userdata: ?*anyopaque, agent_context: *zice.AgentContext, event: zice.CandidateEvent) void {
    _ = userdata;
    switch (event) {
        .candidate => |candidate_event| {
            std.log.info("Agent {} new candidate for media stream {}: ({s}) {} {}", .{
                agent_context.id,
                candidate_event.media_stream_id,
                @tagName(candidate_event.candidate.type),
                candidate_event.candidate.foundation.asNumber(),
                candidate_event.candidate.transport_address,
            });
        },
        else => {
            std.log.info("Agent {} all candidates gathered", .{agent_context.id});
        },
    }
}

pub fn stateChangeCallback(userdata: ?*anyopaque, agent_context: *zice.AgentContext, state: zice.AgentState) void {
    _ = userdata;
    std.log.info("Agent {} new state: {any}", .{ agent_context.id, state });
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

    // NOTE(Corendos,@Temporary): horrible hack until there is an initial interface/address discovery mechanism
    std.time.sleep(10 * std.time.ns_per_ms);

    const agent = try zice_context.createAgent(.{
        .userdata = &context,
        .on_candidate_callback = candidateCallback,
        .on_state_change_callback = stateChangeCallback,
    });
    context.agent = agent;

    zice_context.addMediaStream(agent, 1, 1) catch unreachable;

    try zice_context.gatherCandidates(agent);

    try loop.run(.until_done);
}
