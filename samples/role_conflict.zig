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

pub fn candidateCallback(userdata: ?*anyopaque, agent: *zice.AgentContext, index: usize, result: zice.CandidateResult) void {
    const context: *Context = @alignCast(@ptrCast(userdata.?));
    if (result == .candidate) {
        std.log.info("Agent {} new candidate: ({s}) {} {}", .{ agent.id, @tagName(result.candidate.type), result.candidate.foundation.asNumber(), result.candidate.transport_address });
        context.agent_data[index].candidates.append(result.candidate) catch unreachable;
    } else if (result == .done) {
        const parameters = zice.RemoteCandidateParameters{
            .candidates = context.agent_data[index].candidates.items,
            .username_fragment = agent.local_auth.username_fragment,
            .password = agent.local_auth.password,
        };

        context.zice_context.?.setRemoteCandidates(
            context.agent_data[1 - index].id,
            &context.agent_data[1 - index].set_remote_candidate_completion,
            parameters,
            null,
            setRemoteCandidatesCallback,
        ) catch unreachable;
    }
}

pub fn stateChangeCallback(userdata: ?*anyopaque, agent: *zice.AgentContext, index: usize, state: zice.AgentState) void {
    _ = index;
    const context: *Context = @alignCast(@ptrCast(userdata.?));
    _ = context;
    std.log.info("Agent {} new state: {any}", .{ agent.id, state });
}

pub fn dataCallback(userdata: ?*anyopaque, agent: *zice.AgentContext, index: usize, component_id: u8, data: []const u8) void {
    _ = index;
    _ = userdata;
    std.log.info("Agent {} received data for component {}: {s}", .{ agent.id, component_id, data });
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

const AgentData = struct {
    id: zice.AgentId,
    candidates: std.ArrayList(zice.Candidate),
    set_remote_candidate_completion: zice.ContextCompletion = undefined,
    send_completion: zice.ContextCompletion = undefined,

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

const Context = struct {
    zice_context: ?*zice.Context = null,
    agent_data: [2]AgentData = undefined,
};

fn stopHandlerCallback(userdata: ?*anyopaque, loop: *xev.Loop, result: utils.StopHandler.Result) void {
    _ = result catch unreachable;
    _ = loop;
    const context: *Context = @ptrCast(@alignCast(userdata.?));
    std.log.info("Received SIGINT", .{});

    context.zice_context.?.deleteAgent(context.agent_data[0].id) catch {};
    context.zice_context.?.deleteAgent(context.agent_data[1].id) catch {};
    context.zice_context.?.stop();
}

pub fn createAgents(zice_context: *zice.Context, context: *Context) ![2]zice.AgentId {
    const agent_1 = try zice_context.createAgent(.{
        .userdata = context,
        .on_candidate_callback = (struct {
            pub fn callback(userdata: ?*anyopaque, agent: *zice.AgentContext, result: zice.CandidateResult) void {
                return candidateCallback(userdata, agent, 0, result);
            }
        }).callback,
        .on_state_change_callback = (struct {
            pub fn callback(userdata: ?*anyopaque, agent: *zice.AgentContext, state: zice.AgentState) void {
                return stateChangeCallback(userdata, agent, 0, state);
            }
        }).callback,
        .on_data_callback = (struct {
            pub fn callback(userdata: ?*anyopaque, agent: *zice.AgentContext, component_id: u8, data: []const u8) void {
                return dataCallback(userdata, agent, 0, component_id, data);
            }
        }).callback,
    });
    errdefer zice_context.deleteAgent(agent_1) catch unreachable;

    const agent_2 = try zice_context.createAgent(.{
        .userdata = context,
        .on_candidate_callback = (struct {
            pub fn callback(userdata: ?*anyopaque, agent: *zice.AgentContext, result: zice.CandidateResult) void {
                return candidateCallback(userdata, agent, 1, result);
            }
        }).callback,
        .on_state_change_callback = (struct {
            pub fn callback(userdata: ?*anyopaque, agent: *zice.AgentContext, state: zice.AgentState) void {
                return stateChangeCallback(userdata, agent, 1, state);
            }
        }).callback,
        .on_data_callback = (struct {
            pub fn callback(userdata: ?*anyopaque, agent: *zice.AgentContext, component_id: u8, data: []const u8) void {
                return dataCallback(userdata, agent, 1, component_id, data);
            }
        }).callback,
    });
    errdefer zice_context.deleteAgent(agent_2) catch unreachable;

    return [2]zice.AgentId{ agent_1, agent_2 };
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{ .enable_memory_limit = true }){};
    defer _ = gpa.deinit();

    var allocator = gpa.allocator();

    var loop = try xev.Loop.init(.{});
    defer loop.deinit();

    var stop_handler = try utils.StopHandler.init();
    defer stop_handler.deinit();

    var context = Context{};

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

    const agent_ids = try createAgents(&zice_context, &context);
    context.agent_data[0] = try AgentData.init(agent_ids[0], allocator);
    defer context.agent_data[0].deinit();
    context.agent_data[1] = try AgentData.init(agent_ids[1], allocator);
    defer context.agent_data[1].deinit();

    var gather_completion_1: zice.ContextCompletion = undefined;
    try zice_context.gatherCandidates(context.agent_data[0].id, &gather_completion_1, null, gatherCandidateCallback);
    var gather_completion_2: zice.ContextCompletion = undefined;
    try zice_context.gatherCandidates(context.agent_data[1].id, &gather_completion_2, null, gatherCandidateCallback);

    try loop.run(.until_done);
}
