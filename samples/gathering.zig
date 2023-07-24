// Copyright 2023 - Corentin Godeau and the zice contributors
// SPDX-License-Identifier: MIT

const std = @import("std");
const xev = @import("xev");

const zice = @import("zice");

pub const std_options = struct {
    pub const log_scope_levels = &.{
        //std.log.ScopeLevel{ .scope = .default, .level = .info },
        std.log.ScopeLevel{ .scope = .zice, .level = .debug },
    };
};

const StopHandler = struct {
    storage: [@sizeOf(std.os.linux.signalfd_siginfo)]u8,
    fd: std.os.fd_t,
    mask: std.os.sigset_t,
    completion: xev.Completion = .{},

    pub fn init() !StopHandler {
        var self: StopHandler = undefined;
        self.mask = m: {
            var mask = std.os.empty_sigset;
            std.os.linux.sigaddset(&mask, std.os.SIG.INT);
            break :m mask;
        };
        self.fd = try std.os.signalfd(-1, &self.mask, 0);
        errdefer std.os.close(self);

        return self;
    }

    pub fn deinit(self: StopHandler) void {
        std.os.close(self.fd);
    }

    pub fn register(self: *StopHandler, loop: *xev.Loop) void {
        self.completion = xev.Completion{
            .op = .{
                .read = .{
                    .fd = self.fd,
                    .buffer = .{ .slice = &self.storage },
                },
            },
            .callback = (struct {
                fn callback(
                    _: ?*anyopaque,
                    l: *xev.Loop,
                    _: *xev.Completion,
                    _: xev.Result,
                ) xev.CallbackAction {
                    std.log.info("Received SIGINT", .{});
                    l.stop();
                    return .disarm;
                }
            }).callback,
            .userdata = null,
        };
        loop.add(&self.completion);
        std.os.sigprocmask(std.os.SIG.BLOCK, &self.mask, null);
    }
};

pub fn candidateCallback(userdata: ?*anyopaque, agent_index: u32, result: zice.CandidateResult) void {
    _ = userdata;
    if (result == .candidate) {
        std.log.info("Agent {} new candidate: ({s}) {} {}", .{ agent_index, @tagName(result.candidate.type), result.candidate.foundation().as_number(), result.candidate.transport_address });
    }
}

pub fn stateChangeCallback(userdata: ?*anyopaque, agent_index: u32, state: zice.GatheringState) void {
    _ = userdata;
    std.log.info("Agent {} new gathering state: {any}", .{ agent_index, state });
}

const Context = struct {
    zice_context: *zice.Context,
    agent: u32 = 0,
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{ .enable_memory_limit = true }){};
    defer _ = gpa.deinit();

    var network_loop = try xev.Loop.init(.{});
    defer network_loop.deinit();

    var stop_handler = try StopHandler.init();
    defer stop_handler.deinit();

    stop_handler.register(&network_loop);

    var zice_context = try zice.Context.init(gpa.allocator());
    defer zice_context.deinit();

    try zice_context.start(&network_loop);

    var network_loop_thread = try std.Thread.spawn(.{}, (struct {
        fn callback(l: *xev.Loop) !void {
            try l.run(.until_done);
        }
    }).callback, .{&network_loop});

    var context = Context{
        .zice_context = &zice_context,
    };

    var agent = try zice_context.newAgent(zice.CreateAgentOptions{
        .userdata = &context,
        .on_candidate_callback = candidateCallback,
        .on_state_change_callback = stateChangeCallback,
    });
    defer zice_context.deleteAgent(agent);

    context.agent = agent;

    var gather_completion: zice.Completion = .{};

    try zice_context.gatherCandidates(&gather_completion, agent);

    network_loop_thread.join();
}