// Copyright 2023 - Corentin Godeau and the zice contributors
// SPDX-License-Identifier: MIT

const std = @import("std");

const xev = @import("xev");
const zice = @import("zice");

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

//pub fn dummyCallback(userdata: ?*anyopaque, result: zice.Result) void {
//    const zice_context = @as(*zice.Context, @ptrCast(@alignCast(userdata.?)));
//    const candidates = result.gather_candidates catch return;
//    std.log.debug("Candidates: {any}", .{candidates});
//    zice_context.allocator.free(candidates);
//}

pub fn dummyCandidateCallback(userdata: ?*anyopaque, agent_index: u32, result: zice.CandidateResult) void {
    _ = userdata;
    std.log.debug("Agent {} new candidate: {any}", .{ agent_index, result });
}

pub fn dummyStateChangeCallback(userdata: ?*anyopaque, agent_index: u32, state: zice.GatheringState) void {
    _ = userdata;
    std.log.debug("Agent {} new gathering state: {any}", .{ agent_index, state });
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();

    var event_loop = try xev.Loop.init(.{});
    defer event_loop.deinit();

    var stop_handler = try StopHandler.init();
    defer stop_handler.deinit();

    stop_handler.register(&event_loop);

    var zice_context = try zice.Context.init(gpa.allocator());
    defer zice_context.deinit();

    try zice_context.start(&event_loop);

    const AGENT_COUNT = 1;

    var agents = [_]u32{0} ** AGENT_COUNT;

    for (&agents) |*agent_index| {
        agent_index.* = try zice_context.newAgent(.{
            .userdata = null,
            .on_candidate_callback = dummyCandidateCallback,
            .on_state_change_callback = dummyStateChangeCallback,
        });
    }
    defer for (agents) |agent_index| {
        zice_context.deleteAgent(agent_index);
    };

    var t = try std.Thread.spawn(.{}, (struct {
        pub fn callback(
            inner_zice_context: *zice.Context,
            inner_agents: *[AGENT_COUNT]u32,
        ) !void {
            std.time.sleep(1_000_000_000);
            for (inner_agents) |i| try inner_zice_context.gatherCandidates(i);
        }
    }).callback, .{
        &zice_context,
        &agents,
    });
    defer t.join();

    try event_loop.run(.until_done);
}
