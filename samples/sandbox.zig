// Copyright 2023 - Corentin Godeau and the zice contributors
// SPDX-License-Identifier: MIT

const std = @import("std");
const xev = @import("xev");

const zice = @import("zice");

pub fn Future(comptime T: type) type {
    return struct {
        const Self = @This();

        result: T = undefined,
        barrier: std.Thread.ResetEvent = .{},

        pub fn setValue(self: *Self, v: T) void {
            self.result = v;
            self.barrier.set();
        }

        pub fn getValue(self: *Self) T {
            self.barrier.wait();
            return self.result;
        }
    };
}

pub const Context = struct {
    sockets: []const std.os.fd_t,
    addresses: []const std.net.Address,

    pub fn initFromAddresses(addresses: []std.net.Address, allocator: std.mem.Allocator) !Context {
        var socket_list = try std.ArrayList(std.os.fd_t).initCapacity(allocator, addresses.len);
        defer socket_list.deinit();
        errdefer for (socket_list.items) |socket| {
            std.os.close(socket);
        };
        var address_list = try std.ArrayList(std.net.Address).initCapacity(allocator, addresses.len);
        defer address_list.deinit();

        for (addresses) |address| {
            const socket = try std.os.socket(address.any.family, std.os.SOCK.DGRAM, 0);
            try std.os.bind(socket, &address.any, address.getOsSockLen());
            const bound_address = blk: {
                var a = address;
                var a_len: std.os.socklen_t = a.getOsSockLen();
                try std.os.getsockname(socket, &a.any, &a_len);
                break :blk a;
            };
            try socket_list.append(socket);
            try address_list.append(bound_address);
        }

        return .{
            .sockets = socket_list.toOwnedSlice() catch unreachable,
            .addresses = address_list.toOwnedSlice() catch unreachable,
        };
    }

    pub fn deinit(self: Context, allocator: std.mem.Allocator) void {
        for (self.sockets) |socket| std.os.close(socket);
        allocator.free(self.sockets);
        allocator.free(self.addresses);
    }
};

pub fn main() !void {
    var worker = try zice.Worker.init();
    defer worker.deinit();

    const t = try std.Thread.spawn(.{}, (struct {
        pub fn callback(context: *zice.Worker) !void {
            context.run();
        }
    }).callback, .{&worker});
    defer t.join();
    defer worker.stop();

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();

    var allocator = std.heap.page_allocator;

    const addresses = try zice.getAddressesFromInterfaces(allocator, &worker);
    defer allocator.free(addresses);

    const context = try Context.initFromAddresses(addresses, allocator);
    defer context.deinit(allocator);

    std.log.debug("{any}", .{context});

    const CandidateFuture = Future(zice.CandidateGatheringError!zice.CandidateGatheringResult);
    var candidates_future = CandidateFuture{};

    var candidate_gathering_context = try zice.CandidateGatheringContext.init(context.sockets, context.addresses, allocator, &candidates_future, (struct {
        pub fn callback(userdata: ?*anyopaque, result: zice.CandidateGatheringError!zice.CandidateGatheringResult) void {
            const candidates_future_ptr = @ptrCast(*CandidateFuture, @alignCast(@alignOf(CandidateFuture), userdata.?));
            candidates_future_ptr.setValue(result);
        }
    }).callback);
    defer candidate_gathering_context.cleanup();

    zice.makeCandidates(&candidate_gathering_context, &worker);

    const candidate_result = try candidates_future.getValue();
    defer allocator.free(candidate_result.candidates);
    for (candidate_result.candidates) |c| {
        std.log.debug("{any}", .{c});
    }
}
