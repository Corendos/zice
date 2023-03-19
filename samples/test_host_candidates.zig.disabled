// Copyright 2023 - Corentin Godeau and the zice contributors
// SPDX-License-Identifier: MIT

const std = @import("std");
const zice = @import("zice");

pub const std_options = struct {
    pub fn logFn(
        comptime message_level: std.log.Level,
        comptime scope: @TypeOf(.enum_literal),
        comptime format: []const u8,
        args: anytype,
    ) void {
        const level_txt = comptime message_level.asText();
        const prefix2 = if (scope == .default) ": " else "(" ++ @tagName(scope) ++ "): ";
        const stderr = std.io.getStdErr().writer();
        std.debug.getStderrMutex().lock();
        defer std.debug.getStderrMutex().unlock();
        const now = std.time.Instant.now() catch unreachable;
        const thread_id = std.os.linux.gettid();
        const seconds = now.timestamp.tv_sec;
        const milliseconds = @intCast(u64, @divTrunc(now.timestamp.tv_nsec, std.time.ns_per_ms));
        nosuspend stderr.print("[{}.{:0>3}] [{}] ", .{ seconds, milliseconds, thread_id }) catch return;
        nosuspend stderr.print(level_txt ++ prefix2 ++ format ++ "\n", args) catch return;
    }
};

pub fn bindAddresses(addresses: []std.net.Address, allocator: std.mem.Allocator) !struct { addresses: []std.net.Address, sockets: []zice.net.Socket } {
    var output_address_list = try std.ArrayList(std.net.Address).initCapacity(allocator, addresses.len);
    defer output_address_list.deinit();

    var sockets_list = try std.ArrayList(zice.net.Socket).initCapacity(allocator, addresses.len);
    defer sockets_list.deinit();
    errdefer for (sockets_list.items) |socket| {
        std.os.close(socket.fd);
    };

    for (addresses) |address| {
        const socket = zice.net.Socket{ .fd = std.os.socket(address.any.family, std.os.SOCK.DGRAM, 0) catch return error.BindError };
        errdefer std.os.close(socket.fd);

        //std.os.bind(socket.fd, &address.any, address.getOsSockLen());

        zice.bind(socket.fd, address) catch return error.BindError;

        try output_address_list.append(address);
        try sockets_list.append(socket);
    }

    return .{
        .addresses = try output_address_list.toOwnedSlice(),
        .sockets = try sockets_list.toOwnedSlice(),
    };
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();

    var allocator = gpa.allocator();

    const addresses_and_socket = blk: {
        const addresses = try zice.getAddressesFromInterfaces(allocator);
        defer allocator.free(addresses);

        break :blk try bindAddresses(addresses, allocator);
    };
    const addresses = addresses_and_socket.addresses;
    const sockets = addresses_and_socket.sockets;
    defer allocator.free(addresses);
    defer allocator.free(sockets);

    const host_candidates: []zice.Candidate = try zice.makeHostCandidates(addresses, sockets, allocator);
    defer allocator.free(host_candidates);

    const server_reflexive_candidates: []zice.Candidate = try zice.makeServerReflexiveCandidates(host_candidates, sockets, allocator);
    defer allocator.free(server_reflexive_candidates);

    for (host_candidates) |candidate| {
        std.log.info("{s} {} {}", .{
            @tagName(candidate.type),
            candidate.transport_address,
            candidate.base_address,
        });
    }
    for (server_reflexive_candidates) |candidate| {
        std.log.info("{s} {} {}", .{
            @tagName(candidate.type),
            candidate.transport_address,
            candidate.base_address,
        });
    }
}
