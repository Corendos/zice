// Copyright 2023 - Corentin Godeau and the zice contributors
// SPDX-License-Identifier: MIT

const std = @import("std");
const zice = @import("zice");
const os = zice.os;

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
        const thread_id = os.linux.c.gettid();
        const seconds = now.timestamp.tv_sec;
        const milliseconds = @intCast(u64, @divTrunc(now.timestamp.tv_nsec, std.time.ns_per_ms));
        nosuspend stderr.print("[{}.{:0>3}] [{}] ", .{ seconds, milliseconds, thread_id }) catch return;
        nosuspend stderr.print(level_txt ++ prefix2 ++ format ++ "\n", args) catch return;
    }
};

pub fn bindAddresses(addresses: []zice.net.Address, allocator: std.mem.Allocator) !struct { addresses: []zice.net.Address, socket_fds: []i32 } {
    var output_address_list = try std.ArrayList(zice.net.Address).initCapacity(allocator, addresses.len);
    defer output_address_list.deinit();

    var socket_fds_list = try std.ArrayList(i32).initCapacity(allocator, addresses.len);
    defer socket_fds_list.deinit();
    errdefer for (socket_fds_list.items) |fd| {
        os.linux.close(fd) catch {};
    };

    for (addresses) |address| {
        const protocol_family = switch (address) {
            .ipv4 => os.linux.ProtocolFamily.inet,
            .ipv6 => os.linux.ProtocolFamily.inet6,
        };
        const socket = os.linux.socket(protocol_family, os.linux.SocketType.datagram) catch return error.BindError;
        errdefer os.linux.close(socket) catch {};

        zice.bind(socket, address, null) catch return error.BindError;

        try output_address_list.append(address);
        try socket_fds_list.append(socket);
    }

    return .{
        .addresses = try output_address_list.toOwnedSlice(),
        .socket_fds = try socket_fds_list.toOwnedSlice(),
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
    const socket_fds = addresses_and_socket.socket_fds;
    defer allocator.free(addresses);
    defer allocator.free(socket_fds);

    const host_candidates: []zice.Candidate = try zice.makeHostCandidates(addresses, socket_fds, allocator);
    defer allocator.free(host_candidates);

    const server_reflexive_candidates: []zice.Candidate = try zice.makeServerReflexiveCandidates(host_candidates, socket_fds, allocator);
    defer allocator.free(server_reflexive_candidates);

    for (host_candidates) |candidate| {
        std.log.info("{s} {} {} {} {}", .{
            @tagName(candidate.type),
            candidate.transport_address.address,
            candidate.transport_address.port,
            candidate.base_address.address,
            candidate.base_address.port,
        });
    }
    for (server_reflexive_candidates) |candidate| {
        std.log.info("{s} {} {} {} {}", .{
            @tagName(candidate.type),
            candidate.transport_address.address,
            candidate.transport_address.port,
            candidate.base_address.address,
            candidate.base_address.port,
        });
    }
}
