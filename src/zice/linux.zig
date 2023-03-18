// Copyright 2023 - Corentin Godeau and the zice contributors
// SPDX-License-Identifier: MIT

const std = @import("std");

pub const nl = @import("linux/netlink.zig");
const zice = @import("../main.zig");
const net = zice.net;

/// Gather IP address for all interfaces.
pub fn getAddressesFromInterfaces(allocator: std.mem.Allocator) ![]std.net.Address {
    var temp_arena_state = std.heap.ArenaAllocator.init(allocator);
    defer temp_arena_state.deinit();

    var temp_arena = temp_arena_state.allocator();

    const socket = try std.os.socket(std.os.linux.AF.NETLINK, std.os.linux.SOCK.RAW, std.os.linux.NETLINK.ROUTE);
    defer std.os.close(socket);

    const address = std.os.linux.sockaddr.nl{ .pid = 0, .groups = 0 };
    try std.os.bind(socket, @ptrCast(*const std.os.linux.sockaddr, &address), @sizeOf(std.os.linux.sockaddr.nl));

    var netlink_cache = nl.Cache.init(temp_arena);

    try netlink_cache.update(socket);
    var address_list = std.ArrayList(std.net.Address).init(allocator);
    defer address_list.deinit();

    for (netlink_cache.links) |link| {
        if (link.device_type == nl.ARPHRD.LOOPBACK) continue;
        const nl_addresses = try netlink_cache.getAddressesByInterfaceIndexAlloc(link.interface_index, temp_arena);

        for (nl_addresses) |nl_address| {
            if (nl_address.address.any.family == std.os.linux.AF.INET6) {
                if (net.isSiteLocalIpv6(nl_address.address.in6) or net.isIpv4CompatibleIpv6(nl_address.address.in6) or net.isIpv4MappedIpv6(nl_address.address.in6)) continue;
            }
            try address_list.append(nl_address.address);
        }
    }

    return address_list.toOwnedSlice();
}

pub fn bind(socket: i32, address: std.net.Address) std.os.BindError!void {
    return std.os.bind(socket, &address.any, address.getOsSockLen());
}

pub fn getSocketPort(socket: i32) !u16 {
    var address_storage: std.os.sockaddr.storage = undefined;
    var address_size: u32 = @sizeOf(std.os.sockaddr.storage);

    std.os.getsockname(socket, @ptrCast(*std.os.sockaddr, &address_storage), &address_size) catch return error.BindError;
    return switch (address_storage.family) {
        std.os.AF.INET => @ptrCast(*std.os.sockaddr.in, &address_storage).port,
        std.os.AF.INET6 => @ptrCast(*std.os.sockaddr.in6, &address_storage).port,
        else => error.UnsupportedFamily,
    };
}

pub fn makeHostCandidates(addresses: []std.net.Address, sockets: []net.Socket, allocator: std.mem.Allocator) ![]zice.Candidate {
    var candidate_list = try std.ArrayList(zice.Candidate).initCapacity(allocator, addresses.len);
    defer candidate_list.deinit();

    for (addresses, 0..) |_, i| {
        const port = try getSocketPort(sockets[i].fd);
        var address = addresses[i];
        address.setPort(port);
        try candidate_list.append(zice.Candidate{
            .type = .host,
            .transport_address = address,
            .base_address = address,
        });
    }

    return try candidate_list.toOwnedSlice();
}
