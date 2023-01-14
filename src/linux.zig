// Copyright 2023 - Corentin Godeau and the zice contributors
// SPDX-License-Identifier: MIT

const std = @import("std");
const net = @import("net.zig");
const nl = @import("linux/netlink.zig");

/// Gather IP address for all interfaces.
pub fn getAddressesFromInterfaces(allocator: std.mem.Allocator) ![]net.Address {
    var temp_arena_state = std.heap.ArenaAllocator.init(allocator);
    defer temp_arena_state.deinit();

    var temp_arena = temp_arena_state.allocator();

    const socket = try nl.createSocket();
    defer nl.closeSocket(socket);

    try nl.bindSocket(socket, 0, 0);

    var netlink_cache = nl.Cache.init(temp_arena);

    try netlink_cache.update(socket);
    var address_list = std.ArrayList(net.Address).init(allocator);
    defer address_list.deinit();

    for (netlink_cache.links) |link| {
        if (link.type == nl.ARPHRD.LOOPBACK) continue;
        const addresses = try netlink_cache.getAddressesByInterfaceIndexAlloc(link.interface_index, temp_arena);

        for (addresses) |address| {
            try address_list.append(address);
        }
    }

    return address_list.toOwnedSlice();
}
