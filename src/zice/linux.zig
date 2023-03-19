// Copyright 2023 - Corentin Godeau and the zice contributors
// SPDX-License-Identifier: MIT

const std = @import("std");

pub const nl = @import("linux/netlink.zig");
const zice = @import("../main.zig");
const net = zice.net;

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

/// Gather IP address for all interfaces.
pub fn getAddressesFromInterfaces(allocator: std.mem.Allocator, worker: *zice.Worker) ![]std.net.Address {
    var temp_arena_state = std.heap.ArenaAllocator.init(allocator);
    defer temp_arena_state.deinit();

    var temp_arena = temp_arena_state.allocator();

    const socket = s: {
        const socket = try std.os.socket(std.os.linux.AF.NETLINK, std.os.linux.SOCK.RAW, std.os.linux.NETLINK.ROUTE);

        const address = std.os.linux.sockaddr.nl{ .pid = 0, .groups = 0 };
        try std.os.bind(socket, @ptrCast(*const std.os.linux.sockaddr, &address), @sizeOf(std.os.linux.sockaddr.nl));
        break :s socket;
    };
    defer std.os.close(socket);

    const ListLinkResultFuture = Future(zice.nl.ListLinkError!zice.nl.ListLinkResult);
    var links_future = ListLinkResultFuture{};

    var list_link_context = zice.nl.ListLinkContext{
        .socket = socket,
        .allocator = temp_arena,
        .userdata = &links_future,
        .callback = (struct {
            pub fn callback(userdata: ?*anyopaque, r: zice.nl.ListLinkError!zice.nl.ListLinkResult) void {
                var future = @ptrCast(*ListLinkResultFuture, @alignCast(@alignOf(ListLinkResultFuture), userdata.?));
                future.setValue(r);
            }
        }).callback,
    };
    try zice.nl.listLinkAsync(&list_link_context, worker);
    var links_result = try links_future.getValue();

    var links_map = std.AutoHashMap(u32, zice.nl.Link).init(temp_arena);
    for (links_result.links) |link| {
        try links_map.put(link.interface_index, link);
    }

    const ListAddressResultFuture = Future(zice.nl.ListAddressError!zice.nl.ListAddressResult);
    var addresses_future = ListAddressResultFuture{};

    var list_address_context = zice.nl.ListAddressContext{
        .socket = socket,
        .allocator = temp_arena,
        .userdata = &addresses_future,
        .callback = (struct {
            pub fn callback(userdata: ?*anyopaque, r: zice.nl.ListAddressError!zice.nl.ListAddressResult) void {
                var future = @ptrCast(*ListAddressResultFuture, @alignCast(@alignOf(ListAddressResultFuture), userdata.?));
                future.setValue(r);
            }
        }).callback,
    };
    try zice.nl.listAddressAsync(&list_address_context, worker);
    var address_result = try addresses_future.getValue();

    var address_list = std.ArrayList(std.net.Address).init(allocator);
    defer address_list.deinit();

    for (address_result.addresses) |nl_address| {
        const interface_address = nl_address.interface_address orelse continue;
        const associated_link = links_map.get(nl_address.interface_index) orelse continue;
        if (associated_link.device_type == nl.ARPHRD.LOOPBACK) continue;

        const posix_address = @ptrCast(*const std.os.sockaddr, &interface_address);
        const inet_address = std.net.Address.initPosix(posix_address);

        if (inet_address.any.family == std.os.AF.INET6 and (net.isSiteLocalIpv6(inet_address.in6) or net.isIpv4CompatibleIpv6(inet_address.in6) or net.isIpv4MappedIpv6(inet_address.in6))) continue;

        try address_list.append(std.net.Address.initPosix(posix_address));
    }

    return address_list.toOwnedSlice();
}
