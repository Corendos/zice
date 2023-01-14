// Copyright 2023 - Corentin Godeau and the zice contributors
// SPDX-License-Identifier: MIT

const std = @import("std");
const nl = @import("../netlink.zig");
const net = @import("../../net.zig");

const linux = std.os.linux;

pub const Cache = struct {
    const Self = @This();

    allocator: std.mem.Allocator,
    links: []nl.Link = &.{},
    addresses: []nl.Address = &.{},
    storage: ?std.heap.ArenaAllocator = null,

    pub fn init(allocator: std.mem.Allocator) Self {
        return Self{ .allocator = allocator };
    }

    pub fn deinit(self: Self) void {
        self.allocator.free(self.links);
        self.allocator.free(self.addresses);
        if (self.storage) |storage| {
            storage.deinit();
        }
    }

    pub fn update(self: *Self, socket: i32) !void {
        var new_storage = std.heap.ArenaAllocator.init(self.allocator);
        errdefer new_storage.deinit();

        const links = try listLink(socket, self.allocator, new_storage.allocator());
        errdefer self.allocator.free(links);
        const addresses = try listAddress(socket, self.allocator, new_storage.allocator());
        errdefer self.allocator.free(addresses);

        const old_links = self.links;
        const old_addresses = self.addresses;
        const old_storage_opt = self.storage;
        defer self.allocator.free(old_links);
        defer self.allocator.free(old_addresses);
        defer if (old_storage_opt) |old_storage| {
            old_storage.deinit();
        };

        self.storage = new_storage;
        self.links = links;
        self.addresses = addresses;
    }

    pub fn getAddressesByInterfaceIndexAlloc(self: *const Cache, interface_index: u32, allocator: std.mem.Allocator) ![]net.Address {
        var address_list = std.ArrayList(net.Address).init(allocator);
        defer address_list.deinit();

        for (self.addresses) |address| {
            if (address.interface_index == interface_index) {
                try address_list.append(address.address);
            }
        }

        return address_list.toOwnedSlice();
    }
};

pub fn listLink(netlink_socket: i32, allocator: std.mem.Allocator, storage: std.mem.Allocator) ![]nl.Link {
    var temp_arena_state = std.heap.ArenaAllocator.init(allocator);
    defer temp_arena_state.deinit();

    var temp_arena = temp_arena_state.allocator();

    const request_header = linux.nlmsghdr{
        .len = nl.nlmsg_length(@sizeOf(linux.ifinfomsg)),
        .type = linux.NetlinkMessageType.RTM_GETLINK,
        .flags = linux.NLM_F_DUMP | linux.NLM_F_REQUEST,
        .seq = 1,
        .pid = 0,
    };

    const request_payload = linux.ifinfomsg{
        .family = linux.AF.UNSPEC,
        .type = 0,
        .index = 0,
        .flags = 0,
        .change = 0xFFFFFFFF,
    };

    const request_buffer = blk: {
        var buffer = try temp_arena.alloc(u8, nl.nlmsg_space(@sizeOf(linux.ifinfomsg)));

        var stream = std.io.fixedBufferStream(buffer);
        var writer = stream.writer();
        try writer.writeStruct(request_header);
        try writer.writeStruct(request_payload);

        break :blk buffer;
    };

    try nl.write(netlink_socket, request_buffer);

    var link_list = std.ArrayList(nl.Link).init(allocator);
    defer link_list.deinit();

    const response_buffer = try temp_arena.alloc(u8, 8192);

    var done: bool = false;
    while (!done) {
        const response = try nl.read(netlink_socket, response_buffer);

        var message_it = nl.MessageIterator.init(@alignCast(@alignOf(linux.nlmsghdr), response));

        while (message_it.next()) |message| {
            if (message.flags & linux.NLM_F_MULTI == 0) {
                done = true;
            }

            const message_payload = nl.nlmsg_data(message);
            switch (message.type) {
                linux.NetlinkMessageType.DONE => {
                    done = true;
                },
                linux.NetlinkMessageType.RTM_NEWLINK => {
                    var link = nl.Link{ .type = undefined, .interface_index = undefined };
                    const link_info = @ptrCast(*const linux.ifinfomsg, @alignCast(@alignOf(linux.ifinfomsg), message_payload.ptr));
                    link.type = @intCast(u32, link_info.type);
                    link.interface_index = @intCast(u32, link_info.index);

                    var attribute_it = nl.AttributeIterator.init(@alignCast(@alignOf(nl.rtattr), message_payload[@sizeOf(linux.ifinfomsg)..]));
                    while (attribute_it.next()) |attribute| {
                        const attribute_data = nl.rta_data(attribute);
                        switch (nl.rtattr.as(linux.IFLA, attribute.*)) {
                            linux.IFLA.IFNAME => {
                                const name = @ptrCast([:0]const u8, attribute_data);
                                link.name = try storage.dupe(u8, name);
                            },
                            linux.IFLA.ADDRESS => {
                                std.mem.copy(u8, link.address[0..], attribute_data[0..6]);
                            },
                            else => {},
                        }
                    }

                    try link_list.append(link);
                },
                linux.NetlinkMessageType.ERROR => {
                    const nl_error = @ptrCast(*const nl.nlmsgerr, @alignCast(@alignOf(nl.nlmsgerr), message_payload.ptr));
                    std.log.err("Got error:\n{}", .{nl_error});
                },
                else => {},
            }
        }
    }

    return link_list.toOwnedSlice();
}

pub fn listAddress(netlink_socket: i32, allocator: std.mem.Allocator, storage: std.mem.Allocator) ![]nl.Address {
    _ = storage;
    var temp_arena_state = std.heap.ArenaAllocator.init(allocator);
    defer temp_arena_state.deinit();

    var temp_arena = temp_arena_state.allocator();

    const request_header = linux.nlmsghdr{
        .len = nl.nlmsg_length(@sizeOf(nl.ifaddrmsg)),
        .type = linux.NetlinkMessageType.RTM_GETADDR,
        .flags = linux.NLM_F_DUMP | linux.NLM_F_REQUEST,
        .seq = 1,
        .pid = 0,
    };

    const request_payload = nl.ifaddrmsg{
        .family = linux.AF.UNSPEC, //linux.AF.INET,
        .prefixlen = 0,
        .flags = 0,
        .scope = 0,
        .index = 0,
    };

    const request_buffer = blk: {
        var buffer = try temp_arena.alloc(u8, nl.nlmsg_space(@sizeOf(nl.ifaddrmsg)));

        var stream = std.io.fixedBufferStream(buffer);
        var writer = stream.writer();
        try writer.writeStruct(request_header);
        try writer.writeStruct(request_payload);

        break :blk buffer;
    };

    try nl.write(netlink_socket, request_buffer);

    var address_list = std.ArrayList(nl.Address).init(allocator);
    defer address_list.deinit();

    const response_buffer = try temp_arena.alloc(u8, 8192);

    var done: bool = false;
    while (!done) {
        const response = try nl.read(netlink_socket, response_buffer);

        var message_it = nl.MessageIterator.init(@alignCast(@alignOf(linux.nlmsghdr), response));

        while (message_it.next()) |message| {
            if (message.flags & linux.NLM_F_MULTI == 0) {
                done = true;
            }

            const message_payload = nl.nlmsg_data(message);
            switch (message.type) {
                linux.NetlinkMessageType.DONE => {
                    done = true;
                },
                linux.NetlinkMessageType.RTM_NEWADDR => {
                    var address = nl.Address{ .family = undefined, .interface_index = undefined, .address = undefined };

                    const addr_info = @ptrCast(*const nl.ifaddrmsg, @alignCast(@alignOf(nl.ifaddrmsg), message_payload.ptr));
                    address.interface_index = addr_info.index;
                    address.family = addr_info.family;

                    var attribute_it = nl.AttributeIterator.init(@alignCast(@alignOf(nl.rtattr), message_payload[@sizeOf(nl.ifaddrmsg)..]));
                    while (attribute_it.next()) |attribute| {
                        const attribute_data = nl.rta_data(attribute);
                        switch (nl.rtattr.as(nl.IFA, attribute.*)) {
                            nl.IFA.IFA_ADDRESS => {
                                switch (address.family) {
                                    linux.AF.INET => {
                                        address.address = net.Address{ .ipv4 = net.Ipv4Address{ .value = attribute_data[0..4].* } };
                                    },
                                    linux.AF.INET6 => {
                                        address.address = net.Address{ .ipv6 = net.Ipv6Address{ .value = attribute_data[0..16].* } };
                                    },
                                    else => return error.UnknownFamily,
                                }
                            },
                            else => {},
                        }
                    }

                    try address_list.append(address);
                },
                linux.NetlinkMessageType.ERROR => {
                    const nl_error = @ptrCast(*const nl.nlmsgerr, @alignCast(@alignOf(nl.nlmsgerr), message_payload.ptr));
                    std.log.err("Got error:\n{}", .{nl_error});
                },
                else => {},
            }
        }
    }
    return address_list.toOwnedSlice();
}
