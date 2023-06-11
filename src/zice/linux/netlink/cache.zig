// Copyright 2023 - Corentin Godeau and the zice contributors
// SPDX-License-Identifier: MIT

const std = @import("std");
const xev = @import("xev");

const nl = @import("../netlink.zig");
const zice = @import("../../../main.zig");
const net = zice.net;

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

        //const links = try listLink(socket, self.allocator, new_storage.allocator());
        //errdefer self.allocator.free(links);
        const addresses = try listAddress(socket, self.allocator, new_storage.allocator());
        errdefer self.allocator.free(addresses);

        //const old_links = self.links;
        const old_addresses = self.addresses;
        const old_storage_opt = self.storage;
        //defer self.allocator.free(old_links);
        defer self.allocator.free(old_addresses);
        defer if (old_storage_opt) |old_storage| {
            old_storage.deinit();
        };

        self.storage = new_storage;
        //self.links = links;
        self.addresses = addresses;
    }

    pub fn getAddressesByInterfaceIndexAlloc(self: *const Cache, interface_index: u32, allocator: std.mem.Allocator) ![]nl.Address {
        var address_list = std.ArrayList(nl.Address).init(allocator);
        defer address_list.deinit();

        for (self.addresses) |address| {
            if (address.interface_index == interface_index) {
                try address_list.append(address);
            }
        }

        return address_list.toOwnedSlice();
    }
};

pub fn listLink(netlink_socket: i32, allocator: std.mem.Allocator, storage: std.mem.Allocator) ![]nl.Link {
    _ = storage;
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

    _ = try std.os.write(netlink_socket, request_buffer);

    var link_list = std.ArrayList(nl.Link).init(allocator);
    defer link_list.deinit();

    const response_buffer = try temp_arena.alloc(u8, 8192);
    _ = response_buffer;

    //var done: bool = false;
    //while (!done) {}

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

    _ = try std.os.write(netlink_socket, request_buffer);

    var address_list = std.ArrayList(nl.Address).init(allocator);
    defer address_list.deinit();

    const response_buffer = try temp_arena.alloc(u8, 8192);

    var done: bool = false;
    while (!done) {
        const bytes_read = try std.os.read(netlink_socket, response_buffer);
        const response = response_buffer[0..bytes_read];

        var message_it = nl.MessageIterator.init(@alignCast(response));

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
                    const addr_info = @as(*const nl.ifaddrmsg, @ptrCast(@alignCast(message_payload.ptr)));
                    var address = nl.Address{
                        .family = addr_info.family,
                        .prefix_length = addr_info.prefixlen,
                        .flags = addr_info.flags,
                        .scope = addr_info.scope,
                        .interface_index = @as(u8, @intCast(addr_info.index)),
                    };

                    var attribute_it = nl.AttributeIterator.init(@alignCast(message_payload[@sizeOf(nl.ifaddrmsg)..]));
                    while (attribute_it.next()) |attribute| {
                        const attribute_data = nl.rta_data(attribute);
                        switch (nl.rtattr.as(nl.IFA, attribute.*)) {
                            nl.IFA.IFA_ADDRESS => {
                                switch (address.family) {
                                    linux.AF.INET => {
                                        const a align(8) = linux.sockaddr.in{
                                            .port = 0,
                                            .addr = @as(u32, @bitCast(attribute_data[0..4].*)),
                                        };
                                        address.local_address = @as(*const linux.sockaddr.storage, @ptrCast(&a)).*;
                                    },
                                    linux.AF.INET6 => {
                                        const a align(8) = linux.sockaddr.in6{
                                            .port = 0,
                                            .flowinfo = 0,
                                            .addr = attribute_data[0..16].*,
                                            .scope_id = addr_info.index,
                                        };
                                        address.local_address = @as(*const linux.sockaddr.storage, @ptrCast(&a)).*;
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
                    const nl_error = @as(*const nl.nlmsgerr, @ptrCast(@alignCast(message_payload.ptr)));
                    std.log.err("Got error:\n{}", .{nl_error});
                },
                else => {},
            }
        }
    }
    return address_list.toOwnedSlice();
}
