// Copyright 2023 - Corentin Godeau and the zice contributors
// SPDX-License-Identifier: MIT

const std = @import("std");
const linux = std.os.linux;
const xev = @import("xev");

pub const netlink = @import("linux/netlink.zig");
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

fn formatMacAddress(value: [6]u8, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) @TypeOf(writer).Error!void {
    _ = options;
    _ = fmt;
    try writer.print("{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}", .{
        value[0],
        value[1],
        value[2],
        value[3],
        value[4],
        value[5],
    });
}

const MacAddressFormatter = std.fmt.Formatter(formatMacAddress);

fn formatFlags(value: anytype, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) @TypeOf(writer).Error!void {
    const type_info = @typeInfo(@TypeOf(value));
    const width = type_info.Int.bits;
    const flag_fmt = comptime std.fmt.comptimePrint("{{b:0>{}}}", .{width});
    try writer.print(flag_fmt, .{value});
    _ = options;
    _ = fmt;
}

fn FlagsFormatter(comptime T: type) type {
    return struct {
        flag: T,
        pub fn format(
            self: @This(),
            comptime fmt: []const u8,
            options: std.fmt.FormatOptions,
            writer: anytype,
        ) @TypeOf(writer).Error!void {
            try formatFlags(self.flag, fmt, options, writer);
        }
    };
}

const Link = struct {
    device_type: netlink.ARPHRD = undefined,
    interface_index: u32 = undefined,
    device_flags: u32 = undefined,
    address: ?[6]u8 = null,
    broadcast: ?[6]u8 = null,
    name: ?[]const u8 = null,
    mtu: ?u32 = null,
    link_type: ?u32 = null,
    queueing_discipline: ?[]const u8 = null,

    pub fn deinit(self: Link, allocator: std.mem.Allocator) void {
        if (self.name) |name| allocator.free(name);
        if (self.queueing_discipline) |queueing_discipline| allocator.free(queueing_discipline);
    }

    pub fn format(value: Link, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
        _ = options;
        _ = fmt;
        try writer.print(
            "Link{{ .device_type = {}, interface_index = {}, .device_flags = {}",
            .{ value.device_type, value.interface_index, FlagsFormatter(u32){ .flag = value.device_flags } },
        );
        if (value.address) |a| {
            try writer.print(", address = {}", .{MacAddressFormatter{ .data = a }});
        }
        if (value.broadcast) |a| {
            try writer.print(", broadcast = {}", .{MacAddressFormatter{ .data = a }});
        }
        if (value.name) |name| {
            try writer.print(", name = {s}", .{name});
        }
        try writer.writeAll(" }");
    }
};

const ListLinkError = error{ Unexpected, OutOfMemory };

const ListLinkResult = struct {
    links: []Link,
    storage: std.heap.ArenaAllocator,
};

const ListLinkContext = struct {
    socket: std.os.fd_t,
    allocator: std.mem.Allocator,
    userdata: ?*anyopaque,
    callback: *const fn (userdata: ?*anyopaque, result: ListLinkError!ListLinkResult) void,

    completion: xev.Completion = .{},
    buffer: [4096]u8 = undefined,

    result_links_list: std.ArrayListUnmanaged(Link) = .{},
    result_storage: ?std.heap.ArenaAllocator = null,

    pub fn cleanup(self: *ListLinkContext) void {
        self.result_links_list.deinit(self.allocator);
        if (self.result_storage) |storage| storage.deinit();
    }
};

fn listLinkAsyncWriteCallback(
    userdata: ?*anyopaque,
    loop: *xev.Loop,
    completion: *xev.Completion,
    result: xev.Result,
) xev.CallbackAction {
    const context = @as(*ListLinkContext, @ptrCast(@alignCast(userdata.?)));
    _ = result.write catch {
        context.cleanup();
        context.callback(context.userdata, error.Unexpected);
        return .disarm;
    };

    completion.* = xev.Completion{
        .op = .{
            .read = .{
                .fd = context.socket,
                .buffer = .{ .slice = &context.buffer },
            },
        },
        .userdata = context,
        .callback = listLinkAsyncReadCallback,
    };
    loop.add(&context.completion);

    return .disarm;
}

fn processLinkMessage(message_it: *netlink.MessageIterator, context: *ListLinkContext) !bool {
    var done = false;
    while (message_it.next()) |message| {
        if (message.flags & linux.NLM_F_MULTI == 0) {
            done = true;
        }

        switch (message.type) {
            linux.NetlinkMessageType.DONE => {
                done = true;
            },
            linux.NetlinkMessageType.RTM_NEWLINK => {
                const interface_info_msg = @as(*const linux.ifinfomsg, @ptrCast(@alignCast(message.data.ptr)));
                var link = Link{
                    .device_type = @as(netlink.ARPHRD, @enumFromInt(interface_info_msg.type)),
                    .interface_index = @as(u32, @bitCast(interface_info_msg.index)),
                    .device_flags = interface_info_msg.flags,
                };

                const raw_attributes = @as(linux.rtattr, @alignCast(message.data[@sizeOf(linux.ifinfomsg)..]));
                var attribute_it = netlink.AttributeIterator.init(raw_attributes);
                while (attribute_it.next()) |attribute| {
                    const ifla_attribute = netlink.IflaAttribute.from(attribute);
                    switch (ifla_attribute) {
                        .IFNAME => |interface_name| {
                            link.name = try context.result_storage.?.allocator().dupe(u8, interface_name);
                        },
                        .QDISC => |qdisc| {
                            link.queueing_discipline = try context.result_storage.?.allocator().dupe(u8, qdisc);
                        },
                        .ADDRESS => |addr| {
                            link.address = addr;
                        },
                        .BROADCAST => |addr| {
                            link.broadcast = addr;
                        },
                        .MTU => |mtu| {
                            link.mtu = mtu;
                        },
                        .LINK => |link_type| {
                            link.link_type = link_type;
                        },
                        else => {},
                    }
                }

                try context.result_links_list.append(context.allocator, link);
            },
            linux.NetlinkMessageType.ERROR => {
                const nl_error = @as(*const netlink.nlmsgerr, @ptrCast(@alignCast(message.data.ptr)));
                std.log.err("Got error:\n{}", .{nl_error});
            },
            else => {},
        }
    }

    return done;
}

fn listLinkAsyncReadCallback(
    userdata: ?*anyopaque,
    loop: *xev.Loop,
    completion: *xev.Completion,
    c_result: xev.Result,
) xev.CallbackAction {
    _ = loop;
    const context = @as(*ListLinkContext, @ptrCast(@alignCast(userdata.?)));
    _ = completion;

    if (context.result_storage == null) {
        context.result_storage = std.heap.ArenaAllocator.init(context.allocator);
    }

    const bytes_read = c_result.read catch {
        context.cleanup();
        context.callback(context.userdata, error.Unexpected);
        return .disarm;
    };
    const response = context.buffer[0..bytes_read];

    var message_it = netlink.MessageIterator.init(@alignCast(response));
    const done = processLinkMessage(&message_it, context) catch {
        context.cleanup();
        context.callback(context.userdata, error.Unexpected);
        return .disarm;
    };

    if (done) {
        var links = context.result_links_list.toOwnedSlice(context.allocator) catch |e| {
            context.cleanup();
            context.callback(context.userdata, e);
            return .disarm;
        };

        const result = ListLinkResult{ .links = links, .storage = context.result_storage.? };
        context.callback(context.userdata, result);
        return .disarm;
    }

    return .rearm;
}

fn listLinkAsync(context: *ListLinkContext, worker: *zice.Worker) !void {
    const raw_request = blk: {
        var stream = std.io.fixedBufferStream(&context.buffer);
        var writer = stream.writer();

        const request_header = linux.nlmsghdr{
            .len = netlink.nlmsg_length(@sizeOf(linux.ifinfomsg)),
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

        try writer.writeStruct(request_header);
        try writer.writeStruct(request_payload);

        break :blk stream.getWritten();
    };

    context.completion = xev.Completion{
        .op = .{
            .write = .{
                .fd = context.socket,
                .buffer = .{ .slice = raw_request },
            },
        },
        .userdata = context,
        .callback = listLinkAsyncWriteCallback,
    };
    worker.postCompletion(&context.completion);
}

const Address = struct {
    family: u8 = undefined,
    prefix_length: u8 = undefined,
    flags: u8 = undefined,
    scope: u8 = undefined,
    interface_index: u32 = undefined,
    interface_address: ?linux.sockaddr.storage = null,
    local_address: ?linux.sockaddr.storage = null,
    label: ?[]const u8 = null,
    broadcast_address: ?linux.sockaddr.storage = null,
    anycast_address: ?linux.sockaddr.storage = null,

    pub fn deinit(self: Link, allocator: std.mem.Allocator) void {
        if (self.label) |label| allocator.free(label);
    }

    pub fn format(value: Address, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
        _ = options;
        _ = fmt;
        try writer.print(
            "Address{{ .family = {}, .prefix_length = {}, .flags = {}, .scope = {}, .interface_index = {}",
            .{
                value.family,
                value.prefix_length,
                FlagsFormatter(u32){ .flag = value.flags },
                value.scope,
                value.interface_index,
            },
        );
        if (value.interface_address) |interface_address| {
            const address = std.net.Address.initPosix(@as(*const linux.sockaddr, @ptrCast(&interface_address)));
            try writer.print(", .interface_address = {}", .{address});
        }
        if (value.local_address) |local_address| {
            const address = std.net.Address.initPosix(@as(*const linux.sockaddr, @ptrCast(&local_address)));
            try writer.print(", .local_address = {}", .{address});
        }
        if (value.label) |label| {
            try writer.print(", .label = {s}", .{label});
        }
        if (value.broadcast_address) |broadcast_address| {
            const address = std.net.Address.initPosix(@as(*const linux.sockaddr, @ptrCast(&broadcast_address)));
            try writer.print(", .broadcast_address = {}", .{address});
        }
        if (value.anycast_address) |anycast_address| {
            const address = std.net.Address.initPosix(@as(*const linux.sockaddr, @ptrCast(&anycast_address)));
            try writer.print(", .anycast_address = {}", .{address});
        }
        try writer.writeAll(" }");
    }
};

const ListAddressError = error{ Unexpected, OutOfMemory };

const ListAddressResult = struct {
    addresses: []Address,
    storage: std.heap.ArenaAllocator,
};

const ListAddressContext = struct {
    socket: std.os.fd_t,
    allocator: std.mem.Allocator,
    userdata: ?*anyopaque,
    callback: *const fn (userdata: ?*anyopaque, result: ListAddressError!ListAddressResult) void,

    completion: xev.Completion = .{},
    buffer: [16 * 1024]u8 = undefined,

    result_addresses_list: std.ArrayListUnmanaged(Address) = .{},
    result_storage: ?std.heap.ArenaAllocator = null,

    pub fn cleanup(self: *ListAddressContext) void {
        self.result_addresses_list.deinit(self.allocator);
        if (self.result_storage) |storage| storage.deinit();
    }
};

fn listAddressAsyncWriteCallback(
    userdata: ?*anyopaque,
    loop: *xev.Loop,
    completion: *xev.Completion,
    result: xev.Result,
) xev.CallbackAction {
    const context = @as(*ListAddressContext, @ptrCast(@alignCast(userdata.?)));
    _ = result.write catch {
        context.cleanup();
        context.callback(context.userdata, error.Unexpected);
        return .disarm;
    };

    completion.* = xev.Completion{
        .op = .{
            .read = .{
                .fd = context.socket,
                .buffer = .{ .slice = &context.buffer },
            },
        },
        .userdata = context,
        .callback = listAddressAsyncReadCallback,
    };
    loop.add(&context.completion);

    return .disarm;
}

fn toSockaddr(family: u8, index: u32, raw: []const u8) linux.sockaddr.storage {
    return switch (family) {
        linux.AF.INET => blk: {
            const a align(8) = linux.sockaddr.in{
                .port = 0,
                .addr = @as(u32, @bitCast(raw[0..4].*)),
            };
            break :blk @as(*const linux.sockaddr.storage, @ptrCast(&a)).*;
        },
        linux.AF.INET6 => blk: {
            const a align(8) = linux.sockaddr.in6{
                .port = 0,
                .flowinfo = 0,
                .addr = raw[0..16].*,
                .scope_id = index,
            };
            break :blk @as(*const linux.sockaddr.storage, @ptrCast(&a)).*;
        },
        else => @panic("Unsupported family"),
    };
}

fn processAddressMessage(message_it: *netlink.MessageIterator, context: *ListAddressContext) !bool {
    var done = false;
    while (message_it.next()) |message| {
        if (message.flags & linux.NLM_F_MULTI == 0) {
            done = true;
        }

        switch (message.type) {
            linux.NetlinkMessageType.DONE => {
                done = true;
            },
            linux.NetlinkMessageType.RTM_NEWADDR => {
                const interface_address_msg = @as(*const netlink.ifaddrmsg, @ptrCast(@alignCast(message.data.ptr)));

                var address = Address{
                    .family = interface_address_msg.family,
                    .prefix_length = interface_address_msg.prefixlen,
                    .flags = interface_address_msg.flags,
                    .scope = interface_address_msg.scope,
                    .interface_index = interface_address_msg.index,
                };

                const raw_attributes = @as(*linux.rtattr, @alignCast(message.data[@sizeOf(netlink.ifaddrmsg)..]));
                var attribute_it = netlink.AttributeIterator.init(raw_attributes);
                while (attribute_it.next()) |attribute| {
                    switch (attribute.as(netlink.IFA)) {
                        netlink.IFA.ADDRESS => {
                            address.interface_address = toSockaddr(address.family, address.interface_index, attribute.data);
                        },
                        netlink.IFA.LOCAL => {
                            address.local_address = toSockaddr(address.family, address.interface_index, attribute.data);
                        },
                        netlink.IFA.BROADCAST => {
                            address.broadcast_address = toSockaddr(address.family, address.interface_index, attribute.data);
                        },
                        netlink.IFA.ANYCAST => {
                            address.anycast_address = toSockaddr(address.family, address.interface_index, attribute.data);
                        },
                        netlink.IFA.LABEL => {
                            const label = @as([:0]const u8, @ptrCast(attribute.data));
                            address.label = try context.result_storage.?.allocator().dupe(u8, label);
                        },
                        else => {},
                    }
                }

                try context.result_addresses_list.append(context.allocator, address);
            },
            linux.NetlinkMessageType.ERROR => {
                const nl_error = @as(*const netlink.nlmsgerr, @ptrCast(@alignCast(message.data.ptr)));
                std.log.err("Got error:\n{}", .{nl_error});
            },
            else => {},
        }
    }

    return done;
}

fn listAddressAsyncReadCallback(
    userdata: ?*anyopaque,
    loop: *xev.Loop,
    completion: *xev.Completion,
    c_result: xev.Result,
) xev.CallbackAction {
    _ = loop;
    const context = @as(*ListAddressContext, @ptrCast(@alignCast(userdata.?)));
    _ = completion;

    if (context.result_storage == null) {
        context.result_storage = std.heap.ArenaAllocator.init(context.allocator);
    }

    const bytes_read = c_result.read catch {
        context.cleanup();
        context.callback(context.userdata, error.Unexpected);
        return .disarm;
    };
    const response = context.buffer[0..bytes_read];

    var message_it = netlink.MessageIterator.init(@alignCast(response));
    const done = processAddressMessage(&message_it, context) catch {
        context.cleanup();
        context.callback(context.userdata, error.Unexpected);
        return .disarm;
    };

    if (done) {
        var addresses = context.result_addresses_list.toOwnedSlice(context.allocator) catch |e| {
            context.cleanup();
            context.callback(context.userdata, e);
            return .disarm;
        };

        const result = ListAddressResult{ .addresses = addresses, .storage = context.result_storage.? };
        context.callback(context.userdata, result);
        return .disarm;
    }

    return .rearm;
}

fn listAddressAsync(context: *ListAddressContext, worker: *zice.Worker) !void {
    const raw_request = blk: {
        var stream = std.io.fixedBufferStream(&context.buffer);
        var writer = stream.writer();

        const request_header = linux.nlmsghdr{
            .len = netlink.nlmsg_length(@sizeOf(netlink.ifaddrmsg)),
            .type = linux.NetlinkMessageType.RTM_GETADDR,
            .flags = linux.NLM_F_DUMP | linux.NLM_F_REQUEST,
            .seq = 1,
            .pid = 0,
        };

        const request_payload = netlink.ifaddrmsg{
            .family = linux.AF.UNSPEC,
            .prefixlen = 0,
            .flags = 0,
            .scope = 0,
            .index = 0,
        };

        try writer.writeStruct(request_header);
        try writer.writeStruct(request_payload);

        break :blk stream.getWritten();
    };

    context.completion = xev.Completion{
        .op = .{
            .write = .{
                .fd = context.socket,
                .buffer = .{ .slice = raw_request },
            },
        },
        .userdata = context,
        .callback = listAddressAsyncWriteCallback,
    };
    worker.postCompletion(&context.completion);
}

/// Gather IP address for all interfaces.
pub fn getAddressesFromInterfaces(allocator: std.mem.Allocator, worker: *zice.Worker) ![]std.net.Address {
    var temp_arena_state = std.heap.ArenaAllocator.init(allocator);
    defer temp_arena_state.deinit();

    var temp_arena = temp_arena_state.allocator();

    const socket = s: {
        const socket = try std.os.socket(linux.AF.NETLINK, linux.SOCK.RAW, linux.NETLINK.ROUTE);

        const address = linux.sockaddr.nl{ .pid = 0, .groups = 0 };
        try std.os.bind(socket, @as(*const linux.sockaddr, @ptrCast(&address)), @sizeOf(linux.sockaddr.nl));
        break :s socket;
    };
    defer std.os.close(socket);

    const ListLinkResultFuture = Future(ListLinkError!ListLinkResult);
    var links_future = ListLinkResultFuture{};

    var list_link_context = ListLinkContext{
        .socket = socket,
        .allocator = temp_arena,
        .userdata = &links_future,
        .callback = (struct {
            pub fn callback(userdata: ?*anyopaque, r: ListLinkError!ListLinkResult) void {
                var future = @as(*ListLinkResultFuture, @ptrCast(@alignCast(userdata.?)));
                future.setValue(r);
            }
        }).callback,
    };
    try listLinkAsync(&list_link_context, worker);
    var links_result = try links_future.getValue();

    var links_map = std.AutoHashMap(u32, Link).init(temp_arena);
    for (links_result.links) |link| {
        try links_map.put(link.interface_index, link);
    }

    const ListAddressResultFuture = Future(ListAddressError!ListAddressResult);
    var addresses_future = ListAddressResultFuture{};

    var list_address_context = ListAddressContext{
        .socket = socket,
        .allocator = temp_arena,
        .userdata = &addresses_future,
        .callback = (struct {
            pub fn callback(userdata: ?*anyopaque, r: ListAddressError!ListAddressResult) void {
                var future = @as(*ListAddressResultFuture, @ptrCast(@alignCast(userdata.?)));
                future.setValue(r);
            }
        }).callback,
    };
    try listAddressAsync(&list_address_context, worker);
    var address_result = try addresses_future.getValue();

    var address_list = std.ArrayList(std.net.Address).init(allocator);
    defer address_list.deinit();

    for (address_result.addresses) |nl_address| {
        const interface_address = nl_address.interface_address orelse continue;
        const associated_link = links_map.get(nl_address.interface_index) orelse continue;
        if (associated_link.device_type == netlink.ARPHRD.LOOPBACK) continue;

        const posix_address = @as(*const std.os.sockaddr, @ptrCast(&interface_address));
        const inet_address = std.net.Address.initPosix(posix_address);

        if (inet_address.any.family == std.os.AF.INET6 and (net.isSiteLocalIpv6(inet_address.in6) or net.isIpv4CompatibleIpv6(inet_address.in6) or net.isIpv4MappedIpv6(inet_address.in6))) continue;

        try address_list.append(std.net.Address.initPosix(posix_address));
    }

    return address_list.toOwnedSlice();
}

test {
    _ = netlink;
}
