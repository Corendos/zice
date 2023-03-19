// Copyright 2023 - Corentin Godeau and the zice contributors
// SPDX-License-Identifier: MIT

const std = @import("std");
const xev = @import("xev");

const zice = @import("../../main.zig");
const net = zice.net;
const linux = std.os.linux;

pub const Cache = @import("netlink/cache.zig").Cache;

pub const ARPHRD = struct {
    pub const NETROM = 0;
    pub const ETHER = 1;
    pub const EETHER = 2;
    pub const AX25 = 3;
    pub const PRONET = 4;
    pub const CHAOS = 5;
    pub const IEEE802 = 65;
    pub const ARCNET = 7;
    pub const APPLETLK = 8;
    pub const DLCI = 15;
    pub const ATM = 19;
    pub const METRICOM = 23;
    pub const IEEE1394 = 24;
    pub const EUI64 = 27;
    pub const INFINIBAND = 32;
    pub const SLIP = 256;
    pub const CSLIP = 257;
    pub const SLIP6 = 258;
    pub const CSLIP6 = 259;
    pub const RSRVD = 260;
    pub const ADAPT = 264;
    pub const ROSE = 270;
    pub const X25 = 271;
    pub const HWX25 = 272;
    pub const CAN = 280;
    pub const MCTP = 290;
    pub const PPP = 512;
    pub const CISCO = 513;
    pub const HDLC = CISCO;
    pub const LAPB = 516;
    pub const DDCMP = 517;
    pub const RAWHDLC = 518;
    pub const RAWIP = 519;
    pub const TUNNEL = 768;
    pub const TUNNEL6 = 769;
    pub const FRAD = 770;
    pub const SKIP = 771;
    pub const LOOPBACK = 772;
    pub const LOCALTLK = 773;
    pub const FDDI = 774;
    pub const BIF = 775;
    pub const SIT = 776;
    pub const IPDDP = 777;
    pub const IPGRE = 778;
    pub const PIMREG = 779;
    pub const HIPPI = 780;
    pub const ASH = 781;
    pub const ECONET = 782;
    pub const IRDA = 783;
    pub const FCPP = 784;
    pub const FCAL = 785;
    pub const FCPL = 786;
    pub const FCFABRIC = 787;
    pub const IEEE802_TR = 800;
    pub const IEEE80211 = 801;
    pub const IEEE80211_PRISM = 802;
    pub const IEEE80211_RADIOTAP = 803;
    pub const IEEE802154 = 804;
    pub const IEEE802154_MONITOR = 805;
    pub const PHONET = 820;
    pub const PHONET_PIPE = 821;
    pub const CAIF = 822;
    pub const IP6GRE = 823;
    pub const NETLINK = 824;
    pub const @"6LOWPAN" = 825;
    pub const VSOCKMON = 826;
};

pub const rta_align_to: u32 = 4;

pub inline fn rta_align(len: u32) u32 {
    return (len + rta_align_to - 1) & ~(rta_align_to - 1);
}

pub inline fn rta_length(len: u32) u32 {
    return rta_align(@sizeOf(rtattr) + len);
}

pub inline fn rta_space(len: u32) u32 {
    return rta_align(rta_length(len));
}

pub inline fn rta_data(rta: *const rtattr) []const u8 {
    const data = @ptrCast([*]const u8, rta)[0..rta.len];
    return data[rta_length(0)..];
}

pub inline fn rta_next(rta: *const rtattr, len: *u32) *const rtattr {
    const attribute_length = rta_align(rta.len);
    defer len.* -= attribute_length;

    const data = @ptrCast([*]const u8, rta)[0..len.*];
    return @ptrCast(*const rtattr, @alignCast(@alignOf(rtattr), data[attribute_length..].ptr));
}

pub inline fn rta_ok(rta: *const rtattr, len: u32) bool {
    return len >= @sizeOf(rtattr) and rta.len >= @sizeOf(rtattr) and rta.len <= len;
}

pub inline fn rta_payload(rta: *const rtattr, len: u32) u32 {
    return rta.len - rta_length(len);
}

// TODO(Corendos): Add tests

pub const AttributeIterator = struct {
    const Self = @This();
    const rtattr_alignment = @alignOf(rtattr);

    buffer: []align(rtattr_alignment) const u8,
    len: u32,
    current: *const rtattr,

    pub fn init(buffer: []align(rtattr_alignment) const u8) Self {
        const current = @ptrCast(*const rtattr, buffer);
        return Self{ .buffer = buffer, .len = @intCast(u32, buffer.len), .current = current };
    }

    pub fn next(self: *Self) ?*const rtattr {
        if (!rta_ok(self.current, self.len)) return null;
        defer self.current = rta_next(self.current, &self.len);
        return self.current;
    }
};

pub const nlmsg_align_to: u32 = 4;
pub const nlmsg_hdrlen: u32 = nlmsg_align(@as(u32, @sizeOf(linux.nlmsghdr)));

pub inline fn nlmsg_align(len: u32) u32 {
    return (len + nlmsg_align_to - 1) & ~(@as(u32, nlmsg_align_to - 1));
}

pub inline fn nlmsg_length(len: u32) u32 {
    return len + nlmsg_hdrlen;
}

pub inline fn nlmsg_space(len: u32) u32 {
    return nlmsg_align(nlmsg_length(len));
}

pub inline fn nlmsg_data(nlh: *const linux.nlmsghdr) []const u8 {
    const nlh_data = @ptrCast([*]const u8, nlh)[0..nlh.len];
    return nlh_data[nlmsg_hdrlen..];
}

pub inline fn nlmsg_next(nlh: *const linux.nlmsghdr, len: *u32) *const linux.nlmsghdr {
    const message_length = nlmsg_align(nlh.len);
    defer len.* -= message_length;

    const nlh_data = @ptrCast([*]const u8, nlh)[0..len.*];
    return @ptrCast(*const linux.nlmsghdr, @alignCast(@alignOf(linux.nlmsghdr), nlh_data[message_length..].ptr));
}

pub inline fn nlmsg_ok(nlh: *const linux.nlmsghdr, len: u32) bool {
    const header_size = @sizeOf(linux.nlmsghdr);
    return len >= header_size and nlh.len >= header_size and nlh.len <= len;
}

pub inline fn nlmsg_payload(nlh: *const linux.nlmsghdr, len: u32) u32 {
    return nlh.len - nlmsg_space(len);
}

test "HDRLEN value" {
    try std.testing.expectEqual(@as(u32, 16), nlmsg_hdrlen);
}

test "ALIGN" {
    try std.testing.expectEqual(@as(u32, 4), nlmsg_align(@as(u32, 3)));
}

test "LENGTH" {
    try std.testing.expectEqual(@as(u32, 19), nlmsg_length(@as(u32, 3)));
}

test "SPACE" {
    try std.testing.expectEqual(@as(u32, 20), nlmsg_space(@as(u32, 3)));
}

test "DATA" {
    var buffer align(@alignOf(linux.nlmsghdr)) = [_]u8{0xBA} ** nlmsg_length(3);
    const nlh = @ptrCast(*linux.nlmsghdr, &buffer);
    nlh.len = nlmsg_length(3);

    const data = nlmsg_data(nlh);

    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xBA, 0xBA, 0xBA }, data);
}

test "NEXT" {
    var buffer align(@alignOf(linux.nlmsghdr)) = [_]u8{0} ** (nlmsg_space(3) + nlmsg_space(0));
    const nlh1 = @ptrCast(*linux.nlmsghdr, &buffer);
    nlh1.len = nlmsg_length(3);
    nlh1.seq = 1;

    const nlh2 = @ptrCast(*linux.nlmsghdr, @alignCast(@alignOf(linux.nlmsghdr), buffer[nlmsg_space(3)..]));
    nlh2.len = nlmsg_length(3);
    nlh2.seq = 2;

    var len: u32 = buffer.len;

    const next_nlh = nlmsg_next(nlh1, &len);
    try std.testing.expectEqual(@as(u32, 2), next_nlh.seq);
}

pub const MessageIterator = struct {
    const Self = @This();
    const nlmsghdr_alignment = @alignOf(linux.nlmsghdr);

    buffer: []align(nlmsghdr_alignment) const u8,
    len: u32,
    current: *const linux.nlmsghdr,

    pub fn init(buffer: []align(nlmsghdr_alignment) const u8) Self {
        const current = @ptrCast(*const linux.nlmsghdr, buffer);
        return Self{ .buffer = buffer, .len = @intCast(u32, buffer.len), .current = current };
    }

    pub fn next(self: *Self) ?*const linux.nlmsghdr {
        if (!nlmsg_ok(self.current, self.len)) return null;
        defer self.current = nlmsg_next(self.current, &self.len);
        return self.current;
    }
};

pub const rtattr = extern struct {
    len: c_ushort,
    type: c_ushort,

    pub fn as(comptime T: type, value: rtattr) T {
        return @intToEnum(T, value.type);
    }
};

pub const IFA = enum(c_ushort) {
    IFA_UNSPEC,
    IFA_ADDRESS,
    IFA_LOCAL,
    IFA_LABEL,
    IFA_BROADCAST,
    IFA_ANYCAST,
    IFA_CACHEINFO,
    IFA_MULTICAST,
    IFA_FLAGS,
    IFA_RT_PRIORITY,
    IFA_TARGET_NETNSID,
};

pub const nlmsgerr = extern struct {
    @"error": i32,
    msg: linux.nlmsghdr,
};

pub const ifaddrmsg = extern struct {
    family: u8,
    prefixlen: u8,
    flags: u8,
    scope: u8,
    index: c_uint,
};

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

pub const MacAddressFormatter = std.fmt.Formatter(formatMacAddress);

fn formatFlags(value: anytype, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) @TypeOf(writer).Error!void {
    const type_info = @typeInfo(@TypeOf(value));
    const width = type_info.Int.bits;
    const flag_fmt = comptime std.fmt.comptimePrint("{{b:0>{}}}", .{width});
    try writer.print(flag_fmt, .{value});
    _ = options;
    _ = fmt;
}

pub fn FlagsFormatter(comptime T: type) type {
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

pub const Link = struct {
    device_type: u16 = undefined,
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

pub const ListLinkError = error{ Unexpected, OutOfMemory };

pub const ListLinkResult = struct {
    links: []Link,
    storage: std.heap.ArenaAllocator,
};

pub const ListLinkContext = struct {
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

pub fn listLinkAsyncWriteCallback(
    userdata: ?*anyopaque,
    loop: *xev.Loop,
    completion: *xev.Completion,
    result: xev.Result,
) xev.CallbackAction {
    const context = @ptrCast(*ListLinkContext, @alignCast(@alignOf(ListLinkContext), userdata.?));
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

fn processLinkMessage(message_it: *MessageIterator, context: *ListLinkContext) !bool {
    var done = false;
    while (message_it.next()) |message| {
        if (message.flags & linux.NLM_F_MULTI == 0) {
            done = true;
        }

        const message_payload = nlmsg_data(message);
        switch (message.type) {
            linux.NetlinkMessageType.DONE => {
                done = true;
            },
            linux.NetlinkMessageType.RTM_NEWLINK => {
                const link_info = @ptrCast(*const linux.ifinfomsg, @alignCast(@alignOf(linux.ifinfomsg), message_payload.ptr));
                var link = Link{
                    .device_type = @intCast(u16, link_info.type),
                    .interface_index = @bitCast(u32, link_info.index),
                    .device_flags = @bitCast(u32, link_info.flags),
                };

                var attribute_it = AttributeIterator.init(@alignCast(@alignOf(rtattr), message_payload[@sizeOf(linux.ifinfomsg)..]));
                while (attribute_it.next()) |attribute| {
                    const attribute_data = rta_data(attribute);
                    switch (rtattr.as(linux.IFLA, attribute.*)) {
                        linux.IFLA.IFNAME => {
                            const name = @ptrCast([:0]const u8, attribute_data);
                            link.name = try context.result_storage.?.allocator().dupe(u8, name);
                        },
                        linux.IFLA.ADDRESS => {
                            link.address = attribute_data[0..6].*;
                        },
                        linux.IFLA.BROADCAST => {
                            link.broadcast = attribute_data[0..6].*;
                        },
                        linux.IFLA.MTU => {
                            link.mtu = @intCast(u32, @ptrCast(*const c_uint, @alignCast(4, attribute_data.ptr)).*);
                        },
                        linux.IFLA.LINK => {
                            link.link_type = @bitCast(u32, @ptrCast(*const c_int, @alignCast(4, attribute_data.ptr)).*);
                        },
                        linux.IFLA.QDISC => {
                            const qdisc = @ptrCast([:0]const u8, attribute_data);
                            link.queueing_discipline = try context.result_storage.?.allocator().dupe(u8, qdisc);
                        },
                        else => {},
                    }
                }

                try context.result_links_list.append(context.allocator, link);
            },
            linux.NetlinkMessageType.ERROR => {
                const nl_error = @ptrCast(*const nlmsgerr, @alignCast(@alignOf(nlmsgerr), message_payload.ptr));
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
    const context = @ptrCast(*ListLinkContext, @alignCast(@alignOf(ListLinkContext), userdata.?));
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

    var message_it = MessageIterator.init(@alignCast(@alignOf(linux.nlmsghdr), response));
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

pub fn listLinkAsync(context: *ListLinkContext, worker: *zice.Worker) !void {
    const raw_request = blk: {
        var stream = std.io.fixedBufferStream(&context.buffer);
        var writer = stream.writer();

        const request_header = linux.nlmsghdr{
            .len = nlmsg_length(@sizeOf(linux.ifinfomsg)),
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

pub const Address = struct {
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
            const address = std.net.Address.initPosix(@ptrCast(*const linux.sockaddr, &interface_address));
            try writer.print(", .interface_address = {}", .{address});
        }
        if (value.local_address) |local_address| {
            const address = std.net.Address.initPosix(@ptrCast(*const linux.sockaddr, &local_address));
            try writer.print(", .local_address = {}", .{address});
        }
        if (value.label) |label| {
            try writer.print(", .label = {s}", .{label});
        }
        if (value.broadcast_address) |broadcast_address| {
            const address = std.net.Address.initPosix(@ptrCast(*const linux.sockaddr, &broadcast_address));
            try writer.print(", .broadcast_address = {}", .{address});
        }
        if (value.anycast_address) |anycast_address| {
            const address = std.net.Address.initPosix(@ptrCast(*const linux.sockaddr, &anycast_address));
            try writer.print(", .anycast_address = {}", .{address});
        }
        try writer.writeAll(" }");
    }
};

pub const ListAddressError = error{ Unexpected, OutOfMemory };

pub const ListAddressResult = struct {
    addresses: []Address,
    storage: std.heap.ArenaAllocator,
};

pub const ListAddressContext = struct {
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

pub fn listAddressAsyncWriteCallback(
    userdata: ?*anyopaque,
    loop: *xev.Loop,
    completion: *xev.Completion,
    result: xev.Result,
) xev.CallbackAction {
    const context = @ptrCast(*ListAddressContext, @alignCast(@alignOf(ListAddressContext), userdata.?));
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
                .addr = @bitCast(u32, raw[0..4].*),
            };
            break :blk @ptrCast(*const linux.sockaddr.storage, &a).*;
        },
        linux.AF.INET6 => blk: {
            const a align(8) = linux.sockaddr.in6{
                .port = 0,
                .flowinfo = 0,
                .addr = raw[0..16].*,
                .scope_id = index,
            };
            break :blk @ptrCast(*const linux.sockaddr.storage, &a).*;
        },
        else => @panic("Unsupported family"),
    };
}

fn processAddressMessage(message_it: *MessageIterator, context: *ListAddressContext) !bool {
    var done = false;
    while (message_it.next()) |message| {
        if (message.flags & linux.NLM_F_MULTI == 0) {
            done = true;
        }

        const message_payload = nlmsg_data(message);
        switch (message.type) {
            linux.NetlinkMessageType.DONE => {
                done = true;
            },
            linux.NetlinkMessageType.RTM_NEWADDR => {
                const addr_info = @ptrCast(*const ifaddrmsg, @alignCast(@alignOf(ifaddrmsg), message_payload.ptr));

                var address = Address{
                    .family = addr_info.family,
                    .prefix_length = addr_info.prefixlen,
                    .flags = addr_info.flags,
                    .scope = addr_info.scope,
                    .interface_index = @intCast(u32, addr_info.index),
                };

                var attribute_it = AttributeIterator.init(@alignCast(@alignOf(rtattr), message_payload[@sizeOf(ifaddrmsg)..]));
                while (attribute_it.next()) |attribute| {
                    const attribute_data = rta_data(attribute);
                    switch (rtattr.as(IFA, attribute.*)) {
                        IFA.IFA_ADDRESS => {
                            address.interface_address = toSockaddr(address.family, address.interface_index, attribute_data);
                        },
                        IFA.IFA_LOCAL => {
                            address.local_address = toSockaddr(address.family, address.interface_index, attribute_data);
                        },
                        IFA.IFA_BROADCAST => {
                            address.broadcast_address = toSockaddr(address.family, address.interface_index, attribute_data);
                        },
                        IFA.IFA_ANYCAST => {
                            address.anycast_address = toSockaddr(address.family, address.interface_index, attribute_data);
                        },
                        IFA.IFA_LABEL => {
                            const label = @ptrCast([:0]const u8, attribute_data);
                            address.label = try context.result_storage.?.allocator().dupe(u8, label);
                        },
                        else => {},
                    }
                }

                try context.result_addresses_list.append(context.allocator, address);
            },
            linux.NetlinkMessageType.ERROR => {
                const nl_error = @ptrCast(*const nlmsgerr, @alignCast(@alignOf(nlmsgerr), message_payload.ptr));
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
    const context = @ptrCast(*ListAddressContext, @alignCast(@alignOf(ListAddressContext), userdata.?));
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

    var message_it = MessageIterator.init(@alignCast(@alignOf(linux.nlmsghdr), response));
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

pub fn listAddressAsync(context: *ListAddressContext, worker: *zice.Worker) !void {
    const raw_request = blk: {
        var stream = std.io.fixedBufferStream(&context.buffer);
        var writer = stream.writer();

        const request_header = linux.nlmsghdr{
            .len = nlmsg_length(@sizeOf(ifaddrmsg)),
            .type = linux.NetlinkMessageType.RTM_GETADDR,
            .flags = linux.NLM_F_DUMP | linux.NLM_F_REQUEST,
            .seq = 1,
            .pid = 0,
        };

        const request_payload = ifaddrmsg{
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
