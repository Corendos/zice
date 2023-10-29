// Copyright 2023 - Corentin Godeau and the zice contributors
// SPDX-License-Identifier: MIT

const std = @import("std");

const zice = @import("../../main.zig");
const net = zice.net;
const xev = zice.xev;
const linux = std.os.linux;

// From rtnetlink.h
pub const RTMGRP = struct {
    pub const LINK = 0x01;
    pub const NOTIFY = 0x02;
    pub const NEIGH = 0x04;
    pub const TC = 0x08;
    pub const IPV4_IFADDR = 0x10;
    pub const IPV4_MROUTE = 0x20;
    pub const IPV4_ROUTE = 0x40;
    pub const IPV4_RULE = 0x80;
    pub const IPV6_IFADDR = 0x100;
    pub const IPV6_MROUTE = 0x200;
    pub const IPV6_ROUTE = 0x400;
    pub const IPV6_IFINFO = 0x800;
    pub const DECnet_IFADDR = 0x1000;
    pub const DECnet_ROUTE = 0x4000;
    pub const IPV6_PREFIX = 0x20000;
};

pub const ARPHRD = enum(c_ushort) {
    NETROM = 0,
    ETHER = 1,
    EETHER = 2,
    AX25 = 3,
    PRONET = 4,
    CHAOS = 5,
    IEEE802 = 65,
    ARCNET = 7,
    APPLETLK = 8,
    DLCI = 15,
    ATM = 19,
    METRICOM = 23,
    IEEE1394 = 24,
    EUI64 = 27,
    INFINIBAND = 32,
    SLIP = 256,
    CSLIP = 257,
    SLIP6 = 258,
    CSLIP6 = 259,
    RSRVD = 260,
    ADAPT = 264,
    ROSE = 270,
    X25 = 271,
    HWX25 = 272,
    CAN = 280,
    MCTP = 290,
    PPP = 512,
    CISCO = 513,
    LAPB = 516,
    DDCMP = 517,
    RAWHDLC = 518,
    RAWIP = 519,
    TUNNEL = 768,
    TUNNEL6 = 769,
    FRAD = 770,
    SKIP = 771,
    LOOPBACK = 772,
    LOCALTLK = 773,
    FDDI = 774,
    BIF = 775,
    SIT = 776,
    IPDDP = 777,
    IPGRE = 778,
    PIMREG = 779,
    HIPPI = 780,
    ASH = 781,
    ECONET = 782,
    IRDA = 783,
    FCPP = 784,
    FCAL = 785,
    FCPL = 786,
    FCFABRIC = 787,
    IEEE802_TR = 800,
    IEEE80211 = 801,
    IEEE80211_PRISM = 802,
    IEEE80211_RADIOTAP = 803,
    IEEE802154 = 804,
    IEEE802154_MONITOR = 805,
    PHONET = 820,
    PHONET_PIPE = 821,
    CAIF = 822,
    IP6GRE = 823,
    NETLINK = 824,
    @"6LOWPAN" = 825,
    VSOCKMON = 826,

    pub const HDLC = .CISCO;
};

pub const rtattr = extern struct {
    len: c_ushort,
    type: c_ushort,
};

/// rtattr handling convenience
pub const rta_align_to: u32 = 4;

pub inline fn rta_align(len: u32) u32 {
    return (len + rta_align_to - 1) & ~(rta_align_to - 1);
}

pub inline fn rta_length(len: u32) u32 {
    return rta_align(@sizeOf(rtattr)) + len;
}

pub inline fn rta_space(len: u32) u32 {
    return rta_align(rta_length(len));
}

pub inline fn rta_data(rta: *const rtattr) []const u8 {
    const data = @as([*]const u8, @ptrCast(rta))[0..rta.len];
    return data[rta_length(0)..];
}

pub inline fn rta_next(rta: *const rtattr, len: *u32) *const rtattr {
    const attribute_length = rta_align(rta.len);
    defer len.* -= attribute_length;

    const data = @as([*]const u8, @ptrCast(rta))[0..len.*];
    return @as(*const rtattr, @ptrCast(@alignCast(data[attribute_length..].ptr)));
}

pub inline fn rta_ok(rta: *const rtattr, len: u32) bool {
    return len >= @sizeOf(rtattr) and rta.len >= @sizeOf(rtattr) and rta.len <= len;
}

pub inline fn rta_payload(rta: *const rtattr, len: u32) u32 {
    return rta.len - rta_length(len);
}

test "rta_align" {
    try std.testing.expectEqual(@as(u32, 4), rta_align(3));
    try std.testing.expectEqual(@as(u32, 4), rta_align(4));
}

test "rta_length" {
    try std.testing.expectEqual(@as(u32, 7), rta_length(3));
    try std.testing.expectEqual(@as(u32, 8), rta_length(4));
}

test "rta_space" {
    try std.testing.expectEqual(@as(u32, 8), rta_space(3));
    try std.testing.expectEqual(@as(u32, 8), rta_space(4));
}

test "rta_data" {
    var buffer align(@alignOf(rtattr)) = [_]u8{0xBA} ** rta_space(3);
    const attr = @as(*rtattr, @ptrCast(&buffer));
    attr.len = rta_length(3);

    const data = rta_data(attr);

    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xBA, 0xBA, 0xBA }, data);
}

test "rta_next and rta_ok" {
    const rtattr_align = @alignOf(rtattr);
    var buffer = try std.testing.allocator.alignedAlloc(u8, rtattr_align, nlmsg_space(3) + nlmsg_space(0));
    defer std.testing.allocator.free(buffer);

    const attr1 = @as(*rtattr, @ptrCast(buffer));
    attr1.len = rta_length(3);
    attr1.type = 1;

    const attr2 = @as(*rtattr, @ptrCast(@alignCast(buffer[rta_space(3)..])));
    attr2.len = rta_length(0);
    attr2.type = 2;

    var len: u32 = @as(u32, @intCast(buffer.len));
    const second_attr = rta_next(attr1, &len);
    try std.testing.expect(rta_ok(second_attr, len));
    try std.testing.expectEqual(@as(u32, 2), second_attr.type);

    const next_attr = rta_next(second_attr, &len);
    try std.testing.expect(!rta_ok(next_attr, len));
}

pub const Attribute = struct {
    len: u16,
    type: u16,
    data: []const u8,

    pub inline fn as(self: Attribute, comptime T: type) T {
        return @as(T, @enumFromInt(self.type));
    }
};

pub const AttributeIterator = struct {
    const Self = @This();
    const rtattr_alignment = @alignOf(rtattr);

    buffer: []align(rtattr_alignment) const u8,
    len: u32,
    current: *const rtattr,

    pub fn init(buffer: []align(rtattr_alignment) const u8) Self {
        const current = @as(*const rtattr, @ptrCast(buffer));
        return Self{ .buffer = buffer, .len = @as(u32, @intCast(buffer.len)), .current = current };
    }

    pub fn next(self: *Self) ?Attribute {
        if (!rta_ok(self.current, self.len)) return null;
        defer self.current = rta_next(self.current, &self.len);
        return Attribute{
            .len = self.current.len,
            .type = self.current.type,
            .data = rta_data(self.current),
        };
    }
};

test "AttributeIterator" {
    const rtattr_align = @alignOf(rtattr);
    var buffer = try std.testing.allocator.alignedAlloc(u8, rtattr_align, nlmsg_space(3) + nlmsg_space(0));
    defer std.testing.allocator.free(buffer);
    @memset(buffer, 0xBA);

    const attr1 = @as(*rtattr, @ptrCast(buffer));
    attr1.len = rta_length(3);
    attr1.type = 1;

    const attr2 = @as(*rtattr, @ptrCast(@alignCast(buffer[rta_space(3)..])));
    attr2.len = rta_length(0);
    attr2.type = 2;

    var it = AttributeIterator.init(buffer);
    var next = it.next() orelse unreachable;
    try std.testing.expectEqual(rta_length(3), next.len);
    try std.testing.expectEqual(@as(u16, 1), next.type);
    try std.testing.expectEqualSlices(u8, &.{ 0xBA, 0xBA, 0xBA }, next.data);

    next = it.next() orelse unreachable;
    try std.testing.expectEqual(rta_length(0), next.len);
    try std.testing.expectEqual(@as(u16, 2), next.type);
    try std.testing.expectEqualSlices(u8, &.{}, next.data);
}

test "AttributeIterator empty" {
    var buffer: []align(@alignOf(rtattr)) u8 = &.{};
    var it = AttributeIterator.init(buffer);
    try std.testing.expect(it.next() == null);
}

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
    const nlh_data = @as([*]const u8, @ptrCast(nlh))[0..nlh.len];
    return nlh_data[nlmsg_hdrlen..];
}

pub inline fn nlmsg_next(nlh: *const linux.nlmsghdr, len: *u32) *const linux.nlmsghdr {
    const message_length = nlmsg_align(nlh.len);
    defer len.* -= message_length;

    const nlh_data = @as([*]const u8, @ptrCast(nlh))[0..len.*];
    return @as(*const linux.nlmsghdr, @ptrCast(@alignCast(nlh_data[message_length..].ptr)));
}

pub inline fn nlmsg_ok(nlh: *const linux.nlmsghdr, len: u32) bool {
    const header_size = @sizeOf(linux.nlmsghdr);
    return len >= header_size and nlh.len >= header_size and nlh.len <= len;
}

pub inline fn nlmsg_payload(nlh: *const linux.nlmsghdr, len: u32) u32 {
    return nlh.len - nlmsg_space(len);
}

test "nlmsg_hdr" {
    try std.testing.expectEqual(@as(u32, 16), nlmsg_hdrlen);
}

test "nlmsg_align" {
    try std.testing.expectEqual(@as(u32, 4), nlmsg_align(@as(u32, 3)));
}

test "nlmsg_length" {
    try std.testing.expectEqual(@as(u32, 19), nlmsg_length(@as(u32, 3)));
}

test "nlmsg_space" {
    try std.testing.expectEqual(@as(u32, 20), nlmsg_space(@as(u32, 3)));
}

test "nlmsg_data" {
    var buffer align(@alignOf(linux.nlmsghdr)) = [_]u8{0xBA} ** nlmsg_length(3);
    const nlh = @as(*linux.nlmsghdr, @ptrCast(&buffer));
    nlh.len = nlmsg_length(3);

    const data = nlmsg_data(nlh);

    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xBA, 0xBA, 0xBA }, data);
}

test "nlmsg_next and nlmsg_ok" {
    const nlmsghdr_align = @alignOf(linux.nlmsghdr);
    var buffer = try std.testing.allocator.alignedAlloc(u8, nlmsghdr_align, nlmsg_space(3) + nlmsg_space(0));
    defer std.testing.allocator.free(buffer);
    @memset(buffer, 0xBA);

    const nlh1 = @as(*linux.nlmsghdr, @ptrCast(buffer));
    nlh1.len = nlmsg_length(3);
    nlh1.seq = 1;

    const nlh2 = @as(*linux.nlmsghdr, @ptrCast(@alignCast(buffer[nlmsg_space(3)..])));
    nlh2.len = nlmsg_length(0);
    nlh2.seq = 2;

    var len: u32 = @as(u32, @intCast(buffer.len));
    const second_nlh = nlmsg_next(nlh1, &len);
    try std.testing.expect(nlmsg_ok(second_nlh, len));
    try std.testing.expectEqual(@as(u32, 2), second_nlh.seq);

    const next = nlmsg_next(second_nlh, &len);
    try std.testing.expect(!nlmsg_ok(next, len));
}

pub const Message = struct {
    len: u32,
    type: std.os.linux.NetlinkMessageType,
    flags: u16,
    sequence: u32,
    pid: u32,
    data: []const u8,
};

pub const MessageIterator = struct {
    const Self = @This();
    const nlmsghdr_alignment = @alignOf(linux.nlmsghdr);

    buffer: []align(nlmsghdr_alignment) const u8,
    len: u32,
    current: *const linux.nlmsghdr,

    pub fn init(buffer: []align(nlmsghdr_alignment) const u8) Self {
        const current = @as(*const linux.nlmsghdr, @ptrCast(buffer));
        return Self{ .buffer = buffer, .len = @as(u32, @intCast(buffer.len)), .current = current };
    }

    pub fn next(self: *Self) ?Message {
        if (!nlmsg_ok(self.current, self.len)) return null;
        defer self.current = nlmsg_next(self.current, &self.len);
        return Message{
            .len = self.current.len,
            .type = self.current.type,
            .flags = self.current.flags,
            .sequence = self.current.seq,
            .pid = self.current.pid,
            .data = nlmsg_data(self.current),
        };
    }
};

test "MessageIterator" {
    const nlmsghdr_align = @alignOf(linux.nlmsghdr);
    var buffer = try std.testing.allocator.alignedAlloc(u8, nlmsghdr_align, nlmsg_space(3) + nlmsg_space(0));
    defer std.testing.allocator.free(buffer);
    @memset(buffer, 0xBA);

    const nlh1 = @as(*linux.nlmsghdr, @ptrCast(buffer));
    nlh1.len = nlmsg_length(3);
    nlh1.seq = 1;

    const nlh2 = @as(*linux.nlmsghdr, @ptrCast(@alignCast(buffer[nlmsg_space(3)..])));
    nlh2.len = nlmsg_length(0);
    nlh2.seq = 2;

    var it = MessageIterator.init(buffer);

    var next = it.next() orelse unreachable;
    try std.testing.expectEqual(@as(u32, nlmsg_length(3)), next.len);
    try std.testing.expectEqual(@as(u32, 1), next.sequence);

    next = it.next() orelse unreachable;
    try std.testing.expectEqual(@as(u32, nlmsg_length(0)), next.len);
    try std.testing.expectEqual(@as(u32, 2), next.sequence);
}

test "MessageIterator empty" {
    var buffer: []align(@alignOf(linux.nlmsghdr)) u8 = &.{};
    var it = MessageIterator.init(buffer);
    try std.testing.expect(it.next() == null);
}

pub const IflaAttribute = union(linux.IFLA) {
    UNSPEC: []const u8,
    ADDRESS: [6]u8,
    BROADCAST: [6]u8,
    IFNAME: [:0]const u8,
    MTU: u32,
    LINK: u32,
    QDISC: [:0]const u8,
    STATS: linux.rtnl_link_stats,

    // TODO(Corendos): Switch to correct type for remaining values.
    COST: void,
    PRIORITY: void,
    MASTER: void,

    /// Wireless Extension event
    WIRELESS: void,

    /// Protocol specific information for a link
    PROTINFO: void,

    TXQLEN: void,
    MAP: void,
    WEIGHT: void,
    OPERSTATE: void,
    LINKMODE: void,
    LINKINFO: void,
    NET_NS_PID: void,
    IFALIAS: void,

    /// Number of VFs if device is SR-IOV PF
    NUM_VF: void,

    VFINFO_LIST: void,
    STATS64: void,
    VF_PORTS: void,
    PORT_SELF: void,
    AF_SPEC: void,

    /// Group the device belongs to
    GROUP: void,

    NET_NS_FD: void,

    /// Extended info mask, VFs, etc
    EXT_MASK: void,

    /// Promiscuity count: > 0 means acts PROMISC
    PROMISCUITY: void,

    NUM_TX_QUEUES: void,
    NUM_RX_QUEUES: void,
    CARRIER: void,
    PHYS_PORT_ID: void,
    CARRIER_CHANGES: void,
    PHYS_SWITCH_ID: void,
    LINK_NETNSID: void,
    PHYS_PORT_NAME: void,
    PROTO_DOWN: void,
    GSO_MAX_SEGS: void,
    GSO_MAX_SIZE: void,
    PAD: void,
    XDP: void,
    EVENT: void,

    NEW_NETNSID: void,
    IF_NETNSID: void,

    CARRIER_UP_COUNT: void,
    CARRIER_DOWN_COUNT: void,
    NEW_IFINDEX: void,
    MIN_MTU: void,
    MAX_MTU: void,

    pub fn from(attribute: Attribute) IflaAttribute {
        return switch (attribute.as(std.os.linux.IFLA)) {
            .ADDRESS => .{ .ADDRESS = attribute.data[0..6].* },
            .BROADCAST => .{ .BROADCAST = attribute.data[0..6].* },
            .IFNAME => .{ .IFNAME = @as([:0]const u8, @ptrCast(attribute.data)) },
            .MTU => .{ .MTU = @as(u32, @intCast(std.mem.bytesToValue(c_uint, attribute.data[0..@sizeOf(c_uint)]))) },
            .LINK => .{ .LINK = @as(u32, @intCast(std.mem.bytesToValue(c_int, attribute.data[0..@sizeOf(c_int)]))) },
            .QDISC => .{ .QDISC = @as([:0]const u8, @ptrCast(attribute.data)) },
            .STATS => .{ .STATS = std.mem.bytesToValue(linux.rtnl_link_stats, attribute.data[0..@sizeOf(linux.rtnl_link_stats)]) },
            else => .{ .UNSPEC = attribute.data },
        };
    }
};

test "IflaAttribute: unspec" {
    var raw_attribute = Attribute{
        .len = 7,
        .type = @intFromEnum(std.os.linux.IFLA.UNSPEC),
        .data = &.{ 0x01, 0x02, 0x03 },
    };

    const attribute = IflaAttribute.from(raw_attribute);
    try std.testing.expectEqual(linux.IFLA.UNSPEC, attribute);
    try std.testing.expectEqualSlices(u8, raw_attribute.data, attribute.UNSPEC);
}

test "IflaAttribute: address" {
    var raw_attribute = Attribute{
        .len = 10,
        .type = @intFromEnum(std.os.linux.IFLA.ADDRESS),
        .data = &.{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 },
    };

    const attribute = IflaAttribute.from(raw_attribute);
    try std.testing.expectEqual(linux.IFLA.ADDRESS, attribute);
    try std.testing.expectEqual(raw_attribute.data[0..6].*, attribute.ADDRESS);
}

test "IflaAttribute: interface_name" {
    const interface_name: [:0]const u8 = "eth0";
    var raw_attribute = Attribute{
        .len = rta_length(interface_name.len),
        .type = @intFromEnum(std.os.linux.IFLA.IFNAME),
        .data = interface_name,
    };

    const attribute = IflaAttribute.from(raw_attribute);
    try std.testing.expectEqual(linux.IFLA.IFNAME, attribute);
    try std.testing.expectEqualStrings("eth0", attribute.IFNAME);
}

pub const ifaddrmsg = extern struct {
    family: u8,
    prefixlen: u8,
    flags: u8,
    scope: u8,
    index: c_uint,
};

pub const IFA = enum(c_ushort) {
    UNSPEC,
    ADDRESS,
    LOCAL,
    LABEL,
    BROADCAST,
    ANYCAST,
    CACHEINFO,
    MULTICAST,
    FLAGS,
    RT_PRIORITY,
    TARGET_NETNSID,
};

pub const IfaAttribute = union(IFA) {
    UNSPEC: []const u8,
    ADDRESS: []const u8,
    LOCAL: []const u8,
    LABEL: [:0]const u8,
    BROADCAST: []const u8,
    ANYCAST: []const u8,
    CACHEINFO,
    MULTICAST,
    FLAGS,
    RT_PRIORITY,
    TARGET_NETNSID,

    pub fn from(attribute: Attribute) IfaAttribute {
        return switch (attribute.as(IFA)) {
            .ADDRESS => .{ .ADDRESS = attribute.data },
            .LOCAL => .{ .LOCAL = attribute.data },
            .LABEL => .{ .LABEL = @as([:0]const u8, @ptrCast(attribute.data)) },
            .BROADCAST => .{ .BROADCAST = attribute.data },
            .ANYCAST => .{ .ANYCAST = attribute.data },
            else => .{ .UNSPEC = attribute.data },
        };
    }
};

pub const nlmsgerr = extern struct {
    @"error": i32,
    msg: linux.nlmsghdr,
};
