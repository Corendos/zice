// Copyright 2023 - Corentin Godeau and the zice contributors
// SPDX-License-Identifier: MIT

const std = @import("std");
const xev = @import("xev");

const zice = @import("../../main.zig");
const net = zice.net;
const linux = std.os.linux;

pub const Cache = @import("netlink/cache.zig").Cache;

// From rtnetlink.h
pub const RTMGRP = struct {
    pub const LINK = 1;
    pub const NOTIFY = 2;
    pub const NEIGH = 4;
    pub const TC = 8;
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

// TODO(Corendos): make that an enum ?
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
    const attr = @ptrCast(*rtattr, &buffer);
    attr.len = rta_length(3);

    const data = rta_data(attr);

    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xBA, 0xBA, 0xBA }, data);
}

test "rta_next and rta_ok" {
    const rtattr_align = @alignOf(rtattr);
    var buffer = try std.testing.allocator.alignedAlloc(u8, rtattr_align, nlmsg_space(3) + nlmsg_space(0));
    defer std.testing.allocator.free(buffer);

    const attr1 = @ptrCast(*rtattr, buffer);
    attr1.len = rta_length(3);
    attr1.type = 1;

    const attr2 = @ptrCast(*rtattr, @alignCast(rtattr_align, buffer[rta_space(3)..]));
    attr2.len = rta_length(0);
    attr2.type = 2;

    var len: u32 = @intCast(u32, buffer.len);
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
        return @intToEnum(T, self.type);
    }
};

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

    const attr1 = @ptrCast(*rtattr, buffer);
    attr1.len = rta_length(3);
    attr1.type = 1;

    const attr2 = @ptrCast(*rtattr, @alignCast(rtattr_align, buffer[rta_space(3)..]));
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
    const nlh = @ptrCast(*linux.nlmsghdr, &buffer);
    nlh.len = nlmsg_length(3);

    const data = nlmsg_data(nlh);

    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xBA, 0xBA, 0xBA }, data);
}

test "nlmsg_next and nlmsg_ok" {
    const nlmsghdr_align = @alignOf(linux.nlmsghdr);
    var buffer = try std.testing.allocator.alignedAlloc(u8, nlmsghdr_align, nlmsg_space(3) + nlmsg_space(0));
    defer std.testing.allocator.free(buffer);
    @memset(buffer, 0xBA);

    const nlh1 = @ptrCast(*linux.nlmsghdr, buffer);
    nlh1.len = nlmsg_length(3);
    nlh1.seq = 1;

    const nlh2 = @ptrCast(*linux.nlmsghdr, @alignCast(nlmsghdr_align, buffer[nlmsg_space(3)..]));
    nlh2.len = nlmsg_length(0);
    nlh2.seq = 2;

    var len: u32 = @intCast(u32, buffer.len);
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
        const current = @ptrCast(*const linux.nlmsghdr, buffer);
        return Self{ .buffer = buffer, .len = @intCast(u32, buffer.len), .current = current };
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

    const nlh1 = @ptrCast(*linux.nlmsghdr, buffer);
    nlh1.len = nlmsg_length(3);
    nlh1.seq = 1;

    const nlh2 = @ptrCast(*linux.nlmsghdr, @alignCast(nlmsghdr_align, buffer[nlmsg_space(3)..]));
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
            .IFNAME => .{ .IFNAME = @ptrCast([:0]const u8, attribute.data) },
            .MTU => .{ .MTU = @intCast(u32, std.mem.bytesToValue(c_uint, attribute.data[0..@sizeOf(c_uint)])) },
            .LINK => .{ .LINK = @intCast(u32, std.mem.bytesToValue(c_int, attribute.data[0..@sizeOf(c_int)])) },
            .QDISC => .{ .QDISC = @ptrCast([:0]const u8, attribute.data) },
            .STATS => .{ .STATS = std.mem.bytesToValue(linux.rtnl_link_stats, attribute.data[0..@sizeOf(linux.rtnl_link_stats)]) },
            else => .{ .UNSPEC = attribute.data },
        };
    }
};

test "IflaAttribute: unspec" {
    var raw_attribute = Attribute{
        .len = 7,
        .type = @enumToInt(std.os.linux.IFLA.UNSPEC),
        .data = &.{ 0x01, 0x02, 0x03 },
    };

    const attribute = IflaAttribute.from(raw_attribute);
    try std.testing.expectEqual(linux.IFLA.UNSPEC, attribute);
    try std.testing.expectEqualSlices(u8, raw_attribute.data, attribute.UNSPEC);
}

test "IflaAttribute: address" {
    var raw_attribute = Attribute{
        .len = 10,
        .type = @enumToInt(std.os.linux.IFLA.ADDRESS),
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
        .type = @enumToInt(std.os.linux.IFLA.IFNAME),
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
