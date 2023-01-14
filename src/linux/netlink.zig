// Copyright 2023 - Corentin Godeau and the zice contributors
// SPDX-License-Identifier: MIT

const std = @import("std");
const net = @import("../net.zig");
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

pub const Link = struct {
    type: u32,
    interface_index: u32,
    address: [6]u8 = [_]u8{0} ** 6,
    name: []const u8 = &.{},

    pub fn deinit(self: Link, allocator: std.mem.Allocator) void {
        allocator.free(self.name);
    }

    pub fn format(value: Link, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
        _ = options;
        _ = fmt;
        try writer.print("Link{{ .type = {}, .interface_index = {}, .address: {x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}, .name: \"{s}\"}}", .{
            value.type,
            value.interface_index,
            value.address[0],
            value.address[1],
            value.address[2],
            value.address[3],
            value.address[4],
            value.address[5],
            value.name,
        });
    }
};

pub const Address = struct {
    family: u8,
    interface_index: u32,
    address: net.Address,

    pub fn deinit(self: Address, allocator: std.mem.Allocator) void {
        _ = allocator;
        _ = self;
    }

    pub fn format(value: Address, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
        _ = options;
        _ = fmt;
        try writer.print("Address{{ .family = {}, .interface_index = {}, .address: {}}}", .{
            value.family,
            value.interface_index,
            value.address,
        });
    }
};

pub fn createSocket() !i32 {
    const result = linux.socket(linux.AF.NETLINK, linux.SOCK.RAW, linux.NETLINK.ROUTE);
    if (linux.getErrno(result) != linux.E.SUCCESS) return error.CreationFailed;
    return @intCast(i32, result);
}

pub fn closeSocket(socket: i32) void {
    _ = linux.close(socket);
}

pub fn bindSocket(socket: i32, port_id: u32, groups: u32) !void {
    const address = linux.sockaddr.nl{
        .pid = port_id,
        .groups = groups,
    };

    const result = linux.bind(socket, @ptrCast(*const linux.sockaddr, &address), @sizeOf(linux.sockaddr.nl));
    if (linux.getErrno(result) != linux.E.SUCCESS) return error.BindFailed;
}

pub fn write(socket: i32, buffer: []const u8) !void {
    const result = linux.write(socket, buffer.ptr, buffer.len);
    if (linux.getErrno(result) != linux.E.SUCCESS) return error.WriteError;
}

pub fn read(socket: i32, buffer: []u8) ![]const u8 {
    const result = linux.read(socket, buffer.ptr, buffer.len);
    if (linux.getErrno(result) != linux.E.SUCCESS) return error.ReadError;
    return buffer[0..@intCast(usize, result)];
}
