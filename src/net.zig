// Copyright 2023 - Corentin Godeau and the zice contributors
// SPDX-License-Identifier: MIT

const std = @import("std");
const builtin = @import("builtin");

pub usingnamespace switch (builtin.os.tag) {
    .linux => @import("net/linux.zig"),
    else => @compileError("\"" ++ @tagName(builtin.os.tag) ++ "\" platform is not supported yet."),
};

pub inline fn isLinkLocalIpv6(address: std.net.Ip6Address) bool {
    const addr = std.mem.readIntSliceBig(u128, &address.sa.addr);
    return (addr & 0xFFFF_FFFF_FFFF_FFFF_0000_0000_0000_0000) == 0xfe80_0000_0000_0000_0000_0000_0000_0000;
}

pub inline fn isSiteLocalIpv6(address: std.net.Ip6Address) bool {
    const addr = std.mem.readIntSliceBig(u128, &address.sa.addr);
    return (addr & 0xFFFF_FFFF_FFFF_FFFF_0000_0000_0000_0000) == 0xfec0_0000_0000_0000_0000_0000_0000_0000;
}

pub inline fn isIpv4CompatibleIpv6(address: std.net.Ip6Address) bool {
    const addr = std.mem.readIntSliceBig(u128, &address.sa.addr);
    return (addr & 0xFFFF_FFFF_FFFF_FFFF_FFFF_FFFF_0000_0000) == 0x0;
}

pub inline fn isIpv4MappedIpv6(address: std.net.Ip6Address) bool {
    const addr = std.mem.readIntSliceBig(u128, &address.sa.addr);
    return (addr & 0xFFFF_FFFF_FFFF_FFFF_FFFF_FFFF_0000_0000) == 0x0000_0000_0000_0000_0000_ffff_0000_0000;
}

pub inline fn isValidAddress(address: std.net.Address) bool {
    if (address.any.family != std.os.AF.INET6) return true;
    return !isSiteLocalIpv6(address.in6) and !isLinkLocalIpv6(address.in6) and !isIpv4CompatibleIpv6(address.in6) and !isIpv4MappedIpv6(address.in6);
}

test "ipv6 checks" {
    try std.testing.expect(isLinkLocalIpv6((try std.net.Address.parseIp6("fe80::6d55:f86:a6e6:6464", 0)).in6));
    try std.testing.expect(isSiteLocalIpv6((try std.net.Address.parseIp6("fec0::6d55:f86:a6e6:6464", 0)).in6));
    try std.testing.expect(isIpv4MappedIpv6((try std.net.Address.parseIp6("::ffff:7f00:0001", 0)).in6));
    try std.testing.expect(isIpv4CompatibleIpv6((try std.net.Address.parseIp6("::7f00:0001", 0)).in6));
}

pub fn getSocketAddress(socket: std.os.fd_t) !std.net.Address {
    var address_storage: std.os.linux.sockaddr.storage = undefined;
    const address = @as(*std.os.linux.sockaddr, @ptrCast(&address_storage));
    var a_len: std.os.socklen_t = @sizeOf(std.os.linux.sockaddr.storage);

    try std.os.getsockname(socket, address, &a_len);

    return std.net.Address.initPosix(@alignCast(address));
}
