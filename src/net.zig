// Copyright 2023 - Corentin Godeau and the zice contributors
// SPDX-License-Identifier: MIT

const std = @import("std");
const builtin = @import("builtin");

pub usingnamespace switch (builtin.os.tag) {
    .linux => @import("net/linux.zig"),
    else => @compileError("\"" ++ @tagName(builtin.os.tag) ++ "\" platform is not supported yet."),
};

pub inline fn isSiteLocalIpv6(address: std.net.Ip6Address) bool {
    _ = address;
    return false;
}

pub inline fn isIpv4CompatibleIpv6(address: std.net.Ip6Address) bool {
    _ = address;
    return false;
}

pub inline fn isIpv4MappedIpv6(address: std.net.Ip6Address) bool {
    _ = address;
    return false;
}
