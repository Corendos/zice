// Copyright 2023 - Corentin Godeau and the zice contributors
// SPDX-License-Identifier: MIT

const std = @import("std");

/// Represents the family of the IP address.
pub const AddressFamily = enum {
    /// IPv4 address.
    ipv4,
    /// Ipv6 address.
    ipv6,
};

/// Represents an IP address.
pub const Address = union(AddressFamily) {
    ipv4: Ipv4Address,
    ipv6: Ipv6Address,

    pub fn format(value: Address, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
        return switch (value) {
            inline else => |a| a.format(fmt, options, writer),
        };
    }
};

/// Represents an IPv4 address.
pub const Ipv4Address = struct {
    value: [4]u8,

    pub fn format(value: Ipv4Address, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
        _ = options;
        _ = fmt;
        try writer.print("{}.{}.{}.{}", .{ value.value[0], value.value[1], value.value[2], value.value[3] });
    }
};

/// Represents an IPv6 address.
pub const Ipv6Address = struct {
    value: [16]u8,
    scope_id: u32 = 0,

    pub fn format(value: Ipv6Address, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
        _ = options;
        _ = fmt;
        try writer.print("{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}", .{
            value.value[0],
            value.value[1],
            value.value[2],
            value.value[3],
            value.value[4],
            value.value[5],
            value.value[6],
            value.value[7],
            value.value[8],
            value.value[9],
            value.value[10],
            value.value[11],
            value.value[12],
            value.value[13],
            value.value[14],
            value.value[15],
        });
        if (value.scope_id != 0) {
            try writer.print("%{}", .{value.scope_id});
        }
    }
};

test "ipv4" {
    const address = Ipv4Address{ .value = [_]u8{ 192, 168, 0, 1 } };
    try std.testing.expectFmt("192.168.0.1", "{}", .{address});
}

test "ipv6" {
    const address = Ipv6Address{ .value = [_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 } };
    try std.testing.expectFmt("0000:0000:0000:0000:0000:0000:0000:0001", "{}", .{address});
}
