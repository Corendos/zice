// Copyright 2023 - Corentin Godeau and the zice contributors
// SPDX-License-Identifier: MIT

const std = @import("std");
const builtin = @import("builtin");

pub const AddressFormatter = struct {
    address: std.net.Address,

    pub fn format(self: AddressFormatter, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
        _ = options;
        switch (fmt[0]) {
            'a' => {
                switch (self.address.any.family) {
                    std.os.AF.INET => {
                        const bytes = @as(*const [4]u8, @ptrCast(&self.address.in.sa.addr));
                        try writer.print("{}.{}.{}.{}", .{
                            bytes[0],
                            bytes[1],
                            bytes[2],
                            bytes[3],
                        });
                    },
                    std.os.AF.INET6 => {
                        if (std.mem.eql(u8, self.address.in6.sa.addr[0..12], &[_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff })) {
                            try std.fmt.format(writer, "[::ffff:{}.{}.{}.{}]", .{
                                self.address.in6.sa.addr[12],
                                self.address.in6.sa.addr[13],
                                self.address.in6.sa.addr[14],
                                self.address.in6.sa.addr[15],
                            });
                            return;
                        }
                        const native_endian = builtin.target.cpu.arch.endian();
                        const big_endian_parts = @as(*align(1) const [8]u16, @ptrCast(&self.address.in6.sa.addr));
                        const native_endian_parts = switch (native_endian) {
                            .big => big_endian_parts.*,
                            .little => blk: {
                                var buf: [8]u16 = undefined;
                                for (big_endian_parts, 0..) |part, i| {
                                    buf[i] = std.mem.bigToNative(u16, part);
                                }
                                break :blk buf;
                            },
                        };
                        try writer.writeAll("[");
                        var i: usize = 0;
                        var abbrv = false;
                        while (i < native_endian_parts.len) : (i += 1) {
                            if (native_endian_parts[i] == 0) {
                                if (!abbrv) {
                                    try writer.writeAll(if (i == 0) "::" else ":");
                                    abbrv = true;
                                }
                                continue;
                            }
                            try std.fmt.format(writer, "{x}", .{native_endian_parts[i]});
                            if (i != native_endian_parts.len - 1) {
                                try writer.writeAll(":");
                            }
                        }
                        try writer.writeAll("]");
                    },
                    else => unreachable,
                }
            },
            'p' => {
                try writer.print("{d}", .{self.address.getPort()});
            },
            else => {},
        }
    }
};

pub fn addressFormatter(address: std.net.Address) AddressFormatter {
    return AddressFormatter{ .address = address };
}
