// Copyright 2023 - Corentin Godeau and the zice contributors
// SPDX-License-Identifier: MIT

const std = @import("std");
const builtin = @import("builtin");

pub const net = @import("net.zig");
pub const os = @import("os.zig");

pub usingnamespace switch (builtin.os.tag) {
    .linux => @import("linux.zig"),
    else => @compileError("\"" ++ @tagName(builtin.os.tag) ++ "\" platform is not supported yet."),
};

pub const TransportAddress = struct {
    address: net.Address,
    port: u16,

    pub fn format(value: TransportAddress, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
        _ = options;
        _ = fmt;
        return switch (value.address) {
            .ipv4 => |address| writer.print("{}:{}", .{ address, value.port }),
            .ipv6 => |address| writer.print("[{}]:{}", .{ address, value.port }),
        };
    }
};

pub const CandidateType = enum {
    host,
    server_reflexive,
    peer_reflexive,
    relay,
};

pub const Candidate = struct {
    type: CandidateType,
    transport_address: TransportAddress,
    base_address: TransportAddress,
};

pub const Configuration = struct {
    /// Represents the value of Ta in the RFC 8489.
    pub const new_transaction_interval_ms: u64 = 50;
    /// Represents the value of Rc in the RFC 8489.
    pub const request_count: u64 = 7;
    /// Represents the value of Rm in the RFC 8489.
    pub const last_request_factor: u64 = 16;

    pub inline fn computeRtoMs(candidate_count: u64) u64 {
        return std.math.max(500, candidate_count * new_transaction_interval_ms);
    }
};

test {
    _ = std.testing.refAllDeclsRecursive(@This());
}
