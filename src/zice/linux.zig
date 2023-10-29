// Copyright 2023 - Corentin Godeau and the zice contributors
// SPDX-License-Identifier: MIT

const std = @import("std");
const linux = std.os.linux;
const xev = @import("xev");

pub const netlink = @import("linux/netlink.zig");
const zice = @import("../main.zig");
const net = zice.net;

test {
    _ = netlink;
}
