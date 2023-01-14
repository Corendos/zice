// Copyright 2023 - Corentin Godeau and the zice contributors
// SPDX-License-Identifier: MIT

const std = @import("std");
const builtin = @import("builtin");

pub usingnamespace switch (builtin.os.tag) {
    .linux => @import("linux.zig"),
    else => @compileError("\"" ++ @tagName(builtin.os.tag) ++ "\" platform is not supported yet."),
};

test {
    _ = std.testing.refAllDeclsRecursive(@This());
}
