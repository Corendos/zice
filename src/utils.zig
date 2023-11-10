// Copyright 2023 - Corentin Godeau and the zice contributors
// SPDX-License-Identifier: MIT

const zice = @import("main.zig");
const xev = zice.xev;

pub inline fn autoDup(c: xev.Completion) xev.Completion {
    if (xev.backend == .epoll) {
        var copy = c;
        copy.flags.dup = true;
        return copy;
    }
    return c;
}
