// Copyright 2023 - Corentin Godeau and the zice contributors
// SPDX-License-Identifier: MIT

const std = @import("std");

pub fn Future(comptime T: type) type {
    return struct {
        event: std.Thread.ResetEvent = .{},
        value: ?T = null,

        const Self = @This();

        pub fn set(self: *Self, v: T) void {
            self.value = v;
            self.event.set();
        }

        pub fn wait(self: *Self) void {
            self.event.wait();
        }

        pub fn timedWait(self: *Self, timeout_ns: u64) error{Timeout}!void {
            return self.event.timedWait(timeout_ns);
        }

        pub fn get(self: *Self) T {
            self.wait();
            return self.value.?;
        }

        pub fn timedGet(self: *Self, timeout_ns: u64) T {
            self.timedWait(timeout_ns);
            return self.value.?;
        }

        pub fn getPtr(self: *Self) *T {
            self.wait();
            return &self.value.?;
        }

        pub fn timedGetPtr(self: *Self, timeout_ns: u64) *T {
            self.timedWait(timeout_ns);
            return &self.value.?;
        }
    };
}
