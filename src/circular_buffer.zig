// Copyright 2023 - Corentin Godeau and the zice contributors
// SPDX-License-Identifier: MIT

const std = @import("std");

pub fn CircularBuffer(comptime T: type, comptime size: usize) type {
    return struct {
        const Self = @This();

        data: [size]T = undefined,
        head_index: usize = 0,
        tail_index: usize = 0,

        pub fn push(self: *Self, v: T) !void {
            if (self.head_index - self.tail_index == size) return error.NoSpaceLeft;
            defer self.head_index += 1;
            self.data[self.head_index % size] = v;
        }

        pub fn pushPtr(self: *Self) !*T {
            if (self.head_index - self.tail_index == size) return error.NoSpaceLeft;
            defer self.head_index += 1;
            return &self.data[self.head_index % size];
        }

        pub fn pop(self: *Self) ?T {
            if (self.head_index == self.tail_index) return null;
            defer self.tail_index += 1;
            return self.data[self.tail_index % size];
        }

        pub inline fn empty(self: Self) bool {
            return self.head_index == self.tail_index;
        }
    };
}

test "Basic usage of CircularBuffer" {
    var buffer = CircularBuffer(u32, 2){};
    try std.testing.expect(buffer.empty());
    try buffer.push(1);
    try std.testing.expect(!buffer.empty());
    try std.testing.expectEqual(@as(?u32, 1), buffer.pop());
    try std.testing.expect(buffer.empty());
    try std.testing.expectEqual(@as(?u32, null), buffer.pop());

    try std.testing.expectEqual({}, buffer.push(1));
    try std.testing.expectEqual({}, buffer.push(2));
    try std.testing.expectError(error.NoSpaceLeft, buffer.push(3));

    _ = buffer.pop();
    try std.testing.expectEqual({}, buffer.push(3));
}
