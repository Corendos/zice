// Copyright 2023 - Corentin Godeau and the zice contributors
// SPDX-License-Identifier: MIT

const std = @import("std");

pub const Reader = struct {
    buffer: []const u8,
    cursor: usize = 0,

    pub fn init(data: []const u8) Reader {
        return Reader{ .buffer = data };
    }

    pub fn skip(self: *Reader, c: u8) void {
        while (self.cursor < self.buffer.len and self.buffer[self.cursor] == c) : (self.cursor += 1) {}
    }

    pub inline fn peek(self: *Reader) ?u8 {
        return if (self.cursor < self.buffer.len) self.buffer[self.cursor] else null;
    }

    pub fn skipAny(self: *Reader, comptime values: []const u8) void {
        while (self.cursor < self.buffer.len) : (self.cursor += 1) {
            const none = inline for (values) |c| {
                if (self.buffer[self.cursor] == c) break false;
            } else true;

            if (none) break;
        }
    }

    pub fn readUntil(self: *Reader, c: u8) ?[]const u8 {
        const start = self.cursor;
        const value = self.readUntilOrEof(c);
        if (self.cursor == self.buffer.len) {
            self.cursor = start;
            return null;
        }

        return value;
    }

    pub fn readUntilAny(self: *Reader, comptime values: []const u8) ?[]const u8 {
        const start = self.cursor;
        const value = self.readUntilAnyOrEof(values);
        if (self.cursor == self.buffer.len) {
            self.cursor = start;
            return null;
        }

        return value;
    }

    pub fn readUntilOrEof(self: *Reader, c: u8) []const u8 {
        const start = self.cursor;
        while (self.cursor < self.buffer.len and self.buffer[self.cursor] != c) : (self.cursor += 1) {}

        return self.buffer[start..self.cursor];
    }

    pub fn readUntilAnyOrEof(self: *Reader, comptime values: []const u8) []const u8 {
        const start = self.cursor;
        top: while (self.cursor < self.buffer.len) : (self.cursor += 1) {
            inline for (values) |c| {
                if (self.buffer[self.cursor] == c) break :top;
            }
        }

        return self.buffer[start..self.cursor];
    }

    pub fn expect(self: *Reader, needle: []const u8) bool {
        if (self.cursor + needle.len >= self.buffer.len) return false;
        const match = std.mem.eql(u8, self.buffer[self.cursor .. self.cursor + needle.len], needle);
        if (match) {
            self.cursor += needle.len;
        }
        return match;
    }

    pub inline fn done(self: *const Reader) bool {
        return self.cursor >= self.buffer.len;
    }

    pub fn readRemaining(self: *Reader) []const u8 {
        const result = self.buffer[self.cursor..];
        self.cursor = self.buffer.len;
        return result;
    }
};
