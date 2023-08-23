const std = @import("std");

const CircularBuffer = @import("circular_buffer.zig").CircularBuffer;

pub fn BoundedFifo(comptime T: type, comptime size: usize) type {
    return struct {
        buffer: CircularBuffer(T, size) = .{},

        pub fn push(self: *@This(), v: T) !void {
            try self.buffer.push(v);
        }

        pub fn pop(self: *@This()) ?T {
            return self.buffer.pop();
        }

        pub fn empty(self: *const @This()) bool {
            return self.buffer.empty();
        }

        pub fn count(self: *const @This()) usize {
            return self.buffer.head_index - self.buffer.tail_index;
        }

        pub fn getPtr(self: *@This(), index: usize) *T {
            std.debug.assert(self.buffer.tail_index + index < self.buffer.head_index);
            return &self.buffer.data[(self.buffer.tail_index + index) % self.buffer.data.len];
        }

        pub fn get(self: *const @This(), index: usize) T {
            std.debug.assert(self.buffer.tail_index + index < self.buffer.head_index);
            return self.buffer.data[(self.buffer.tail_index + index) % self.buffer.data.len];
        }

        pub fn orderedRemove(self: *@This(), index: usize) T {
            std.debug.assert(self.buffer.tail_index + index < self.buffer.head_index);
            const removed = self.buffer.data[(self.buffer.tail_index + index) % self.buffer.data.len];
            for (self.buffer.tail_index + index + 1..self.buffer.head_index) |i| {
                self.buffer.data[(i - 1) % self.buffer.data.len] = self.buffer.data[i % self.buffer.data.len];
            }
            self.buffer.head_index -= 1;
            return removed;
        }

        pub fn findFirstContext(self: *const @This(), context: anytype, v: T, comptime eql: fn (ctx: @TypeOf(context), a: T, b: T) bool) ?T {
            return for (self.buffer.tail_index..self.buffer.head_index) |index| {
                const current = self.buffer.data[index % self.buffer.data.len];
                if (eql(context, v, current)) break current;
            } else null;
        }

        pub fn findFirst(self: *const @This(), v: T, comptime eqlFn: fn (a: T, b: T) bool) ?T {
            return self.findFirstContext({}, v, (struct {
                fn eql(_: void, a: T, b: T) bool {
                    return eqlFn(a, b);
                }
            }).eql);
        }
    };
}

test "Basic usage" {
    var fifo: BoundedFifo(u32, 4) = .{};
    try fifo.push(1);
    try fifo.push(2);
    try fifo.push(3);

    try std.testing.expectEqual(@as(u32, 2), fifo.orderedRemove(1));
    try std.testing.expectEqual(@as(?u32, 1), fifo.pop());
    try std.testing.expectEqual(@as(?u32, 3), fifo.pop());

    try fifo.push(1);
    try fifo.push(2);
    try fifo.push(3);

    try std.testing.expectEqual(@as(u32, 1), fifo.orderedRemove(0));
    try std.testing.expectEqual(@as(?u32, 2), fifo.pop());
    try std.testing.expectEqual(@as(?u32, 3), fifo.pop());

    try fifo.push(1);
    try fifo.push(2);
    try fifo.push(3);

    try std.testing.expectEqual(@as(u32, 3), fifo.orderedRemove(2));
    try std.testing.expectEqual(@as(?u32, 1), fifo.pop());
    try std.testing.expectEqual(@as(?u32, 2), fifo.pop());
}
