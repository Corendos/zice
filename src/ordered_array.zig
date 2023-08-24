const std = @import("std");

// Automatically compute the default context to use in OrderedBoundedArray for T.
fn AutoContext(comptime T: type) type {
    return struct {
        const Self = @This();

        pub const lessThan = switch (@typeInfo(T)) {
            .Int, .Float => (struct {
                fn lessThan(_: *Self, a: T, b: T) bool {
                    return a < b;
                }
            }).lessThan,
            else => @compileError("AutoContext is only defined for orderable types"),
        };
    };
}

/// Array with a fixed maximum capacity that stays ordered.
/// In order to work properly, the given Context struct needs to have `lessThan` method declared.
/// This method has the following signature: `fn lessThan(context: *Context, a: T, b: T) bool`.
pub fn OrderedBoundedArray(comptime T: type, comptime capacity: usize, comptime Context: type) type {
    return struct {
        const Self = @This();

        data: [capacity]T = undefined,
        size: usize = 0,
        items: []T = &.{},

        context: Context,

        pub fn init() Self {
            if (@sizeOf(Context) != 0)
                @compileError("Cannot infer context " ++ @typeName(Context) ++ ", call initContext instead.");
            return initContext(undefined);
        }

        pub fn initContext(context: Context) Self {
            return Self{ .context = context };
        }

        pub fn insert(self: *Self, v: T) void {
            defer self.items = self.data[0..self.size];

            if (self.size == 0) {
                self.data[0] = v;
                self.size += 1;
                return;
            }

            var last = self.data[self.size - 1];
            std.mem.copyBackwards(T, self.data[1..self.size], self.data[0 .. self.size - 1]);
            self.data[0] = v;
            std.sort.insertion(T, self.data[0..self.size], &self.context, Context.lessThan);

            if (self.size < self.data.len) {
                self.data[self.size] = last;
                if (Context.lessThan(&self.context, self.data[self.size], self.data[self.size - 1])) {
                    std.mem.swap(T, &self.data[self.size], &self.data[self.size - 1]);
                }
                self.size += 1;
            } else {
                if (Context.lessThan(&self.context, last, self.data[self.size - 1])) {
                    std.mem.swap(T, &last, &self.data[self.size - 1]);
                }
            }
        }

        pub fn remove(self: *Self, index: usize) T {
            std.debug.assert(index < self.size);
            defer self.items = self.data[0..self.size];

            const removed = self.data[index];
            std.mem.copyForwards(T, self.data[index .. self.size - 1], self.data[index + 1 .. self.size]);
            self.size -= 1;
            return removed;
        }
    };
}

/// Return an OrderedBoundedArray with the default context derived from T.
pub fn AutoOrderedBoundedArray(comptime T: type, comptime capacity: usize) type {
    return OrderedBoundedArray(T, capacity, AutoContext(T));
}

test "OrderedArray" {
    const Context = struct {
        pub fn lessThan(_: *@This(), a: u32, b: u32) bool {
            return a < b;
        }
    };

    var ordered_array = OrderedBoundedArray(u32, 10, Context).init();

    ordered_array.insert(5);
    try std.testing.expectEqualSlices(u32, &.{5}, ordered_array.items);

    ordered_array.insert(4);
    try std.testing.expectEqualSlices(u32, &.{ 4, 5 }, ordered_array.items);

    ordered_array.insert(1);
    ordered_array.insert(2);
    ordered_array.insert(3);
    ordered_array.insert(6);
    ordered_array.insert(7);
    ordered_array.insert(8);
    ordered_array.insert(9);
    ordered_array.insert(10);

    try std.testing.expectEqualSlices(u32, &.{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 }, ordered_array.items);

    ordered_array.insert(11);
    try std.testing.expectEqualSlices(u32, &.{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 }, ordered_array.items);

    ordered_array.insert(0);
    try std.testing.expectEqualSlices(u32, &.{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 }, ordered_array.items);

    try std.testing.expectEqual(@as(u32, 3), ordered_array.remove(3));
    try std.testing.expectEqualSlices(u32, &.{ 0, 1, 2, 4, 5, 6, 7, 8, 9 }, ordered_array.items);
}
