const std = @import("std");
const assert = std.debug.assert;

/// An intrusive doubly linked list implementation. The type T must have fields
/// "next" and "prev" of type `?*T`.
pub fn DoublyLinkedList(comptime T: type) type {
    return struct {
        const Self = @This();
        const EqlFunction = *const fn (a: T, b: T) bool;

        /// Head is the front of the queue and tail is the back of the queue.
        head: ?*T = null,
        tail: ?*T = null,

        /// Enqueue a new element to the back of the queue.
        pub fn pushBack(self: *Self, v: *T) void {
            assert(v.next == null);
            assert(v.prev == null);

            if (self.tail) |tail| {
                // If we have elements in the queue, then we add a new tail.
                tail.next = v;
                v.prev = tail;
                self.tail = v;
            } else {
                // No elements in the queue we setup the initial state.
                self.head = v;
                self.tail = v;
            }
        }

        /// Enqueue a new element to the front of the queue.
        pub fn pushFront(self: *Self, v: *T) void {
            assert(v.next == null);
            assert(v.prev == null);

            if (self.head) |head| {
                // If we have elements in the queue, then we add a new head.
                head.prev = v;
                v.next = head;
                self.head = v;
            } else {
                // No elements in the queue we setup the initial state.
                self.head = v;
                self.tail = v;
            }
        }

        /// Dequeue the element at the back of the queue.
        pub fn popBack(self: *Self) ?*T {
            // The back element is in "tail".
            const next = self.tail orelse return null;

            // If the head and tail are equal this is the last element
            // so we also set head to null so we can now be empty.
            if (self.head == self.tail) self.head = null;

            // Tail is whatever is next (if we're the last element,
            // this will be null);
            self.tail = next.prev;

            // We set the "next" and "prev" fields to null so that this element
            // can be inserted again.
            next.next = null;
            next.prev = null;
            return next;
        }

        /// Dequeue the element at the front of the queue.
        pub fn popFront(self: *Self) ?*T {
            // The front element is in "head".
            const next = self.head orelse return null;

            // If the head and tail are equal this is the last element
            // so we also set tail to null so we can now be empty.
            if (self.head == self.tail) self.tail = null;

            // Head is whatever is next (if we're the last element,
            // this will be null);
            self.head = next.next;

            // We set the "next" and "prev" fields to null so that this element
            // can be inserted again.
            next.next = null;
            next.prev = null;
            return next;
        }

        /// Returns true if the queue is empty.
        pub fn empty(self: *const Self) bool {
            return self.head == null;
        }

        pub fn removeContext(self: *Self, context: anytype, v: T, comptime eql: fn (ctx: @TypeOf(context), a: T, b: T) bool) ?*T {
            var node_opt = self.head;

            while (node_opt) |node| {
                if (eql(context, v, node.*)) {
                    if (node.prev) |prev| {
                        prev.next = node.next;
                    } else {
                        // The node is the head, so we update it.
                        self.head = node.next;
                    }

                    if (node.next) |next| {
                        next.prev = node.prev;
                    } else {
                        // The node is the tail, so we update it.
                        self.tail = node.prev;
                    }

                    // We set the "next" and "prev" fields to null so that this element
                    // can be inserted again.
                    node.prev = null;
                    node.next = null;

                    return node;
                }
                node_opt = node.next;
            }

            return null;
        }

        pub fn remove(self: *Self, v: T, comptime eqlFn: fn (a: T, b: T) bool) ?*T {
            return self.removeContext({}, v, (struct {
                fn eql(_: void, a: T, b: T) bool {
                    return eqlFn(a, b);
                }
            }).eql);
        }

        pub fn findFirstContext(self: *const Self, context: anytype, v: T, comptime eql: fn (ctx: @TypeOf(context), a: T, b: T) bool) ?*T {
            var node_opt = self.head;
            while (node_opt) |node| {
                if (eql(context, v, node.*)) return node;
                node_opt = node.next;
            }
            return null;
        }

        pub fn findFirst(self: *const Self, v: T, comptime eqlFn: fn (a: T, b: T) bool) ?*T {
            return self.findFirstContext({}, v, (struct {
                fn eql(_: void, a: T, b: T) bool {
                    return eqlFn(a, b);
                }
            }).eql);
        }

        pub fn findLastContext(self: *const Self, context: anytype, v: T, comptime eql: fn (ctx: @TypeOf(context), a: T, b: T) bool) ?*T {
            var node_opt = self.tail;
            while (node_opt) |node| {
                if (eql(context, v, node.*)) return node;
                node_opt = node.prev;
            }
            return null;
        }

        pub fn findLast(self: *const Self, v: T, comptime eqlFn: fn (a: T, b: T) bool) ?*T {
            return self.findLastContext({}, v, (struct {
                fn eql(_: void, a: T, b: T) bool {
                    return eqlFn(a, b);
                }
            }).eql);
        }
    };
}

test "DoublyLinkedList" {
    const testing = std.testing;

    // Types
    const Elem = struct {
        const Self = @This();
        value: usize = 0,
        next: ?*Self = null,
        prev: ?*Self = null,

        fn eql(a: Self, b: Self) bool {
            return a.value == b.value;
        }
    };
    const DLL = DoublyLinkedList(Elem);
    var q: DLL = .{};
    try testing.expect(q.empty());

    // Elems
    var elems: [10]Elem = .{.{}} ** 10;
    for (elems[0..], 0..) |*e, i| e.value = i;

    // One
    try testing.expect(q.popBack() == null);
    q.pushBack(&elems[0]);
    try testing.expect(!q.empty());
    try testing.expect(q.popBack().? == &elems[0]);
    try testing.expect(q.popBack() == null);
    try testing.expect(q.empty());

    try testing.expect(q.popFront() == null);
    q.pushFront(&elems[0]);
    try testing.expect(!q.empty());
    try testing.expect(q.popFront().? == &elems[0]);
    try testing.expect(q.popFront() == null);
    try testing.expect(q.empty());

    try testing.expect(q.popBack() == null);
    q.pushBack(&elems[0]);
    try testing.expect(!q.empty());
    try testing.expect(q.popFront().? == &elems[0]);
    try testing.expect(q.popBack() == null);
    try testing.expect(q.empty());

    // Two
    try testing.expect(q.popBack() == null);
    q.pushBack(&elems[0]);
    q.pushBack(&elems[1]);
    try testing.expect(q.popFront().? == &elems[0]);
    try testing.expect(q.popFront().? == &elems[1]);
    try testing.expect(q.popFront() == null);

    try testing.expect(q.popBack() == null);
    q.pushBack(&elems[0]);
    q.pushBack(&elems[1]);
    try testing.expect(q.popBack().? == &elems[1]);
    try testing.expect(q.popBack().? == &elems[0]);
    try testing.expect(q.popBack() == null);

    // Removing
    try testing.expect(q.popBack() == null);
    q.pushBack(&elems[0]);
    q.pushBack(&elems[1]);
    try testing.expect(q.remove(Elem{ .value = 0 }, Elem.eql).? == &elems[0]);
}
