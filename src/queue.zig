// Copyright 2023 - Corentin Godeau and the zice contributors
// SPDX-License-Identifier: MIT

const std = @import("std");

pub fn Intrusive(comptime T: type) type {
    return struct {
        const Self = @This();

        /// Head is the front of the queue and tail is the back of the queue.
        head: ?*T = null,
        tail: ?*T = null,

        mutex: std.Thread.Mutex = .{},

        /// Enqueue a new element to the back of the queue.
        pub fn push(self: *Self, v: *T) void {
            self.mutex.lock();
            defer self.mutex.unlock();
            std.debug.assert(v.next == null);

            if (self.tail) |tail| {
                // If we have elements in the queue, then we add a new tail.
                tail.next = v;
                self.tail = v;
            } else {
                // No elements in the queue we setup the initial state.
                self.head = v;
                self.tail = v;
            }
        }

        /// Dequeue the next element from the queue.
        pub fn pop(self: *Self) ?*T {
            self.mutex.lock();
            defer self.mutex.unlock();

            // The next element is in "head".
            const next = self.head orelse return null;

            // If the head and tail are equal this is the last element
            // so we also set tail to null so we can now be empty.
            if (self.head == self.tail) self.tail = null;

            // Head is whatever is next (if we're the last element,
            // this will be null);
            self.head = next.next;

            // We set the "next" field to null so that this element
            // can be inserted again.
            next.next = null;
            return next;
        }

        /// Returns true if the queue is empty.
        pub fn empty(self: *const Self) bool {
            self.mutex.lock();
            defer self.mutex.unlock();
            return self.head == null;
        }
    };
}
