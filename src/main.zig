// Copyright 2023 - Corentin Godeau and the zice contributors
// SPDX-License-Identifier: MIT

const std = @import("std");
const builtin = @import("builtin");

const ztun = @import("ztun");
const xev = @import("xev");

pub const net = @import("net.zig");

const platform = switch (builtin.os.tag) {
    .linux => @import("zice/linux.zig"),
    else => @compileError("\"" ++ @tagName(builtin.os.tag) ++ "\" platform not supported"),
};

pub usingnamespace platform;

pub const Intrusive = @import("queue.zig").Intrusive;
pub const Worker = @import("zice/Worker.zig");

/// Represents an ICE candidate type. See https://www.rfc-editor.org/rfc/rfc8445#section-4 for definitions.
pub const CandidateType = enum {
    host,
    server_reflexive,
    peer_reflexive,
    relay,

    pub inline fn preference(self: CandidateType) u32 {
        return switch (self) {
            .host => 126,
            .server_reflexive => 100,
            .peer_reflexive => 110,
            .relay => 0,
        };
    }
};

// TODO(Corentin): Implement https://www.rfc-editor.org/rfc/rfc8421#section-4 for local preference computation

/// Represents an ICE candidate.
pub const Candidate = struct {
    /// The type of candidate.
    type: CandidateType,
    /// The candidate transport address.
    transport_address: std.net.Address,
    /// The candidate base address.
    base_address: std.net.Address,

    // TODO(Corendos): multiple component ID support

    /// The component ID associated to the candidate.
    component_id: u8 = 1,

    pub inline fn computePriority(self: Candidate, local_preference: u32) u32 {
        return (self.type.preference() << 24) | (local_preference << 8) | (256 - @as(u32, self.component_id));
    }
};

test "candidate priority" {
    const candidate_1 = Candidate{
        .type = .host,
        .transport_address = undefined,
        .base_address = undefined,
    };
    const candidate_2 = Candidate{
        .type = .server_reflexive,
        .transport_address = undefined,
        .base_address = undefined,
    };

    try std.testing.expectEqual(@as(u32, 2_113_929_471), candidate_1.computePriority(0));
    try std.testing.expectEqual(@as(u32, 1_677_721_855), candidate_2.computePriority(0));
}

/// ICE protocol configuration.
pub const Configuration = struct {
    /// Represents the value of Ta in the RFC 8489.
    pub const new_transaction_interval_ms: u64 = 50;
    /// Represents the value of Rc in the RFC 8489.
    pub const request_count: u64 = 3;
    /// Represents the value of Rm in the RFC 8489.
    pub const last_request_factor: u64 = 16;

    //const stun_address_ipv4 = std.net.Address.parseIp4("91.134.140.104", 3478) catch unreachable;
    const stun_address_ipv4 = std.net.Address.parseIp4("172.253.120.127", 19302) catch unreachable;
    const stun_address_ipv6 = std.net.Address.parseIp6("2a00:1450:400c:c00::7f", 19302) catch unreachable;

    pub inline fn computeRtoMs(candidate_count: u64) u64 {
        return std.math.max(500, candidate_count * new_transaction_interval_ms);
    }
};

/// Represents the status of each potential candidate when gathering them.
pub const GatheringStatus = enum {
    /// The candidate has just been created.
    new,
    /// The candidate is currently being checked.
    checking,
    /// The candidate check resulted in a failure.
    failed,
    /// The candidate has been checked succesfully.
    done,
};

/// Stores the various fields required to handle retry during checks.
const RetryTimerContext = struct {
    /// The xev timer that is used.
    timer: xev.Timer,
    /// The xev Completion associated with the timer.
    completion: xev.Completion = undefined,
    /// The current timeout of the timer.
    timeout_ms: u64 = 0,
    /// The number of request already sent.
    request_sent_count: usize = 0,
};

/// Stores data required to properly send a message through the socket.
pub const MessageData = struct {
    /// The associated xev.Completion.
    completion: xev.Completion = .{},
    /// The buffer where the message is stored before sending.
    buffer: []u8 = &.{},
    /// The iovec used in sendmsg.
    iovec: std.os.iovec_const = undefined,
    /// The message_header used in sendmsg.
    message_header: std.os.msghdr_const = undefined,
    /// The address used in sendmsg.
    address: std.net.Address = undefined,

    /// Fill the iovec and message_header field using the given paramters.
    pub fn setFrom(self: *MessageData, address: std.net.Address, size: usize) void {
        self.address = address;

        self.iovec = .{
            .iov_base = self.buffer.ptr,
            .iov_len = size,
        };

        self.message_header = .{
            .name = &self.address.any,
            .namelen = self.address.getOsSockLen(),
            .control = null,
            .controllen = 0,
            .iov = @ptrCast([*]const std.os.iovec_const, &self.iovec),
            .iovlen = 1,
            .flags = 0,
        };
    }
};

/// Stores data required to properly read data from the socket.
pub const ReadData = struct {
    /// The associated xev.Completion.
    completion: xev.Completion = .{},
    /// The xev.Completion used to cancel the read.
    cancel_completion: xev.Completion = .{},
    /// The buffer where incoming data will be put.
    buffer: []u8 = &.{},
};

/// Gathering process errors.
pub const CandidateGatheringError = error{
    OutOfMemory,
    Unexpected,
};

/// Context for a candidate during the gathering process.
pub const CandidateContext = struct {
    /// The socket associated with the candidate.
    socket: std.os.fd_t,
    /// The local address associated with the candidate.
    address: std.net.Address,

    /// The status of this candidate.
    status: GatheringStatus = .new,

    /// The data required to send a message.
    message_data: MessageData = undefined,
    /// The data required to read a message.
    read_data: ReadData = undefined,

    /// The timer that is used for retry.
    retry_timer: xev.Timer,
    /// The associated xev.Completion.
    retry_timer_completion: xev.Completion = .{},
    /// The current timeout for the retry timer.
    retry_timer_timeout_ms: u64 = 0,

    /// The timer that is used to handle failure.
    failed_timer: xev.Timer,
    /// The associated xev.Completion.
    failed_timer_completion: xev.Completion = .{},

    /// Counts the number of request sent.
    request_sent_count: u64 = 0,
    /// The current RTO (see RFC).
    rto: u64,

    /// The associated gathering context.
    parent_context: ?*CandidateGatheringContext = null,

    /// Initialize a Candidate context from the given socket, address and rto.
    pub fn init(socket: std.os.fd_t, address: std.net.Address, rto: u64, allocator: std.mem.Allocator) !CandidateContext {
        const retry_timer = try xev.Timer.init();
        errdefer retry_timer.deinit();

        const failed_timer = try xev.Timer.init();
        errdefer failed_timer.deinit();

        var read_buffer = try allocator.alloc(u8, 4096);
        errdefer allocator.free(read_buffer);

        var message_buffer = try allocator.alloc(u8, 4096);
        errdefer allocator.free(message_buffer);

        return .{
            .socket = socket,
            .address = address,
            .message_data = .{ .buffer = message_buffer },
            .read_data = .{ .buffer = read_buffer },
            .retry_timer = retry_timer,
            .failed_timer = failed_timer,
            .rto = rto,
        };
    }

    /// Deinitialize a candidate context.
    pub fn deinit(self: *CandidateContext, allocator: std.mem.Allocator) void {
        allocator.free(self.message_data.buffer);
        allocator.free(self.read_data.buffer);
        self.failed_timer.deinit();
        self.retry_timer.deinit();
    }

    // Callbacks for various xev.Completion

    fn handleSendCallback(self: *CandidateContext, loop: *xev.Loop, c: *xev.Completion, result: xev.Result) void {
        _ = result.sendmsg catch |err| {
            std.log.err("Got {} with candidate \"{}\" while writing to socket", .{ err, self.address });
            self.status = .failed;
            return;
        };
        _ = c;

        self.request_sent_count += 1;
        std.log.debug("STUN request sent for candidate \"{}\"", .{self.address});

        if (self.request_sent_count == 1) {
            self.read_data.completion = xev.Completion{
                .op = .{ .read = .{
                    .fd = self.socket,
                    .buffer = xev.ReadBuffer{
                        .slice = self.read_data.buffer,
                    },
                } },
                .userdata = self,
                .callback = readCallback,
            };
            loop.add(&self.read_data.completion);
            self.retry_timer_timeout_ms = self.rto;
        } else if (self.request_sent_count == Configuration.request_count) {
            self.failed_timer.run(
                loop,
                &self.failed_timer_completion,
                self.rto * Configuration.last_request_factor,
                CandidateContext,
                self,
                failedTimerCallback,
            );
            return;
        } else {
            self.retry_timer_timeout_ms = self.retry_timer_timeout_ms * 2;
        }

        self.retry_timer.run(
            loop,
            &self.retry_timer_completion,
            self.retry_timer_timeout_ms,
            CandidateContext,
            self,
            retryTimerCallback,
        );
    }

    fn handleReadCallback(self: *CandidateContext, loop: *xev.Loop, c: *xev.Completion, result: xev.Result) void {
        const bytes_read = result.read catch |err| {
            if (err != error.Canceled) {
                std.log.err("Got {} with candidate \"{}\" while reading from socket", .{ err, self.address });
            }
            self.status = .failed;
            return;
        };
        _ = loop;

        const raw_message_buffer = c.op.read.buffer.slice[0..bytes_read];

        var buffer: [4096]u8 = undefined;
        var allocator_state = std.heap.FixedBufferAllocator.init(&buffer);
        var allocator = allocator_state.allocator();
        const message: ztun.Message = blk: {
            var stream = std.io.fixedBufferStream(raw_message_buffer);
            break :blk ztun.Message.readAlloc(stream.reader(), allocator) catch unreachable;
        };
        defer message.deinit(allocator);

        self.status = .done;
        std.log.debug("Gathering done for candidate \"{}\"", .{self.address});

        const candidate_gathering_context = self.parent_context.?;
        if (getServerReflexiveAddressFromStunMessage(message)) |transport_address| {
            candidate_gathering_context.result_candidates.append(candidate_gathering_context.allocator, Candidate{
                .type = .server_reflexive,
                .transport_address = transport_address,
                .base_address = self.address,
            }) catch unreachable;
        }
    }

    fn handleRetryTimerCallback(self: *CandidateContext, loop: *xev.Loop, c: *xev.Completion, result: xev.Timer.RunError!void) void {
        if (self.status == .done or self.status == .failed) return;

        _ = result catch |err| {
            std.log.err("Got {} with candidate \"{}\" while waiting for timer", .{ err, self.address });
            self.status = .failed;
            return;
        };
        _ = c;

        std.debug.assert(self.status == .checking);

        std.log.debug("STUN request {}/{} from candidate \"{}\" timed out", .{ self.request_sent_count, Configuration.request_count, self.address });

        const message_size = blk: {
            var buffer: [4096]u8 = undefined;
            var allocator_state = std.heap.FixedBufferAllocator.init(&buffer);
            var allocator = allocator_state.allocator();
            const request_message = makeRequest(allocator) catch unreachable;
            defer request_message.deinit(allocator);

            var stream = std.io.fixedBufferStream(self.message_data.buffer);
            request_message.write(stream.writer()) catch unreachable;
            break :blk stream.getWritten().len;
        };

        const address = switch (self.address.any.family) {
            std.os.AF.INET => Configuration.stun_address_ipv4,
            std.os.AF.INET6 => Configuration.stun_address_ipv6,
            else => unreachable,
        };
        self.message_data.setFrom(address, message_size);

        self.message_data.completion = xev.Completion{
            .op = .{
                .sendmsg = .{
                    .fd = self.socket,
                    .msghdr = &self.message_data.message_header,
                    .buffer = null,
                },
            },
            .userdata = self,
            .callback = sendCallback,
        };
        loop.add(&self.message_data.completion);
    }

    fn handleFailedTimerCallback(self: *CandidateContext, loop: *xev.Loop, c: *xev.Completion, result: xev.Timer.RunError!void) void {
        _ = c;
        if (self.status == .done or self.status == .failed) return;

        std.debug.assert(self.status == .checking);
        if (result) |_| {
            std.log.debug("Gathering timed out for candidate \"{}\"", .{self.address});
        } else |err| {
            std.log.err("Got {} with candidate \"{}\" while waiting for timer", .{ err, self.address });
        }

        self.read_data.cancel_completion = xev.Completion{
            .op = .{
                .cancel = .{ .c = &self.read_data.completion },
            },
        };
        loop.add(&self.read_data.cancel_completion);
    }
};

/// The context used while gathering candidates.
pub const CandidateGatheringContext = struct {
    /// The allocator to use for allocations.
    allocator: std.mem.Allocator,
    /// Opaque data.
    userdata: ?*anyopaque,
    /// Callback.
    callback: *const fn (userdata: ?*anyopaque, result: CandidateGatheringError![]Candidate) void,

    /// The timer that fires when a new candidate can be checked.
    main_timer: xev.Timer,
    /// The associated xev.Completion.
    main_timer_completion: xev.Completion = .{},

    /// The Worker completion
    completion: Worker.Completion = .{},

    /// The context for every candidates.
    candidate_contexts: []CandidateContext = &.{},

    /// Stores the result for each candidate.
    result_candidates: std.ArrayListUnmanaged(Candidate) = .{},
    /// Stores an error if there was one during gathring.
    result_error: ?CandidateGatheringError = null,

    /// Has this gathering already been completed ?
    completed: bool = false,

    /// Initialize a gathering context.
    pub fn init(
        sockets: []const std.os.fd_t,
        addresses: []const std.net.Address,
        allocator: std.mem.Allocator,
        userdata: ?*anyopaque,
        callback: *const fn (userdata: ?*anyopaque, result: CandidateGatheringError![]Candidate) void,
    ) !CandidateGatheringContext {
        var main_timer = try xev.Timer.init();
        errdefer main_timer.deinit();

        var candidate_context_list = try std.ArrayList(CandidateContext).initCapacity(allocator, addresses.len);
        defer candidate_context_list.deinit();
        defer for (candidate_context_list.items) |*ctx| ctx.deinit(allocator);

        const rto = Configuration.computeRtoMs(addresses.len);
        for (sockets, addresses) |socket, address| {
            candidate_context_list.appendAssumeCapacity(try CandidateContext.init(socket, address, rto, allocator));
        }

        return CandidateGatheringContext{
            .allocator = allocator,
            .userdata = userdata,
            .callback = callback,
            .main_timer = main_timer,
            .candidate_contexts = candidate_context_list.toOwnedSlice() catch unreachable,
        };
    }

    /// Deinitialize a gathering context.
    pub fn deinit(self: *CandidateGatheringContext) void {
        for (self.candidate_contexts) |*ctx| ctx.deinit(self.allocator);
        self.allocator.free(self.candidate_contexts);
        self.main_timer.deinit();
        self.result_candidates.deinit(self.allocator);
    }

    /// Return the index of a candidate that has not been checked yet or null.
    fn getUncheckedCandidate(self: *const CandidateGatheringContext) ?usize {
        for (self.candidate_contexts, 0..) |ctx, i| {
            if (ctx.status == .new) {
                return i;
            }
        }
        return null;
    }

    /// Call the callbacks with the gathering result.
    /// This MUST be calles once only.
    fn perform(self: *CandidateGatheringContext) void {
        // NOTE(Corendos): This is not supposed to happen.
        std.debug.assert(!self.completed);
        self.completed = true;

        const result: CandidateGatheringError![]Candidate = self.result_error orelse self.result_candidates.toOwnedSlice(self.allocator);

        self.callback(self.userdata, result);
    }

    /// Returns true if the gathering is done and we can call the callback with a valid result.
    fn isDone(self: *const CandidateGatheringContext) bool {
        var checking_count: usize = 0;
        var new_count: usize = 0;
        for (self.candidate_contexts) |ctx| {
            if (ctx.status == .checking) checking_count += 1;
            if (ctx.status == .new) new_count += 1;
        }

        // If we encountered an error
        if (self.result_error != null) {
            // We are done only if there is no check in flight.
            return checking_count == 0;
        }

        // Otherwise, we are done if all candiates have been checked
        return new_count == 0 and checking_count == 0;
    }

    /// Callbacks for the main timer.
    fn handleMainTimerCallback(self: *CandidateGatheringContext, loop: *xev.Loop, c: *xev.Completion, result: xev.Timer.RunError!void) void {
        _ = result catch |err| {
            std.log.err("{}", .{err});
            self.result_error = error.Unexpected;
            return;
        };

        std.debug.assert(self.candidate_contexts.len != 0);

        // Get a candidate still in the .new state or disarm the timer.
        const candidate_index = self.getUncheckedCandidate() orelse return;

        const candidate_context_ptr = &self.candidate_contexts[candidate_index];

        // Set the candidate in the .checking state
        candidate_context_ptr.status = .checking;

        std.log.debug("Sending message for candidate \"{}\"", .{candidate_context_ptr.address});
        const message_size = blk: {
            var buffer: [4096]u8 = undefined;
            var allocator_state = std.heap.FixedBufferAllocator.init(&buffer);
            var allocator = allocator_state.allocator();
            const request_message = makeRequest(allocator) catch unreachable;
            defer request_message.deinit(allocator);

            var stream = std.io.fixedBufferStream(candidate_context_ptr.message_data.buffer);
            request_message.write(stream.writer()) catch unreachable;
            break :blk stream.getWritten().len;
        };

        const address = switch (candidate_context_ptr.address.any.family) {
            std.os.AF.INET => Configuration.stun_address_ipv4,
            std.os.AF.INET6 => Configuration.stun_address_ipv6,
            else => unreachable,
        };

        // TODO(Corendos): Maybe the size can be set elsewhere ?
        candidate_context_ptr.message_data.setFrom(address, message_size);

        candidate_context_ptr.message_data.completion = xev.Completion{
            .op = .{
                .sendmsg = .{
                    .fd = candidate_context_ptr.socket,
                    .msghdr = &candidate_context_ptr.message_data.message_header,
                    .buffer = null,
                },
            },
            .userdata = candidate_context_ptr,
            .callback = sendCallback,
        };
        loop.add(&candidate_context_ptr.message_data.completion);

        // Rearm the timer
        self.main_timer.run(loop, c, Configuration.new_transaction_interval_ms, CandidateGatheringContext, self, mainTimerCallback);
    }
};

pub fn makeRequest(allocator: std.mem.Allocator) !ztun.Message {
    var message_builder = ztun.MessageBuilder.init(allocator);
    defer message_builder.deinit();

    // Binding request with random transaction ID.
    message_builder.setClass(ztun.Class.request);
    message_builder.setMethod(ztun.Method.binding);
    message_builder.randomTransactionId();

    // Add a fingerprint for validity check.
    message_builder.addFingerprint();
    return try message_builder.build();
}

pub fn fromStunAddress(mapped_address: ztun.attr.common.MappedAddress) std.net.Address {
    return switch (mapped_address.family) {
        .ipv4 => |value| std.net.Address.initIp4(@bitCast([4]u8, std.mem.bigToNative(u32, value)), mapped_address.port),
        .ipv6 => |value| std.net.Address.initIp6(@bitCast([16]u8, std.mem.bigToNative(u128, value)), mapped_address.port, 0, 0),
    };
}

pub fn getServerReflexiveAddressFromStunMessage(message: ztun.Message) ?std.net.Address {
    for (message.attributes) |attribute| {
        if (attribute.type == ztun.attr.Type.mapped_address) {
            const mapped_address_attribute = ztun.attr.common.MappedAddress.fromAttribute(attribute) catch return null;
            return fromStunAddress(mapped_address_attribute);
        } else if (attribute.type == ztun.attr.Type.xor_mapped_address) {
            const xor_mapped_address_attribute = ztun.attr.common.XorMappedAddress.fromAttribute(attribute) catch return null;
            const mapped_address_attribute = ztun.attr.common.decode(xor_mapped_address_attribute, message.transaction_id);
            return fromStunAddress(mapped_address_attribute);
        }
    }

    return null;
}

fn failedTimerCallback(userdata: ?*CandidateContext, loop: *xev.Loop, c: *xev.Completion, result: xev.Timer.RunError!void) xev.CallbackAction {
    const candidate_context_ptr = userdata.?;
    candidate_context_ptr.handleFailedTimerCallback(loop, c, result);

    const context = candidate_context_ptr.parent_context.?;

    if (context.isDone()) {
        context.perform();
    }
    return .disarm;
}

fn retryTimerCallback(userdata: ?*CandidateContext, loop: *xev.Loop, c: *xev.Completion, result: xev.Timer.RunError!void) xev.CallbackAction {
    var candidate_context_ptr = userdata.?;
    candidate_context_ptr.handleRetryTimerCallback(loop, c, result);

    const context = candidate_context_ptr.parent_context.?;

    if (context.isDone()) {
        context.perform();
    }

    return .disarm;
}

fn readCallback(userdata: ?*anyopaque, loop: *xev.Loop, c: *xev.Completion, result: xev.Result) xev.CallbackAction {
    const candidate_context_ptr = @ptrCast(*CandidateContext, @alignCast(@alignOf(CandidateContext), userdata.?));
    candidate_context_ptr.handleReadCallback(loop, c, result);

    const context = candidate_context_ptr.parent_context.?;

    if (context.isDone()) {
        context.perform();
    }

    return .disarm;
}

fn sendCallback(userdata: ?*anyopaque, loop: *xev.Loop, c: *xev.Completion, result: xev.Result) xev.CallbackAction {
    const candidate_context_ptr = @ptrCast(*CandidateContext, @alignCast(@alignOf(CandidateContext), userdata.?));
    candidate_context_ptr.handleSendCallback(loop, c, result);

    const context = candidate_context_ptr.parent_context.?;

    if (context.isDone()) {
        context.perform();
    }

    return .disarm;
}

fn mainTimerCallback(userdata: ?*CandidateGatheringContext, loop: *xev.Loop, c: *xev.Completion, result: xev.Timer.RunError!void) xev.CallbackAction {
    var context = userdata.?;
    context.handleMainTimerCallback(loop, c, result);

    if (context.isDone()) {
        context.perform();
    }

    return .disarm;
}

pub fn makeCandidates(context: *CandidateGatheringContext, worker: *Worker) void {
    for (context.candidate_contexts) |ctx| {
        context.result_candidates.append(context.allocator, Candidate{
            .type = .host,
            .base_address = ctx.address,
            .transport_address = ctx.address,
        }) catch |e| {
            context.result_error = e;
            context.perform();
            return;
        };
    }

    for (context.candidate_contexts) |*ctx| ctx.parent_context = context;

    context.completion = Worker.Completion{
        .userdata = context,
        .callback = (struct {
            pub fn callback(ud: ?*anyopaque, worker_inner: *Worker, c_inner: *Worker.Completion) void {
                _ = c_inner;
                const context_inner = @ptrCast(*CandidateGatheringContext, @alignCast(@alignOf(CandidateGatheringContext), ud.?));

                context_inner.main_timer.run(
                    &worker_inner.loop,
                    &context_inner.main_timer_completion,
                    Configuration.new_transaction_interval_ms,
                    CandidateGatheringContext,
                    context_inner,
                    mainTimerCallback,
                );
            }
        }).callback,
    };

    worker.post(&context.completion);
}

test {
    _ = Worker;
    _ = Intrusive;
    _ = platform;
    _ = net;
}
