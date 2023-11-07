// Copyright 2023 - Corentin Godeau and the zice contributors
// SPDX-License-Identifier: MIT

const std = @import("std");
const builtin = @import("builtin");
const build_options = @import("build_options");
const ztun = @import("ztun");

pub const xev = if (builtin.os.tag == .linux)
    switch (build_options.linux_backend) {
        .io_uring => @import("xev").IO_Uring,
        .epoll => @import("xev").Epoll,
    }
else
    @import("xev");
pub const net = @import("net.zig");
pub const fmt = @import("fmt.zig");
pub const platform = switch (builtin.os.tag) {
    .linux => @import("zice/linux.zig"),
    else => @compileError("\"" ++ @tagName(builtin.os.tag) ++ "\" platform not supported"),
};

pub const DoublyLinkedList = @import("doubly_linked_list.zig").DoublyLinkedList;
pub const CircularBuffer = @import("circular_buffer.zig").CircularBuffer;
pub const BoundedFifo = @import("bounded_fifo.zig").BoundedFifo;
pub const OrderedBoundedArray = @import("ordered_array.zig").OrderedBoundedArray;
pub const GenerationId = @import("generation_id.zig").GenerationId;
const NetlinkContext = @import("netlink.zig").NetlinkContext;
pub const Intrusive = @import("queue.zig").Intrusive;
pub const Future = @import("future.zig").Future;

const log = std.log.scoped(.zice);

// TODO(Corendos,@Global):
// * Handle peer-reflexive
// * Implement https://www.rfc-editor.org/rfc/rfc8421#section-4 for local preference computation
// * Support multiple data streams

/// Represents an ICE candidate type. See https://www.rfc-editor.org/rfc/rfc8445#section-4 for definitions.
pub const CandidateType = enum(u2) {
    host,
    server_reflexive,
    peer_reflexive,
    relay,

    /// Returns the numerical preference associated with a candidate type.
    pub inline fn preference(self: CandidateType) u32 {
        return switch (self) {
            .host => 126,
            .server_reflexive => 100,
            .peer_reflexive => 110,
            .relay => 0,
        };
    }

    /// Returns a string representation of a candidate type.
    pub inline fn toString(self: CandidateType) [:0]const u8 {
        return switch (self) {
            .host => "host",
            .server_reflexive => "srflx",
            .peer_reflexive => "prflx",
            .relay => "relay",
        };
    }
};

/// Represents the type of the Transport Address.
pub const Protocol = enum(u2) {
    /// The addresses uses the UDP protocol.
    udp,
    /// The addresses uses the TCP protocol.
    tcp,

    // NOTE(Corendos): TCP is not supported yet.
};

/// Represents the Foundation of a candidate. See https://www.rfc-editor.org/rfc/rfc8445#section-4 for definitions.
/// The Foundations of two candidates must be identical if they have the same type, base address, protocol and STUN/TURN servers.
/// We store these and interpret the struct as a integer.
pub const Foundation = packed struct {
    /// The type of the candidate.
    type: CandidateType,
    /// The protocol used by the candidate.
    protocol: Protocol,
    /// The index of the address associated with the candidate. This is simpler than storing the full address.
    address_index: u8,

    /// Backing integer of the struct.
    pub const IntType = std.meta.Int(.unsigned, @bitSizeOf(Foundation));

    /// Returns the struct as an integer.
    pub inline fn asNumber(self: Foundation) IntType {
        return @intCast(@as(IntType, @bitCast(self)));
    }

    /// Compare two Foundations.
    pub inline fn eql(a: Foundation, b: Foundation) bool {
        return a.asNumber() == b.asNumber();
    }
};

test "Foundation conversions" {
    const f = Foundation{ .address_index = 1, .type = .server_reflexive, .protocol = .udp };
    try std.testing.expectEqual(@as(u16, 17), f.asNumber());
}

/// Represents an ICE candidate.
pub const Candidate = struct {
    /// The type of candidate.
    type: CandidateType,
    /// The candidate transport address.
    transport_address: std.net.Address,
    /// The candidate base address.
    base_address: std.net.Address,
    /// The candidate priority.
    priority: u32 = 0,
    /// The candidate foundation.
    foundation: Foundation = undefined,
    /// The component ID associated to the candidate.
    component_id: u8 = 1,
    /// Is this candidate the default candidate.
    default: bool = false,
};

/// Compute the priority using the type preference, local preference and component ID according to https://www.rfc-editor.org/rfc/rfc8445#section-5.1.2.1.
inline fn computePriority(type_preference: u32, local_preference: u32, component_id: u8) u32 {
    return (type_preference << 24) + (local_preference << 8) + (256 - @as(u32, component_id));
}

test "candidate priority" {
    const priority1 = computePriority(CandidateType.host.preference(), 0, 1);
    const priority2 = computePriority(CandidateType.server_reflexive.preference(), 0, 1);

    try std.testing.expectEqual(@as(u32, 0x7E_0000_FF), priority1);
    try std.testing.expectEqual(@as(u32, 0x64_0000_FF), priority2);
}

/// ICE protocol configuration.
pub const Configuration = struct {
    /// Represents the value of Ta in the RFC 8489.
    pub const new_transaction_interval_ms: u64 = 50;
    /// Represents the value of Rc in the RFC 8489.
    pub const request_count: u64 = 3;
    /// Represents the value of Rm in the RFC 8489.
    pub const last_request_factor: u64 = 16;
    /// Represents the limit for candidate pairs within a checklist set.
    pub const candidate_pair_limit = 10;

    //const stun_address_ipv4 = std.net.Address.parseIp4("91.134.140.104", 3479) catch unreachable;
    const stun_address_ipv4 = std.net.Address.parseIp4("172.253.120.127", 19302) catch unreachable;
    const stun_address_ipv6 = std.net.Address.parseIp6("2a00:1450:400c:c00::7f", 19302) catch unreachable;

    /// Compute the RTO in milliseconds for the gathering step.
    pub inline fn computeRtoGatheringMs(candidate_count: u64) u64 {
        return @max(500, candidate_count * new_transaction_interval_ms);
    }

    /// Compute the RTO in millisconds for the connectivity checks.
    pub inline fn computeRtoCheckMs(check_count: u64, waiting_count: u64, in_progress_count: u64) u64 {
        return @max(500, check_count * (waiting_count + in_progress_count) * new_transaction_interval_ms);
    }
};

/// Convenience to build a basic STUN request.
fn makeBasicBindingRequest(allocator: std.mem.Allocator, transaction_id: ?u96) !ztun.Message {
    var message_builder = ztun.MessageBuilder.init(allocator);
    defer message_builder.deinit();

    // Binding request with random transaction ID.
    message_builder.setClass(ztun.Class.request);
    message_builder.setMethod(ztun.Method.binding);
    if (transaction_id) |v| {
        message_builder.transactionId(v);
    } else {
        message_builder.randomTransactionId();
    }

    // Add a fingerprint for validity check.
    message_builder.addFingerprint();
    return try message_builder.build();
}

/// Make the username used in STUN transaction from local and remote fragments.
fn makeUsername(
    local_username_fragment: []const u8,
    remote_username_fragment: []const u8,
    allocator: std.mem.Allocator,
) ![]u8 {
    var result = try allocator.alloc(u8, local_username_fragment.len + remote_username_fragment.len + 1);
    errdefer allocator.free(result);

    @memcpy(result[0..local_username_fragment.len], local_username_fragment);
    result[local_username_fragment.len] = ':';
    @memcpy(result[local_username_fragment.len + 1 ..], remote_username_fragment);

    return result;
}

/// Convenience to build a STUN request used in connectivity checks.
fn makeConnectivityCheckBindingRequest(
    local_username_fragment: []const u8,
    remote_username_fragment: []const u8,
    password: []const u8,
    priority: u32,
    role: AgentRole,
    tiebreaker: u64,
    use_candidate: bool,
    allocator: std.mem.Allocator,
) !ztun.Message {
    var message_builder = ztun.MessageBuilder.init(allocator);
    defer message_builder.deinit();

    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();

    var arena = arena_state.allocator();

    const authentication = ztun.auth.Authentication{ .short_term = ztun.auth.ShortTermAuthentication{ .password = password } };

    // Binding request with random transaction ID.
    message_builder.setClass(ztun.Class.request);
    message_builder.setMethod(ztun.Method.binding);
    message_builder.randomTransactionId();

    const username = try makeUsername(local_username_fragment, remote_username_fragment, arena);
    const username_attribute = try (ztun.attr.common.Username{ .value = username }).toAttribute(allocator);
    try message_builder.addAttribute(username_attribute);

    const priority_attribute = try (ztun.attr.common.Priority{ .value = priority }).toAttribute(allocator);
    try message_builder.addAttribute(priority_attribute);

    const role_attribute = switch (role) {
        .controlling => try (ztun.attr.common.IceControlling{ .value = tiebreaker }).toAttribute(allocator),
        .controlled => try (ztun.attr.common.IceControlled{ .value = tiebreaker }).toAttribute(allocator),
    };
    try message_builder.addAttribute(role_attribute);

    if (use_candidate) {
        const use_candidate_attribute = try (ztun.attr.common.UseCandidate{}).toAttribute(allocator);
        try message_builder.addAttribute(use_candidate_attribute);
    }

    message_builder.addMessageIntegrity(authentication);

    // Add a fingerprint for validity check.
    message_builder.addFingerprint();

    const message = try message_builder.build();

    return message;
}

/// Convenience to build a STUN response to a request.
fn makeBindingResponse(transaction_id: u96, source: std.net.Address, password: []const u8, allocator: std.mem.Allocator) !ztun.Message {
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();

    var message_builder = ztun.MessageBuilder.init(arena_state.allocator());

    message_builder.setClass(ztun.Class.success_response);
    message_builder.setMethod(ztun.Method.binding);
    message_builder.transactionId(transaction_id);

    const mapped_address = toStunAddress(source);
    const xor_mapped_address = ztun.attr.common.encode(mapped_address, transaction_id);
    const xor_mapped_address_attribute = try xor_mapped_address.toAttribute(arena_state.allocator());
    try message_builder.addAttribute(xor_mapped_address_attribute);

    const authentication = ztun.auth.Authentication{ .short_term = .{ .password = password } };
    message_builder.addMessageIntegrity(authentication);

    message_builder.addFingerprint();

    return try message_builder.build();
}

/// Convenience to build a STUN error response caused by a role conflict.
fn makeRoleConflictResponse(transaction_id: u96, password: []const u8, allocator: std.mem.Allocator) !ztun.Message {
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();

    var message_builder = ztun.MessageBuilder.init(arena_state.allocator());

    message_builder.setClass(ztun.Class.error_response);
    message_builder.setMethod(ztun.Method.binding);
    message_builder.transactionId(transaction_id);

    const error_code_attribute = try (ztun.attr.common.ErrorCode{ .value = .role_conflict, .reason = "Role Conflict" }).toAttribute(arena_state.allocator());
    try message_builder.addAttribute(error_code_attribute);

    const authentication = ztun.auth.Authentication{ .short_term = .{ .password = password } };
    message_builder.addMessageIntegrity(authentication);

    message_builder.addFingerprint();

    return try message_builder.build();
}

/// Convert a MAPPED-ADDRESS STUN attributes to a std.net.Address.
pub inline fn fromStunAddress(mapped_address: ztun.attr.common.MappedAddress) std.net.Address {
    return switch (mapped_address.family) {
        .ipv4 => |value| std.net.Address.initIp4(value, mapped_address.port),
        .ipv6 => |value| std.net.Address.initIp6(value, mapped_address.port, 0, 0),
    };
}

/// Convert a std.net.Address to a MAPPED-ADDRESS STUN attributes.
pub inline fn toStunAddress(address: std.net.Address) ztun.attr.common.MappedAddress {
    const family = switch (address.any.family) {
        std.os.AF.INET => ztun.attr.common.AddressFamily{ .ipv4 = std.mem.toBytes(address.in.sa.addr) },
        std.os.AF.INET6 => ztun.attr.common.AddressFamily{ .ipv6 = address.in6.sa.addr[0..16].* },
        else => unreachable,
    };

    return ztun.attr.common.MappedAddress{ .family = family, .port = address.getPort() };
}

/// Tries to extract the address from a STUN binding response or return null if that's not possible.
pub fn getMappedAddressFromStunMessage(message: ztun.Message) ?std.net.Address {
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

/// Compute the priority for a candidate pair according to https://www.rfc-editor.org/rfc/rfc8445#section-6.1.2.3.
inline fn computePairPriority(local_candidate_priority: u32, remote_candidate_priority: u32, role: AgentRole) u64 {
    const g: u64 = if (role == .controlling) local_candidate_priority else remote_candidate_priority;
    const d: u64 = if (role == .controlled) local_candidate_priority else remote_candidate_priority;
    const discriminant: u64 = if (g > d) 1 else 0;
    return (@min(g, d) << 32) + (@max(g, d) << 1) + discriminant;
}

/// Represents the status of each potential candidate when gathering them.
pub const CandidateGatheringStatus = enum {
    /// The candidate has just been created.
    new,
    /// The candidate is currently being checked.
    checking,
    /// The candidate check resulted in a failure.
    failed,
    /// The candidate has been checked succesfully.
    done,
};

/// Stores data required to properly send a message through the socket.
pub const WriteData = struct {
    /// The iovec used in sendmsg.
    iovec: std.os.iovec_const = undefined,
    /// The message_header used in sendmsg.
    message_header: std.os.msghdr_const = undefined,
    /// The address used in sendmsg.
    address: std.net.Address = undefined,

    /// Fill the iovec and message_header field using the given paramters.
    pub fn from(self: *WriteData, address: std.net.Address, data: []const u8) void {
        self.address = address;
        self.iovec = .{ .iov_base = data.ptr, .iov_len = data.len };

        self.message_header = .{
            .name = &self.address.any,
            .namelen = self.address.getOsSockLen(),
            .control = null,
            .controllen = 0,
            .iov = @ptrCast(&self.iovec),
            .iovlen = 1,
            .flags = 0,
        };
    }
};

/// Stores data required to properly receive a message from the socket.
pub const ReadData = struct {
    /// The iovec used in recvmsg.
    iovec: std.os.iovec = undefined,
    /// The message_header used in recvmsg.
    message_header: std.os.msghdr = undefined,
    /// The address used in recvmsg.
    address: std.net.Address = undefined,
};

/// Represents the gathering state of the agent.
pub const GatheringState = enum {
    /// Waiting to start gathering candidates.
    idle,
    /// Candidates are being gathered.
    gathering,
    /// Candidates have been gathered,
    done,
};

/// Represents the payload of the OnCandidateCallback callback.
pub const CandidateResult = union(enum) {
    /// Candidate gathering is done and there won't be any new candidates.
    done: void,
    /// A candidate has been found,
    candidate: Candidate,
};

/// Callback that is called when a candidate has been found or when all the candidates have been found.
pub const OnCandidateCallback = *const fn (userdata: ?*anyopaque, agent: *AgentContext, result: CandidateResult) void;
fn noopCandidateCallback(_: ?*anyopaque, _: *AgentContext, _: CandidateResult) void {}

/// Callback that is called when the ICE state changes.
pub const OnStateChangeCallback = *const fn (userdata: ?*anyopaque, agent: *AgentContext, state: AgentState) void;
fn noopStateChangeCallback(_: ?*anyopaque, _: *AgentContext, _: AgentState) void {}

/// Callback that is called when the agent receives data.
pub const OnDataCallback = *const fn (userdate: ?*anyopaque, agent: *AgentContext, component_id: u8, data: []const u8) void;
fn noopDataCallback(_: ?*anyopaque, _: *AgentContext, _: u8, _: []const u8) void {}

/// Represents the errors that can occur while performing a STUN transaction.
pub const TransactionError = error{
    /// The transaction was canceled.
    Canceled,
    /// The transaction timed out (this is for the final timeout, not for retries).
    Timeout,
    /// The given storage buffer for the response is not big enough.
    NotEnoughSpace,
};

/// Represents the result of a STUN transaction.
pub const TransactionResult = TransactionError!struct {
    /// The raw STUN response
    raw_message: []const u8,
    /// The source address of the response.
    source: std.net.Address,
};

/// Callback that is called when a STUN transaction completed.
const TransactionCallback = *const fn (userdata: ?*anyopaque, transaction: *Transaction, result: TransactionResult) void;
fn noopTransactionCallback(_: ?*anyopaque, _: *Transaction, _: TransactionResult) void {}

pub const Transaction = struct {
    /// The socket to use for the STUN transaction.
    socket: std.os.fd_t,
    /// The address to which the request should be sent.
    server_address: std.net.Address,

    /// The timer that is used for retry.
    retry_timer: xev.Timer,
    /// The current timeout for the retry timer.
    retry_timer_timeout_ms: u64 = 0,
    /// The associated xev.Completion.
    retry_timer_completion: xev.Completion = .{},
    /// The associated cancel xev.Completion
    retry_timer_cancel_completion: xev.Completion = .{},
    /// The timer that is used for timeout.
    timeout_timer: xev.Timer,
    /// The completion for the transaction timeout.
    timeout_completion: xev.Completion = .{},
    /// The associated cancel xev.Completion.
    timeout_cancel_completion: xev.Completion = .{},

    /// The buffer used to send a message.
    write_buffer: []u8 = &.{},
    /// The actual request data.
    request_data: []u8 = &.{},
    /// The data required to send a message.
    write_data: WriteData = undefined,
    /// The associated xev.Completion.
    write_completion: xev.Completion = .{},
    /// The completion to cancel the write.
    write_cancel_completion: xev.Completion = .{},
    /// The transaction id of the request being sent to the STUN server.
    transaction_id: u96,

    /// Counts the number of request sent.
    request_sent_count: u64 = 0,
    /// The current RTO (see RFC).
    rto: ?u64 = null,

    /// Transaction status flags.
    flags: packed struct {
        /// The transaction was canceled.
        canceled: bool = false,
        /// Retransmits were canceled.
        no_retransmits: bool = false,
        /// The transaction timed out.
        timeout: bool = false,
    } = .{},

    /// Userdata to use in completion callback.
    userdata: ?*anyopaque = null,
    /// The completion callback.
    callback: TransactionCallback = noopTransactionCallback,
    /// Storage for the transaction result.
    result: ?TransactionResult = null,
    /// Storage for the response.
    read_buffer: []u8 = &.{},

    /// Initialize a Transaction with given parameters.
    pub fn init(socket: std.os.fd_t, destination: std.net.Address, message: ztun.Message, write_buffer: []u8, read_buffer: []u8, userdata: ?*anyopaque, comptime callback: TransactionCallback) Transaction {
        const retry_timer = xev.Timer.init() catch unreachable;
        const timeout_timer = xev.Timer.init() catch unreachable;

        const request_data = b: {
            var stream = std.io.fixedBufferStream(write_buffer);
            const writer = stream.writer();
            message.write(writer) catch unreachable;
            break :b stream.getWritten();
        };

        return .{
            .socket = socket,
            .server_address = destination,
            .retry_timer = retry_timer,
            .timeout_timer = timeout_timer,
            .write_buffer = write_buffer,
            .request_data = request_data,
            .transaction_id = message.transaction_id,
            .read_buffer = read_buffer,
            .userdata = userdata,
            .callback = callback,
        };
    }

    /// Deinitialize a candidate context.
    pub fn deinit(self: *Transaction) void {
        self.retry_timer.deinit();
        self.timeout_timer.deinit();
    }

    fn enqueueWrite(self: *Transaction, loop: *xev.Loop) void {
        self.write_data.from(self.server_address, self.request_data);

        self.write_completion = xev.Completion{
            .op = .{
                .sendmsg = .{
                    .fd = self.socket,
                    .msghdr = &self.write_data.message_header,
                    .buffer = null,
                },
            },
            .userdata = self,
            .callback = writeCallback,
        };

        if (xev.backend == .epoll) {
            self.write_completion.flags.dup = true;
        }

        loop.add(&self.write_completion);
    }

    /// Start a transaction with the given retransmit timout and event-loop.
    pub fn start(self: *Transaction, rto: u64, loop: *xev.Loop) void {
        self.rto = rto;
        self.enqueueWrite(loop);
    }

    /// Cancel the transaction.
    pub fn cancel(self: *Transaction, loop: *xev.Loop) void {
        self.cancelWrite(loop);
        self.cancelRetry(loop);
        self.cancelTimeout(loop);

        if (self.result == null) {
            self.result = error.Canceled;
        }

        self.flags.canceled = true;
    }

    /// Cancel retransmits.
    pub fn stopRetransmits(self: *Transaction, loop: *xev.Loop) void {
        self.cancelWrite(loop);
        self.cancelRetry(loop);
        self.flags.no_retransmits = true;
    }

    /// Handle the STUN response.
    /// Unlike writes, this need to be called from outside because the socket might receive various messages and we are only interested in
    /// STUN response associated with this transaction.
    pub fn readCallback(self: *Transaction, loop: *xev.Loop, raw_message: []const u8, source: std.net.Address) void {
        self.cancelWrite(loop);
        self.cancelRetry(loop);
        self.cancelTimeout(loop);

        if (self.result == null) {
            // If the transaction has not been canceled or it has not timed out yet, we store the result.
            if (raw_message.len <= self.read_buffer.len) {
                const dest = self.read_buffer[0..raw_message.len];
                @memcpy(dest, raw_message);
                self.result = .{ .raw_message = dest, .source = source };
            } else {
                // If we don't have enough space to store what we receive, we store the error in result.
                self.result = error.NotEnoughSpace;
            }
        }

        // If the transaction is complete, we call the callback.
        if (self.state() == .dead) {
            self.callback(self.userdata, self, self.result.?);
        }
    }

    /// Returns true if a write (or a cancellation of a write) is currently active.
    pub inline fn isWriteActive(self: Transaction) bool {
        return self.write_completion.state() != .dead or self.write_cancel_completion.state() != .dead;
    }

    /// Returns true if the retry timer (or a cancellation of it) is currently active.
    pub inline fn isRetryTimerActive(self: Transaction) bool {
        return self.retry_timer_completion.state() != .dead or self.retry_timer_cancel_completion.state() != .dead;
    }

    /// Returns true if the timeout timer (or a cancellation of it) is currently active.
    pub inline fn isTimeoutTimerActive(self: Transaction) bool {
        return self.timeout_completion.state() != .dead or self.timeout_cancel_completion.state() != .dead;
    }

    /// Returns the state of the transaction in terms of xev.CompletionState.
    pub inline fn state(self: Transaction) xev.CompletionState {
        return if (self.isWriteActive() or self.isRetryTimerActive() or self.isTimeoutTimerActive()) .active else .dead;
    }

    /// Cancel a potentially active write.
    fn cancelWrite(self: *Transaction, loop: *xev.Loop) void {
        if (self.write_completion.state() == .dead or self.write_cancel_completion.state() == .active) return;

        self.write_cancel_completion = xev.Completion{
            .op = .{ .cancel = .{ .c = &self.write_completion } },
            .userdata = self,
            .callback = writeCancelCallback,
        };
        loop.add(&self.write_cancel_completion);
    }

    /// Cancel a potentially active retry timer.
    fn cancelRetry(self: *Transaction, loop: *xev.Loop) void {
        if (self.retry_timer_completion.state() == .dead or self.retry_timer_cancel_completion.state() == .active) return;

        self.retry_timer.cancel(
            loop,
            &self.retry_timer_completion,
            &self.retry_timer_cancel_completion,
            Transaction,
            self,
            retryCancelCallback,
        );
    }

    /// Cancel a potentially active timeout timer.
    fn cancelTimeout(self: *Transaction, loop: *xev.Loop) void {
        if (self.timeout_completion.state() == .dead or self.timeout_cancel_completion.state() == .active) return;

        self.timeout_timer.cancel(
            loop,
            &self.timeout_completion,
            &self.timeout_cancel_completion,
            Transaction,
            self,
            timeoutCancelCallback,
        );
    }

    /// Callback used when a write has been completed.
    fn writeCallback(
        userdata: ?*anyopaque,
        loop: *xev.Loop,
        c: *xev.Completion,
        result: xev.Result,
    ) xev.CallbackAction {
        _ = c;
        const self: *Transaction = @ptrCast(@alignCast(userdata.?));

        _ = result.sendmsg catch |err| {
            log.err("Transaction {x:12} - Failed to send STUN request. Reason: {}", .{ self.transaction_id, err });
            if (self.state() == .dead) {
                self.callback(self.userdata, self, self.result.?);
            }

            return .disarm;
        };

        self.request_sent_count += 1;

        const is_first_request = self.request_sent_count == 1;
        self.retry_timer_timeout_ms = if (is_first_request) self.rto.? else self.retry_timer_timeout_ms * 2;

        if (is_first_request) {
            const timeout_ms: u64 = (@as(u64, 1 << Configuration.request_count) - 1 + Configuration.last_request_factor) * self.rto.?;
            self.timeout_timer.run(loop, &self.timeout_completion, timeout_ms, Transaction, self, timeoutCallback);
        }

        const is_last_request = self.request_sent_count == Configuration.request_count;
        if (!is_last_request and !self.flags.no_retransmits and !self.flags.canceled) {
            self.retry_timer.run(
                loop,
                &self.retry_timer_completion,
                self.retry_timer_timeout_ms,
                Transaction,
                self,
                retryCallback,
            );
        }

        return .disarm;
    }

    /// Callback used when a write cancellation has been completed.
    fn writeCancelCallback(
        userdata: ?*anyopaque,
        loop: *xev.Loop,
        c: *xev.Completion,
        result: xev.Result,
    ) xev.CallbackAction {
        _ = c;
        _ = result;
        _ = loop;
        const self: *Transaction = @ptrCast(@alignCast(userdata.?));

        if (self.state() == .dead) {
            self.callback(self.userdata, self, self.result.?);
        }

        return .disarm;
    }

    /// Callback used when the retry timer fired.
    fn retryCallback(
        userdata: ?*Transaction,
        loop: *xev.Loop,
        c: *xev.Completion,
        result: xev.Timer.RunError!void,
    ) xev.CallbackAction {
        _ = c;
        const self = userdata.?;

        _ = result catch {
            if (self.state() == .dead) {
                self.callback(self.userdata, self, self.result.?);
            }
            return .disarm;
        };
        loop.add(&self.write_completion);

        return .disarm;
    }

    /// Callback used when the retry timer has been cancelled.
    fn retryCancelCallback(
        userdata: ?*Transaction,
        loop: *xev.Loop,
        c: *xev.Completion,
        result: xev.CancelError!void,
    ) xev.CallbackAction {
        _ = c;
        _ = result catch {};
        _ = loop;

        const self = userdata.?;

        if (self.state() == .dead) {
            self.callback(self.userdata, self, self.result.?);
        }

        return .disarm;
    }

    /// Callback used when the timeout timer fired.
    fn timeoutCallback(
        userdata: ?*Transaction,
        loop: *xev.Loop,
        c: *xev.Completion,
        result: xev.Timer.RunError!void,
    ) xev.CallbackAction {
        _ = c;
        _ = loop;

        const self = userdata.?;
        _ = result catch {
            if (self.state() == .dead) {
                self.callback(self.userdata, self, self.result.?);
            }
            return .disarm;
        };

        if (self.result == null) {
            self.result = error.Timeout;
        }

        if (self.state() == .dead) {
            self.callback(self.userdata, self, self.result.?);
        }

        return .disarm;
    }

    /// Callback used when the timeout timer has been cancelled.
    fn timeoutCancelCallback(
        userdata: ?*Transaction,
        loop: *xev.Loop,
        c: *xev.Completion,
        result: xev.CancelError!void,
    ) xev.CallbackAction {
        _ = c;
        _ = result catch {};
        _ = loop;

        const self = userdata.?;

        if (self.state() == .dead) {
            self.callback(self.userdata, self, self.result.?);
        }

        return .disarm;
    }
};

/// Contains the additional data associated with an open socket.
pub const SocketContext = struct {
    /// Our index in the Agent Context.
    index: usize,

    /// Our associated socket.
    socket: std.os.fd_t,
    /// Our bound address.
    address: std.net.Address,

    // NOTE(Corendos): The bound address corresponds to the base address of candidates.

    /// The buffer used to read a message.
    read_buffer: []u8 = &.{},
    /// The data required to receive a message.
    read_data: ReadData = undefined,
    /// The associated xev.Completion.
    read_completion: xev.Completion = .{},
    /// The completion to cancel reads.
    read_cancel_completion: xev.Completion = .{},

    pub fn init(index: usize, address: std.net.Address, read_buffer: []u8) !SocketContext {
        const socket = try std.os.socket(address.any.family, std.os.SOCK.DGRAM, std.os.IPPROTO.UDP);
        errdefer std.os.close(socket);

        try std.os.bind(socket, &address.any, address.getOsSockLen());
        const bound_address = try net.getSocketAddress(socket);

        return SocketContext{
            .index = index,
            .socket = socket,
            .address = bound_address,
            .read_buffer = read_buffer,
        };
    }

    pub fn start(
        self: *SocketContext,
        loop: *xev.Loop,
        userdata: ?*anyopaque,
        callback: *const fn (
            ?*anyopaque,
            *xev.Loop,
            *xev.Completion,
            xev.Result,
        ) xev.CallbackAction,
    ) void {
        // Start to listen for activity on the socket.
        var read_data = &self.read_data;
        read_data.iovec = .{ .iov_len = self.read_buffer.len, .iov_base = self.read_buffer.ptr };
        read_data.message_header = .{
            .name = &read_data.address.any,
            .namelen = read_data.address.any.data.len,
            .control = null,
            .controllen = 0,
            .iov = @ptrCast(&read_data.iovec),
            .iovlen = 1,
            .flags = 0,
        };

        self.read_completion = xev.Completion{
            .op = .{
                .recvmsg = .{
                    .fd = self.socket,
                    .msghdr = &read_data.message_header,
                },
            },
            .userdata = userdata,
            .callback = callback,
        };

        // TODO(Corendos): Hide implementation details
        if (xev.backend == .epoll) {
            self.read_completion.flags.dup = true;
        }

        loop.add(&self.read_completion);
    }

    pub fn cancel(self: *SocketContext, loop: *xev.Loop) void {
        if (self.read_completion.state() == .dead) return;

        self.read_cancel_completion = .{
            .op = .{ .cancel = .{ .c = &self.read_completion } },
        };

        loop.add(&self.read_cancel_completion);
    }

    pub inline fn done(self: *const SocketContext) bool {
        return self.read_completion.state() == .dead and self.read_cancel_completion.state() == .dead;
    }

    pub fn deinit(self: *SocketContext) void {
        std.os.close(self.socket);
    }
};

/// Represents the role of the agent in an ICE process.
const AgentRole = enum(u1) {
    /// The agent is controlling the ICE process.
    controlling,
    /// The agent is controlled by another agent.
    controlled,
};

/// Represents the state of the ICE session.
pub const AgentState = enum {
    /// The Agent is running.
    running,
    /// The Agent completed all the checklists,
    completed,
    /// The agent has at least one failed checklist.
    failed,
};

/// Represents the state of a checklist.
const ChecklistState = enum {
    /// The checks are being done.
    running,
    /// The checklist checks completed successfully.
    completed,
    /// The checklist checks failed.
    failed,
};

/// Represents the state of a candidate pair when running checks.
const CandidatePairState = enum {
    /// The candidate pair is waiting to be checked.
    waiting,
    /// The check is in progress.
    in_progress,
    /// The check succeeded.
    succeeded,
    /// The check failed.
    failed,
    /// The candidate pair is frozen.
    frozen,

    const count = std.meta.tags(CandidatePairState).len;
};

/// Represents a candidate pair.
const CandidatePair = struct {
    /// The index of the local candidate.
    local_candidate_index: usize,
    /// The index of the remote candidate.
    remote_candidate_index: usize,

    pub inline fn eql(a: CandidatePair, b: CandidatePair) bool {
        return a.local_candidate_index == b.local_candidate_index and a.remote_candidate_index == b.remote_candidate_index;
    }
};

/// Represents the foundation of a pair of candidate.
const CandidatePairFoundation = packed struct {
    /// The local candidate foundation.
    local: Foundation,
    /// The remote candidate foundation.
    remote: Foundation,

    pub inline fn eql(a: CandidatePairFoundation, b: CandidatePairFoundation) bool {
        return a.local.eql(b.local) and a.remote.eql(b.remote);
    }
};

/// Represents the data associated with a candidate pair.
const CandidatePairData = struct {
    /// The pair priority.
    priority: u64,
    /// The pair foundation.
    foundation: CandidatePairFoundation,
    /// The candidate pair state.
    state: CandidatePairState = .frozen,
    /// Has this pair been nominated ? (Only used when in a valid list).
    nominated: bool = false,
};

/// Represents an association between a candidate pair and its associated data.
/// This is used in an array of entries.
const CandidatePairEntry = struct {
    /// The candidate pair.
    pair: CandidatePair,
    /// The data associated with a candidate pair.
    data: CandidatePairData,

    /// Context used in struct requiring ordering.
    pub const Context = struct {
        pub fn lessThan(_: *@This(), a: CandidatePairEntry, b: CandidatePairEntry) bool {
            return a.data.priority > b.data.priority;
        }
    };

    /// Compares two entries.
    pub inline fn eql(a: CandidatePairEntry, b: CandidatePairEntry) bool {
        return CandidatePair.eql(a.pair, b.pair);
    }
};

/// Represents an entry in a list/array of triggered check.
const TriggeredCheckEntry = struct {
    /// The candidate pair for which a triggered check should be done.
    candidate_pair: CandidatePair,
    /// Is this triggered check a nomination.
    nominate: bool = false,

    /// Compares two entries.
    pub fn eql(a: TriggeredCheckEntry, b: TriggeredCheckEntry) bool {
        return a.candidate_pair.eql(b.candidate_pair);
    }
};

/// Represents a checklist that will be used to check candidate pairs.
const Checklist = struct {
    const OrderedPairArray = OrderedBoundedArray(CandidatePairEntry, 16, CandidatePairEntry.Context);
    /// The state of the checklist.
    state: ChecklistState = .running,
    /// The candidate pairs to check ordered by priority.
    pairs: OrderedPairArray,

    /// The valid candidate pairs.
    valid_pairs: OrderedPairArray,

    /// The triggered check FIFO associated with this checklist.
    triggered_check_queue: BoundedFifo(TriggeredCheckEntry, 16) = .{},

    // NOTE(Corentin): Temporary flag to avoid multiple nomination in parallel.
    nomination_in_progress: bool = false,

    /// The pair that has been selected.
    selected_pair: ?CandidatePair = null,

    /// Initializes a checklist.
    pub fn init() Checklist {
        return Checklist{
            .pairs = OrderedPairArray.init(),
            .valid_pairs = OrderedPairArray.init(),
        };
    }

    /// Returns the index of the pair in the given list of entries.
    fn indexOfPair(entries: []const CandidatePairEntry, candidate_pair: CandidatePair) ?usize {
        return for (entries, 0..) |entry, i| {
            if (entry.pair.eql(candidate_pair)) break i;
        } else null;
    }

    /// Returns true if the checklist contains the given pair.
    pub fn containsPair(self: *const Checklist, candidate_pair: CandidatePair) bool {
        return indexOfPair(self.pairs.slice(), candidate_pair) != null;
    }

    /// Returns true if the checklist contains the given pair in its valid list.
    pub fn containsValidPair(self: *const Checklist, candidate_pair: CandidatePair) bool {
        return indexOfPair(self.valid_pairs.slice(), candidate_pair) != null;
    }

    /// Adds the candidate pair and its associated data to the checklist.
    pub fn addPair(self: *Checklist, candidate_pair: CandidatePair, candidate_pair_data: CandidatePairData) !void {
        if (indexOfPair(self.pairs.slice(), candidate_pair) != null) return error.AlreadyExists;

        self.pairs.insert(.{ .pair = candidate_pair, .data = candidate_pair_data });
    }

    /// Removes the candidate pair from the checklist.
    pub fn removePair(self: *Checklist, candidate_pair: CandidatePair) !void {
        const index = indexOfPair(self.pairs.slice(), candidate_pair) orelse return error.NotFound;
        _ = self.pairs.remove(index);
    }

    /// Adds the pair and its associated data to the valid list of the checklist.
    pub fn addValidPair(self: *Checklist, candidate_pair: CandidatePair, candidate_pair_data: CandidatePairData) !void {
        if (indexOfPair(self.valid_pairs.slice(), candidate_pair) != null) return error.AlreadyExists;

        self.valid_pairs.insert(.{ .pair = candidate_pair, .data = candidate_pair_data });
    }

    /// Removez the pair from the valid list of the checklist.
    pub fn removeValidPair(self: *Checklist, candidate_pair: CandidatePair) !void {
        const index = indexOfPair(self.valid_pairs.slice(), candidate_pair) orelse return error.NotFound;

        _ = self.valid_pairs.remove(index);
    }

    /// Returns the number of pairs in the given state.
    inline fn getPairCount(self: *const Checklist, state: CandidatePairState) usize {
        var count: usize = 0;

        for (self.pairs.slice()) |entry| {
            if (entry.data.state == state) count += 1;
        }

        return count;
    }

    /// Returns a pointer to the CandidatePairEntry in the valid list corresponding to the given candidate pair, or null if there is none.
    pub fn getValidEntry(self: *Checklist, candidate_pair: CandidatePair) ?*CandidatePairEntry {
        const index = indexOfPair(self.valid_pairs.slice(), candidate_pair) orelse return null;
        return &self.valid_pairs.slice()[index];
    }

    /// Returns a pointer to the CandidatePairEntry corresponding to the given candidate pair, or null if there is none.
    fn getEntry(self: *Checklist, candidate_pair: CandidatePair) ?*CandidatePairEntry {
        const index = indexOfPair(self.pairs.slice(), candidate_pair) orelse return null;
        return &self.pairs.slice()[index];
    }

    /// Sets the state of the candidate pair to the given state.
    pub fn setPairState(self: *Checklist, candidate_pair: CandidatePair, state: CandidatePairState) void {
        const entry = self.getEntry(candidate_pair) orelse @panic("TODO: Unknown candidate pair");
        const old_state = entry.data.state;
        if (state != old_state) {
            log.debug("Pair {}:{} state changed from \"{s}\" to \"{s}\"", .{ candidate_pair.local_candidate_index, candidate_pair.remote_candidate_index, @tagName(old_state), @tagName(state) });
            entry.data.state = state;
        }
    }

    /// Updates the checklist state from the state of each candidate pair.
    pub fn updateState(self: *Checklist) void {
        const new_state: ChecklistState = b: {
            const has_nominated_pair_for_component = for (self.valid_pairs.slice()) |entry| {
                if (entry.data.state == .succeeded and entry.data.nominated) break true;
            } else false;

            if (has_nominated_pair_for_component) {
                break :b .completed;
            }

            const are_pairs_done = for (self.pairs.slice()) |entry| {
                if (entry.data.state != .succeeded and entry.data.state != .failed) break false;
            } else true;

            break :b if (are_pairs_done)
                .failed
            else
                .running;
        };

        if (new_state == .completed) {
            self.selected_pair = for (self.valid_pairs.slice()) |entry| {
                if (entry.data.nominated) break entry.pair;
            } else unreachable;
        }

        if (new_state != self.state) {
            log.debug("New Checklist state: {s} -> {s}", .{ @tagName(self.state), @tagName(new_state) });
            self.state = new_state;
        }
    }

    /// Recompute the pairs priorities using the given role.
    pub fn recomputePriorities(self: *Checklist, local_candidates: []const Candidate, remote_candidates: []const Candidate, role: AgentRole) void {
        for (self.pairs.slice()) |*entry| {
            const local_candidate = local_candidates[entry.pair.local_candidate_index];
            const remote_candidate = remote_candidates[entry.pair.remote_candidate_index];
            entry.data.priority = computePairPriority(local_candidate.priority, remote_candidate.priority, role);
        }

        const SortContext = struct {
            entries: []CandidatePairEntry,
            pub fn lessThan(ctx: @This(), a: usize, b: usize) bool {
                return ctx.entries[a].data.priority > ctx.entries[b].data.priority;
            }
            pub fn swap(ctx: @This(), a: usize, b: usize) void {
                std.mem.swap(CandidatePairEntry, &ctx.entries[a], &ctx.entries[b]);
            }
        };

        std.sort.heapContext(0, self.pairs.slice().len, SortContext{ .entries = self.pairs.slice() });
    }
};

/// Represents the context used in a connectivity check.
const ConnectivityCheckContext = struct {
    /// The socket associated with the check.
    socket_index: usize,
    /// The candidate pair associated with the check.
    candidate_pair: CandidatePair,

    /// Various flags used for bookkeeping.
    flags: packed struct {
        /// Is this check a triggered check.
        is_triggered_check: bool = false,
        /// Is this check a nomination.
        is_nomination: bool = false,
        /// Has this check been canceled.
        is_canceled: bool = false,
        /// What role had the agent when the check was queued.
        role: AgentRole = undefined,
    } = .{},

    /// The STUN transaction associated with the check.
    transaction: Transaction,
};

/// Represents the context used when gathering candidates.
const GatheringContext = struct {
    /// The socket used to gather the candidate.
    socket_index: usize,
    /// The index of the candidate in the local list of candidates.
    candidate_index: usize,

    /// The associated STUN transaction.
    transaction: Transaction,
};

/// Represents the type of operation associated with a STUN transaction.
const StunContextType = enum {
    /// The transaction is used to gather candidates.
    gathering,
    /// The transaction is used to perform a connectivity check.
    check,
};

/// Represents the context used when performing a connectivity check or when gathering candidates.
const StunContext = union(StunContextType) {
    gathering: GatheringContext,
    check: ConnectivityCheckContext,
};

/// An entry associated with a response that must be sent when possible.
const ResponseEntry = struct {
    /// The index of the socket in which we want to send the response.
    socket_index: usize,
    /// The transaction ID of the request associated with this response.
    transaction_id: u96,
    /// The source of the associated request.
    source: std.net.Address,
    /// Various flags.
    flags: packed struct {
        /// Did the associated request trigger a role conflict.
        role_conflict: bool,
    },
};

/// Represents the parameters used to authenticate STUN transaction.
pub const AuthParameters = struct {
    /// The fragment of the user attribute.
    username_fragment: []const u8,
    /// The password used for authentication.
    password: []const u8,

    /// The buffer storing the username fragment and buffer.
    storage: []const u8,

    /// Inits an AuthParameters by copying the given username fragment and password.
    pub fn initFrom(username_fragment: []const u8, password: []const u8, allocator: std.mem.Allocator) !AuthParameters {
        var storage = try allocator.alloc(u8, username_fragment.len + password.len);
        errdefer allocator.free(storage);

        @memcpy(storage[0..username_fragment.len], username_fragment);
        @memcpy(storage[username_fragment.len..], password);

        return AuthParameters{
            .username_fragment = storage[0..username_fragment.len],
            .password = storage[username_fragment.len..],
            .storage = storage,
        };
    }

    /// Generates random parameters using the given random object.
    pub inline fn random(rand: std.rand.Random, allocator: std.mem.Allocator) !AuthParameters {
        var buffer: [6 + 18]u8 = undefined;
        rand.bytes(&buffer);

        var base64_buffer = try allocator.alloc(u8, 8 + 24);
        var result = std.base64.standard.Encoder.encode(base64_buffer, &buffer);

        return .{
            .username_fragment = result[0..8],
            .password = result[8..32],
            .storage = base64_buffer,
        };
    }

    /// Deinit allocated auth parameters.
    pub fn deinit(self: AuthParameters, allocator: std.mem.Allocator) void {
        allocator.free(self.storage);
    }
};

/// Represents an entry in an array of STUN contexts.
/// The AgentContext stores a fixed array of entries that can be used to gather candidates or perform connectivity checks.
const StunContextEntry = struct {
    /// The transaction ID of the associated STUN transaction.
    transaction_id: u96,
    /// The context of the STUN transaction.
    stun_context: StunContext,

    /// Various flags.
    flags: packed struct {
        /// Is this entry currently in use.
        in_use: bool = false,
    } = .{},
};

/// Represents the context associated with an ICE agent.
/// This stores all the required data to handle all the lifecycle of an ICE agent.
pub const AgentContext = struct {
    /// The id of this agent.
    id: AgentId,

    /// The allocator used by the AgentContext.
    allocator: std.mem.Allocator,

    /// A reference to the associated zice.Context.
    context: *Context,

    /// The agent state.
    state: AgentState = .running,
    /// The agent role.
    role: ?AgentRole = null,

    /// The local authentication parameters used for connectivity checks.
    local_auth: AuthParameters,
    /// The remote authentication parameters used for connectivity checks.
    remote_auth: ?AuthParameters = null,
    /// Tiebreaker value.
    tiebreaker: u64,

    /// The list of local candidates.
    local_candidates: std.ArrayListUnmanaged(Candidate) = .{},
    /// The list of remote candidates.
    remote_candidates: std.ArrayListUnmanaged(Candidate) = .{},
    /// Have we received the remote candidates.
    has_remote_candidates: bool = false,

    /// A pool of buffer that can be used for network IO.
    buffer_pool: std.heap.MemoryPool([4096]u8),

    /// A fixed size array of STUN context entry that can be used to gather candidates or perform connectivity checks.
    stun_context_entries: *[64]StunContextEntry,

    /// Contexts for each bound sockets.
    socket_contexts: []SocketContext = &.{},

    // Gathering related fields.

    /// The timer that fires when a new candidate can be checked.
    gathering_main_timer: xev.Timer,
    /// The associated xev.Completion.
    gathering_main_timer_completion: xev.Completion = .{},
    /// The xev.Completion used to cancel the gathering timer.
    gathering_main_timer_cancel_completion: xev.Completion = .{},
    /// The agent gathering state.
    gathering_state: GatheringState = .idle,
    /// The gathering status of each server reflexive candidate.
    gathering_candidate_statuses: []CandidateGatheringStatus = &.{},

    // Connectivity checks related fields.

    /// The checklists used to check candidate pairs.
    checklist: Checklist,

    /// The timer that fires when a connectivity check needs to be done.
    connectivity_checks_timer: xev.Timer,
    /// The associated xev.Completion.
    connectivity_checks_timer_completion: xev.Completion = .{},
    /// The completion used to cancel the connectivity checks timer.
    connectivity_checks_timer_cancel_completion: xev.Completion = .{},

    /// Queue of response to send when ready.
    check_response_queue: *CircularBuffer(ResponseEntry, 64),
    check_response_queue_write_buffer: []u8 = &.{},
    check_response_queue_write_data: WriteData = .{},
    check_response_queue_write_completion: xev.Completion = .{},

    // NOTE(Corendos): ^ We could have one completion/buffer/data per socket.

    // Other fields.

    flags: packed struct {
        /// Has this agent been stopped.
        stopped: bool = false,
    } = .{},

    /// Userdata that is given back in callbacks.
    userdata: ?*anyopaque,
    /// Callbacks to call when a new candidate is found during gathering (or when there won't be any new candidates).
    on_candidate_callback: OnCandidateCallback,
    /// Callback to call when the gathering state changes.
    on_state_change_callback: OnStateChangeCallback,
    /// Callbacks to call when data is available.
    on_data_callback: OnDataCallback,

    /// The zice.Context event loop.
    loop: *xev.Loop,

    /// Initializes an agent.
    pub fn init(context: *Context, agent_id: AgentId, loop: *xev.Loop, options: CreateAgentOptions, allocator: std.mem.Allocator) !AgentContext {
        const auth_parameters = try AuthParameters.random(std.crypto.random, allocator);
        errdefer auth_parameters.deinit(allocator);
        const tiebreaker = std.crypto.random.int(u64);

        var gathering_main_timer = try xev.Timer.init();
        errdefer gathering_main_timer.deinit();
        var connectivity_checks_timer = try xev.Timer.init();
        errdefer connectivity_checks_timer.deinit();

        var buffer_pool = std.heap.MemoryPool([4096]u8).init(allocator);
        errdefer buffer_pool.deinit();

        var check_response_queue_write_buffer = try buffer_pool.create();
        errdefer buffer_pool.destroy(check_response_queue_write_buffer);

        const stun_context_entries = try allocator.create([64]StunContextEntry);
        errdefer allocator.destroy(stun_context_entries);
        @memset(stun_context_entries[0..], .{ .transaction_id = undefined, .stun_context = undefined });

        var checklist = Checklist.init();

        const check_response_queue = try allocator.create(CircularBuffer(ResponseEntry, 64));
        errdefer allocator.destroy(check_response_queue);
        check_response_queue.* = .{};

        return AgentContext{
            .id = agent_id,
            .allocator = allocator,
            .context = context,
            .gathering_main_timer = gathering_main_timer,
            .buffer_pool = buffer_pool,
            .stun_context_entries = stun_context_entries,
            .checklist = checklist,
            .connectivity_checks_timer = connectivity_checks_timer,
            .check_response_queue_write_buffer = check_response_queue_write_buffer,
            .local_auth = auth_parameters,
            .tiebreaker = tiebreaker,
            .check_response_queue = check_response_queue,
            .userdata = options.userdata,
            .on_candidate_callback = options.on_candidate_callback,
            .on_state_change_callback = options.on_state_change_callback,
            .on_data_callback = options.on_data_callback,
            .loop = loop,
        };
    }

    /// Stops the agent
    /// This will cancel any on-going operation.
    pub fn stop(self: *AgentContext) void {
        if (self.flags.stopped) return;
        self.flags.stopped = true;

        for (self.socket_contexts) |*ctx| {
            ctx.cancel(self.loop);
        }

        for (self.stun_context_entries) |*entry| {
            if (entry.flags.in_use) {
                switch (entry.stun_context) {
                    inline else => |*v| v.transaction.cancel(self.loop),
                }
            }
        }

        if (self.gathering_main_timer_completion.state() == .active) {
            self.gathering_main_timer.cancel(
                self.loop,
                &self.gathering_main_timer_completion,
                &self.gathering_main_timer_cancel_completion,
                AgentContext,
                self,
                mainTimerCancelCallback,
            );
        }

        if (self.connectivity_checks_timer_completion.state() == .active) {
            self.connectivity_checks_timer.cancel(
                self.loop,
                &self.connectivity_checks_timer_completion,
                &self.connectivity_checks_timer_cancel_completion,
                AgentContext,
                self,
                connectivityCheckTimerCancelCallback,
            );
        }
    }

    /// Returns true if the agent is done with all potential ongoing operations.
    pub fn done(self: *const AgentContext) bool {
        for (self.socket_contexts) |*ctx| if (ctx.read_completion.state() != .dead or ctx.read_cancel_completion.state() != .dead) return false;
        for (self.stun_context_entries) |*entry| if (entry.flags.in_use) return false;
        if (self.gathering_main_timer_completion.state() != .dead or self.gathering_main_timer_cancel_completion.state() != .dead) return false;
        if (self.connectivity_checks_timer_completion.state() != .dead or self.connectivity_checks_timer_cancel_completion.state() != .dead) return false;

        return true;
    }

    /// Deinitializes an agent.
    pub fn deinit(self: *AgentContext) void {
        std.debug.assert(self.done());

        self.local_auth.deinit(self.allocator);
        if (self.remote_auth) |remote_auth| {
            remote_auth.deinit(self.allocator);
        }

        self.gathering_main_timer.deinit();
        self.buffer_pool.deinit();
        self.allocator.destroy(self.stun_context_entries);

        self.connectivity_checks_timer.deinit();

        for (self.socket_contexts) |*ctx| ctx.deinit();
        self.allocator.free(self.socket_contexts);

        self.allocator.free(self.gathering_candidate_statuses);

        self.local_candidates.deinit(self.allocator);
        self.remote_candidates.deinit(self.allocator);

        self.allocator.destroy(self.check_response_queue);
    }

    /// Creates all the socket contexts associated with the given addresses.
    fn createSocketContexts(addresses: []const std.net.Address, allocator: std.mem.Allocator, buffer_pool: *std.heap.MemoryPool([4096]u8)) ![]SocketContext {
        var socket_context_list = try std.ArrayList(SocketContext).initCapacity(allocator, addresses.len);
        defer socket_context_list.deinit();

        errdefer for (socket_context_list.items) |*socket_context| {
            socket_context.deinit();
            buffer_pool.destroy(@alignCast(socket_context.read_buffer[0..4096]));
        };

        for (addresses, 0..) |address, index| {
            const read_buffer = try buffer_pool.create();
            errdefer buffer_pool.destroy(read_buffer);

            const socket_context = try SocketContext.init(index, address, read_buffer);

            socket_context_list.appendAssumeCapacity(socket_context);
        }

        return socket_context_list.toOwnedSlice() catch unreachable;
    }

    /// Starts any required operation to gather candidates.
    /// This should only be called by the zice Context.
    pub fn processGatherCandidates(self: *AgentContext) !void {
        // By default, assume that we are in the controlling role if we are explicitly asked to gather candidates.
        if (self.role == null) {
            self.role = .controlling;
        }

        const address_list = try self.context.getValidCandidateAddresses(self.allocator);
        defer self.allocator.free(address_list);

        self.socket_contexts = try createSocketContexts(address_list, self.allocator, &self.buffer_pool);
        errdefer for (self.socket_contexts) |*socket_context| {
            socket_context.deinit();
            self.buffer_pool.destroy(@alignCast(socket_context.read_buffer[0..4096]));
        };

        for (self.socket_contexts) |*socket_context| {
            socket_context.start(self.loop, self, readCallback);
        }
        errdefer for (self.socket_contexts) |*socket_context| {
            socket_context.cancel(self.loop);
        };

        self.gathering_state = .gathering;

        for (self.socket_contexts, 0..) |ctx, index| {
            const candidate = Candidate{
                .type = .host,
                .base_address = ctx.address,
                .transport_address = ctx.address,
                .foundation = Foundation{
                    .type = .host,
                    // TODO(Corentin): When supported, get that from the socket.
                    .protocol = .udp,
                    .address_index = @intCast(index),
                },
            };
            self.local_candidates.append(self.allocator, candidate) catch unreachable;
            self.on_candidate_callback(self.userdata, self, .{ .candidate = candidate });
        }

        self.gathering_candidate_statuses = try self.allocator.alloc(CandidateGatheringStatus, self.socket_contexts.len);
        errdefer self.allocator.free(self.gathering_candidate_statuses);
        @memset(self.gathering_candidate_statuses, .new);

        self.gathering_main_timer.run(
            self.loop,
            &self.gathering_main_timer_completion,
            Configuration.new_transaction_interval_ms,
            AgentContext,
            self,
            mainTimerCallback,
        );
    }

    /// Sets the remote candidates and starts any required operations.
    /// This should only be called by the zice Context.
    fn processSetRemoteCandidates(self: *AgentContext, parameters: RemoteCandidateParameters) !void {
        try self.remote_candidates.appendSlice(self.allocator, parameters.candidates);
        self.remote_auth = try AuthParameters.initFrom(parameters.username_fragment, parameters.password, self.allocator);
        self.has_remote_candidates = true;

        // If we don't have a role yet, we can assume that the other agent is the controlling one.
        if (self.role == null) {
            self.role = .controlled;
        }

        switch (self.role.?) {
            .controlling => {
                if (self.gathering_state == .done) {
                    self.startChecks();
                }
            },
            .controlled => {
                try self.processGatherCandidates();
            },
        }
    }

    /// Starts any required operation to send the given message to the other agents.
    /// This should only be called by the zice Context.
    fn processSend(self: *AgentContext, completion: *ContextCompletion) !void {
        if (self.checklist.selected_pair) |selected_pair| {
            const local_candidate = self.local_candidates.items[selected_pair.local_candidate_index];
            const remote_candidate = self.remote_candidates.items[selected_pair.remote_candidate_index];

            const socket_context = self.socket_contexts[self.getSocketContextIndexFromAddress(local_candidate.base_address).?];

            const parameters = &completion.op.send;

            parameters.write_data.from(remote_candidate.transport_address, parameters.data);
            parameters.write_completion = xev.Completion{
                .op = .{
                    .sendmsg = .{
                        .fd = socket_context.socket,
                        .msghdr = &parameters.write_data.message_header,
                        .buffer = null,
                    },
                },
                .userdata = completion,
                .callback = (struct {
                    pub fn callback(
                        userdata: ?*anyopaque,
                        inner_loop: *xev.Loop,
                        inner_c: *xev.Completion,
                        inner_result: xev.Result,
                    ) xev.CallbackAction {
                        _ = inner_c;
                        _ = inner_loop;
                        const inner_completion: *ContextCompletion = @ptrCast(@alignCast(userdata.?));
                        const result: SendError!usize = inner_result.sendmsg catch |err| err;
                        inner_completion.callback(inner_completion.userdata, .{ .send = result });
                        return .disarm;
                    }
                }).callback,
            };

            // TODO(Corendos): hide implementation details
            if (xev.backend == .epoll) {
                parameters.write_completion.flags.dup = true;
            }

            self.loop.add(&parameters.write_completion);
        } else {
            completion.callback(completion.userdata, ContextResult{ .send = error.NotReady });
        }
    }

    /// Starts connectivity checks.
    fn startChecks(
        self: *AgentContext,
    ) void {
        self.printCandidates();
        self.computeCandidatePairs() catch unreachable;
        self.computeInitialCandidatePairsState();
        self.printPairStates();

        self.handleConnectivityCheckMainTimer({}) catch unreachable;
    }

    inline fn getSocketContextIndexFromAddress(self: *AgentContext, address: std.net.Address) ?usize {
        return for (self.socket_contexts, 0..) |ctx, i| {
            if (ctx.address.eql(address)) break i;
        } else null;
    }

    inline fn getLocalCandidateIndexFromTransportAddress(self: *const AgentContext, address: std.net.Address) ?usize {
        return for (self.local_candidates.items, 0..) |c, i| {
            if (c.transport_address.eql(address)) break i;
        } else null;
    }

    inline fn getRemoteCandidateIndexFromTransportAddress(self: *const AgentContext, address: std.net.Address) ?usize {
        return for (self.remote_candidates.items, 0..) |c, i| {
            if (c.transport_address.eql(address)) break i;
        } else null;
    }

    /// Returns true if the gathering is done and we can call the callback with a valid result.
    fn isGatheringDone(self: *const AgentContext) bool {
        return self.gathering_main_timer_completion.state() == .dead and for (self.gathering_candidate_statuses) |status| {
            if (status != .done and status != .failed) break false;
        } else true;
    }

    /// Return the index of a candidate that has not been checked yet or null.
    inline fn getUncheckedCandidateIndex(self: *const AgentContext) ?usize {
        return for (self.gathering_candidate_statuses, 0..) |s, i| {
            if (s == .new) break i;
        } else null;
    }

    /// Computes the priority of every local candidate.
    fn computePriorities(self: *AgentContext) void {
        // TODO(Corendos): Handle component ID as well.

        var arena_state = std.heap.ArenaAllocator.init(self.allocator);
        defer arena_state.deinit();

        const candidate_type_count = std.meta.tags(CandidateType).len;
        var candidate_lists_per_type: [candidate_type_count * 2]std.ArrayList(usize) = undefined;
        for (&candidate_lists_per_type) |*list| list.* = std.ArrayList(usize).initCapacity(arena_state.allocator(), self.local_candidates.items.len) catch unreachable;

        for (self.local_candidates.items, 0..) |candidate, i| {
            const address_family = candidate.transport_address.any.family;
            const address_index: usize = if (address_family == std.os.AF.INET) 0 else if (address_family == std.os.AF.INET6) 1 else unreachable;
            candidate_lists_per_type[@intFromEnum(candidate.type) * 2 + address_index].appendAssumeCapacity(i);
        }

        // Consider each candidate type separately to assign local_preference.
        for (std.meta.tags(CandidateType)) |candidate_type| {
            var current_local_preference: u16 = 32768;

            const candidate_type_index: usize = @intFromEnum(candidate_type);

            var ipv4_index: usize = 0;
            var ipv4_candidate_indices = candidate_lists_per_type[candidate_type_index * 2];

            var ipv6_index: usize = 0;
            var ipv6_candidate_indices = candidate_lists_per_type[candidate_type_index * 2 + 1];

            var counter: usize = 0;

            // Try to alternate between IPv6 and IPv4 candidates.
            while (ipv4_index < ipv4_candidate_indices.items.len or ipv6_index < ipv6_candidate_indices.items.len) : (counter += 1) {
                const candidate_index = b: {
                    if (counter % 2 == 0) {
                        if (ipv6_index < ipv6_candidate_indices.items.len) {
                            defer ipv6_index += 1;
                            break :b ipv6_candidate_indices.items[ipv6_index];
                        } else {
                            defer ipv4_index += 1;
                            break :b ipv4_candidate_indices.items[ipv4_index];
                        }
                    } else {
                        if (ipv4_index < ipv4_candidate_indices.items.len) {
                            defer ipv4_index += 1;
                            break :b ipv4_candidate_indices.items[ipv4_index];
                        } else {
                            defer ipv6_index += 1;
                            break :b ipv6_candidate_indices.items[ipv6_index];
                        }
                    }
                };

                const candidate = &self.local_candidates.items[candidate_index];

                candidate.priority = computePriority(candidate.type.preference(), current_local_preference, candidate.component_id);
                current_local_preference -= 128;
            }
        }
    }

    /// Remove redundant local candidates.
    fn removeRedundantCandidates(self: *AgentContext) void {
        var current_index: usize = 0;
        while (current_index < self.local_candidates.items.len - 1) : (current_index += 1) {
            const current_candidate: Candidate = self.local_candidates.items[current_index];

            var other_index: usize = current_index + 1;
            while (other_index < self.local_candidates.items.len) {
                const other_candidate: Candidate = self.local_candidates.items[other_index];

                const have_same_base_address = current_candidate.base_address.eql(other_candidate.base_address);
                const have_same_transport_address = current_candidate.transport_address.eql(other_candidate.transport_address);
                if (have_same_base_address and have_same_transport_address) {
                    if (current_candidate.priority < other_candidate.priority) {
                        std.mem.swap(Candidate, &self.local_candidates.items[current_index], &self.local_candidates.items[other_index]);
                    }
                    _ = self.local_candidates.swapRemove(other_index);
                    continue;
                }

                other_index += 1;
            }
        }
    }

    /// Form candidate pairs.
    fn formPairs(local_candidates: []const Candidate, remote_candidates: []const Candidate, allocator: std.mem.Allocator) !std.ArrayList(CandidatePair) {
        var pair_list = std.ArrayList(CandidatePair).init(allocator);
        errdefer pair_list.deinit();

        for (local_candidates, 0..) |local_candidate, i| {
            const local_component_id = local_candidate.component_id;
            const local_address_family = local_candidate.transport_address.any.family;
            for (remote_candidates, 0..) |remote_candidate, j| {
                const remote_component_id = remote_candidate.component_id;
                const remote_address_family = remote_candidate.transport_address.any.family;
                if (local_component_id == remote_component_id and local_address_family == remote_address_family) {
                    const candidate_pair = CandidatePair{ .local_candidate_index = i, .remote_candidate_index = j };
                    try pair_list.append(candidate_pair);
                }
            }
        }

        return pair_list;
    }

    /// Sort pairs based on the priority of the associated candidates.
    fn sortPairs(pairs: []CandidatePair, local_candidates: []const Candidate, remote_candidates: []const Candidate, role: AgentRole) void {
        // Sort pairs in decreasing order of priority.
        const SortContext = struct {
            local_candidates: []const Candidate,
            remote_candidates: []const Candidate,
            agent_role: AgentRole,
            ordered_pairs: []CandidatePair,

            pub fn lessThan(ctx: @This(), a: usize, b: usize) bool {
                const candidate_pair_a = ctx.ordered_pairs[a];
                const candidate_pair_b = ctx.ordered_pairs[b];

                const priority_a = computePairPriority(ctx.local_candidates[candidate_pair_a.local_candidate_index].priority, ctx.remote_candidates[candidate_pair_a.remote_candidate_index].priority, ctx.agent_role);
                const priority_b = computePairPriority(ctx.local_candidates[candidate_pair_b.local_candidate_index].priority, ctx.remote_candidates[candidate_pair_b.remote_candidate_index].priority, ctx.agent_role);

                return priority_a > priority_b;
            }

            pub fn swap(ctx: @This(), a: usize, b: usize) void {
                std.mem.swap(CandidatePair, &ctx.ordered_pairs[a], &ctx.ordered_pairs[b]);
            }
        };

        std.sort.heapContext(0, pairs.len, SortContext{
            .local_candidates = local_candidates,
            .remote_candidates = remote_candidates,
            .agent_role = role,
            .ordered_pairs = pairs,
        });
    }

    /// Prune pairs by removing redundant ones.
    fn prunePairs(pair_list: *std.ArrayList(CandidatePair), local_candidates: []const Candidate, remote_candidates: []const Candidate, role: AgentRole) void {
        // Replace reflexive candidate with their base as per https://www.rfc-editor.org/rfc/rfc8445#section-6.1.2.4.
        for (pair_list.items) |*candidate_pair| {
            const local_candidate = local_candidates[candidate_pair.local_candidate_index];

            if (local_candidate.type == .server_reflexive) {
                const new_local_candidate_index = for (local_candidates, 0..) |*c, i| {
                    if (c.type == .host and c.transport_address.eql(local_candidate.base_address)) break i;
                } else unreachable;
                candidate_pair.local_candidate_index = new_local_candidate_index;
            }
        }

        // Remove redundant pairs as per https://www.rfc-editor.org/rfc/rfc8445#section-6.1.2.4.
        var current_index: usize = 0;
        while (current_index < pair_list.items.len - 1) : (current_index += 1) {
            const current_candidate_pair = pair_list.items[current_index];
            const current_candidate_pair_priority = computePairPriority(local_candidates[current_candidate_pair.local_candidate_index].priority, remote_candidates[current_candidate_pair.remote_candidate_index].priority, role);

            const current_local_candidate_index = current_candidate_pair.local_candidate_index;
            const current_local_candidate = local_candidates[current_local_candidate_index];
            const current_remote_candidate_index = current_candidate_pair.remote_candidate_index;

            var other_index: usize = current_index + 1;
            while (other_index < pair_list.items.len) {
                const other_candidate_pair = pair_list.items[other_index];
                const other_candidate_pair_priority = computePairPriority(local_candidates[other_candidate_pair.local_candidate_index].priority, remote_candidates[other_candidate_pair.remote_candidate_index].priority, role);
                const other_local_candidate_index = other_candidate_pair.local_candidate_index;
                const other_local_candidate = local_candidates[other_local_candidate_index];
                const other_remote_candidate_index = other_candidate_pair.remote_candidate_index;

                const have_same_local_candidate_base = std.net.Address.eql(current_local_candidate.base_address, other_local_candidate.base_address);
                const have_same_remote_candidate = current_remote_candidate_index == other_remote_candidate_index;

                if (have_same_local_candidate_base and have_same_remote_candidate) {
                    // The list should already be ordered. Otherwise, something is wrong.
                    std.debug.assert(current_candidate_pair_priority >= other_candidate_pair_priority);

                    // Remove lower priority redundant pairs but keep ordering.
                    _ = pair_list.orderedRemove(other_index);

                    continue;
                }

                other_index += 1;
            }
        }
    }

    /// Computes the candidate pairs.
    fn computeCandidatePairs(self: *AgentContext) !void {
        var pair_list = try formPairs(self.local_candidates.items, self.remote_candidates.items, self.allocator);
        defer pair_list.deinit();

        sortPairs(pair_list.items, self.local_candidates.items, self.remote_candidates.items, self.role.?);

        prunePairs(&pair_list, self.local_candidates.items, self.remote_candidates.items, self.role.?);

        if (pair_list.items.len > Configuration.candidate_pair_limit) {
            try pair_list.resize(Configuration.candidate_pair_limit);
        }

        var checklist = Checklist.init();

        for (pair_list.items) |candidate_pair| {
            checklist.addPair(candidate_pair, self.makeCandidatePairData(candidate_pair)) catch {};
        }

        self.checklist = checklist;
    }

    fn makeCandidatePairData(self: *const AgentContext, candidate_pair: CandidatePair) CandidatePairData {
        const local_candidate = &self.local_candidates.items[candidate_pair.local_candidate_index];
        const remote_candidate = &self.remote_candidates.items[candidate_pair.remote_candidate_index];

        const g = if (self.role == .controlling) local_candidate.priority else remote_candidate.priority;
        const d = if (self.role == .controlled) local_candidate.priority else remote_candidate.priority;
        return CandidatePairData{
            .priority = (@as(u64, @min(g, d)) << 32) + (@as(u64, @max(g, d) << 1)) + @as(u64, if (g > d) 1 else 0),
            .foundation = CandidatePairFoundation{ .local = local_candidate.foundation, .remote = remote_candidate.foundation },
        };
    }

    fn computeInitialCandidatePairsState(self: *AgentContext) void {
        var arena_state = std.heap.ArenaAllocator.init(self.allocator);
        defer arena_state.deinit();

        var foundation_map = std.AutoHashMap(CandidatePairFoundation, CandidatePair).init(arena_state.allocator());

        for (self.checklist.pairs.slice()) |entry| {
            // Compute pair foundation
            const local_candidate = self.local_candidates.items[entry.pair.local_candidate_index];

            // Get hash map entry if it exists.
            const gop = foundation_map.getOrPut(entry.data.foundation) catch unreachable;

            if (!gop.found_existing) {
                // If it doesn't exist yet, we store this pair as the one that will be put in the Waiting state.
                gop.value_ptr.* = entry.pair;
            } else {
                // Otherwise, we compare the component IDs and/or priorities to select the one that will be put in the Waiting state.
                const stored_candidate_pair = gop.value_ptr.*;
                const stored_local_candidate = self.local_candidates.items[stored_candidate_pair.local_candidate_index];

                const has_lower_component_id = local_candidate.component_id < stored_local_candidate.component_id;
                const has_higher_priority = local_candidate.component_id == stored_local_candidate.component_id and local_candidate.priority > stored_local_candidate.priority;
                if (has_lower_component_id or has_higher_priority) {
                    gop.value_ptr.* = entry.pair;
                }
            }
        }

        var it = foundation_map.iterator();
        while (it.next()) |entry| {
            const candidate_pair = entry.value_ptr.*;
            self.checklist.setPairState(candidate_pair, .waiting);
        }
    }

    /// Returns the candidate pair in "waiting" state with the highest priority and lowest component ID, or null if there is none.
    fn getWaitingPair(self: *AgentContext) ?CandidatePair {
        var result: ?CandidatePair = null;

        var max_priority: u64 = 0;
        var min_component_id: u8 = 255;
        for (self.checklist.pairs.slice()) |entry| {
            if (entry.data.state != .waiting) continue;

            const component_id = self.local_candidates.items[entry.pair.local_candidate_index].component_id;
            if (result != null) {
                // If the next candidate pair has a lower priority, no need to go further as they should be ordered and every pairs after
                // this one will have a lower priority as well.
                if (entry.data.priority < max_priority) break;
                std.debug.assert(entry.data.priority == max_priority);
                if (component_id < min_component_id) {
                    result = entry.pair;
                    min_component_id = component_id;
                }
            } else {
                result = entry.pair;
                min_component_id = component_id;
                max_priority = entry.data.priority;
            }
        }

        return result;
    }

    /// Tries to unfreeze a candidate pair.
    fn unfreezePair(self: *AgentContext) void {
        pair: for (self.checklist.pairs.slice()) |entry| {
            if (entry.data.state != .frozen) continue;

            for (self.checklist.pairs.slice()) |other_entry| {
                if (entry.pair.eql(other_entry.pair)) continue;

                const have_same_foundation = entry.data.foundation.eql(other_entry.data.foundation);
                const other_state = other_entry.data.state;
                if ((other_state == .waiting or other_state == .in_progress) and have_same_foundation) continue :pair;
            }

            // If we are here, we didn't find another pair with the same foundation in the waiting or in_progress state.
            self.checklist.setPairState(entry.pair, .waiting);
            return;
        }
    }

    pub fn releaseStunContext(self: *AgentContext, stun_context: *StunContext) void {
        for (self.stun_context_entries) |*entry| {
            if (&entry.stun_context == stun_context) {
                switch (entry.stun_context) {
                    inline else => |*ctx| {
                        self.buffer_pool.destroy(@alignCast(ctx.transaction.write_buffer[0..4096]));
                        self.buffer_pool.destroy(@alignCast(ctx.transaction.read_buffer[0..4096]));
                        ctx.transaction.deinit();
                    },
                }
                entry.flags.in_use = false;
                return;
            }
        }
    }

    pub fn handleNomination(self: *AgentContext, candidate_pair: CandidatePair, loop: *xev.Loop) void {
        const nominated_entry = self.checklist.getValidEntry(candidate_pair) orelse @panic("TODO: Nominated a candidate pair that is not in the valid list yet");
        log.debug("Agent {} - Candidate pair {}:{} nominated", .{ self.id, candidate_pair.local_candidate_index, candidate_pair.remote_candidate_index });
        nominated_entry.data.nominated = true;

        const valid_local_candidate = self.local_candidates.items[candidate_pair.local_candidate_index];

        if (self.checklist.state == .running) {
            // Remove pairs with same component ID from the triggered_check_queue.
            var index: usize = 0;
            while (index < self.checklist.triggered_check_queue.count()) {
                const current = self.checklist.triggered_check_queue.get(index);
                const current_local_candidate = self.local_candidates.items[current.candidate_pair.local_candidate_index];
                if (current_local_candidate.component_id == valid_local_candidate.component_id) {
                    _ = self.checklist.triggered_check_queue.orderedRemove(index);
                    continue;
                }
                index += 1;
            }

            // Remove pairs with same component ID from the checklist.
            index = 0;
            while (index < self.checklist.pairs.slice().len) {
                const current_entry = &self.checklist.pairs.slice()[index];

                const current_local_candidate = self.local_candidates.items[current_entry.pair.local_candidate_index];

                if (!current_entry.pair.eql(candidate_pair) and current_local_candidate.component_id == valid_local_candidate.component_id) {
                    // Cancel in-progress transaction for the removed entry.
                    for (self.stun_context_entries) |*entry| {
                        if (!entry.flags.in_use) continue;
                        if (entry.stun_context != .check) continue;
                        const check_context = &entry.stun_context.check;
                        if (check_context.candidate_pair.eql(current_entry.pair)) {
                            check_context.transaction.stopRetransmits(loop);
                            check_context.flags.is_canceled = true;
                        }
                    }

                    _ = self.checklist.pairs.remove(index);

                    continue;
                }

                index += 1;
            }
        }
    }

    pub inline fn setState(self: *AgentContext, new_state: AgentState) void {
        const old_state = self.state;
        if (new_state != old_state) {
            log.debug("Agent {} - State changed from \"{s}\" to \"{s}\"", .{ self.id, @tagName(old_state), @tagName(new_state) });
            self.state = new_state;
            self.on_state_change_callback(self.userdata, self, new_state);
        }
    }

    /// Single entrypoint for all gathering related events (STUN message received, transaction completed or main timer fired).
    /// The rationale to have a single function instead of multiple callback is that it makes it easier to know exactly when the gathering is done.
    fn handleGatheringEvent(
        self: *AgentContext,
        result: GatheringEventResult,
    ) void {
        std.debug.assert(self.gathering_state != .done);

        switch (result) {
            .read => |r| {
                const gathering_context = &r.stun_context.gathering;
                self.handleGatheringResponseRead(gathering_context, r.raw_message) catch @panic("TODO");
            },
            .completed => |r| {
                const gathering_context = &r.stun_context.gathering;
                self.handleGatheringTransactionCompleted(gathering_context, r.result);
                self.releaseStunContext(r.stun_context);
            },
            .main_timer => |r| self.handleGatheringMainTimer(r),
        }

        if (!self.isGatheringDone()) return;

        self.gathering_state = .done;

        self.computePriorities();
        self.removeRedundantCandidates();

        // Select the first server reflexive candidate to be the default candidate.
        for (self.local_candidates.items) |*candidate| {
            if (candidate.type == .server_reflexive) {
                candidate.default = true;
                break;
            }
        }

        self.on_candidate_callback(self.userdata, self, .{ .done = {} });

        if (self.has_remote_candidates) {
            self.startChecks();
        }
    }

    fn handleGatheringResponseRead(
        self: *AgentContext,
        gathering_context: *GatheringContext,
        raw_message: []const u8,
    ) !void {
        if (self.gathering_candidate_statuses[gathering_context.candidate_index] != .checking) return;

        const candidate = self.local_candidates.items[gathering_context.candidate_index];
        log.debug("Agent {} - Received STUN response for base address \"{}\"", .{ self.id, candidate.base_address });

        gathering_context.transaction.readCallback(self.loop, raw_message, undefined);
    }

    fn handleGatheringTransactionCompleted(
        self: *AgentContext,
        gathering_context: *GatheringContext,
        result: TransactionResult,
    ) void {
        const host_candidate = self.local_candidates.items[gathering_context.candidate_index];

        const payload = result catch |err| {
            self.gathering_candidate_statuses[gathering_context.candidate_index] = .failed;
            log.debug("Agent {} - Gathering failed with {} for base address \"{}\"", .{ self.id, err, host_candidate.base_address });
            return;
        };

        var buffer: [4096]u8 = undefined;
        const message = b: {
            var arena_state = std.heap.FixedBufferAllocator.init(&buffer);
            var stream = std.io.fixedBufferStream(payload.raw_message);
            var reader = stream.reader();
            break :b ztun.Message.readAlloc(reader, arena_state.allocator()) catch unreachable;
        };

        if (getMappedAddressFromStunMessage(message)) |transport_address| {
            const candidate = Candidate{
                .type = .server_reflexive,
                .transport_address = transport_address,
                .base_address = host_candidate.base_address,
                .foundation = Foundation{
                    .type = .server_reflexive,
                    // TODO(Corentin): When supported, get that from the socket.
                    .protocol = .udp,
                    .address_index = @intCast(gathering_context.candidate_index),
                },
            };
            self.local_candidates.append(self.allocator, candidate) catch unreachable;
            self.on_candidate_callback(self.userdata, self, .{ .candidate = candidate });
        }

        self.gathering_candidate_statuses[gathering_context.candidate_index] = .done;
        log.debug("Agent {} - Gathering done for base address \"{}\"", .{ self.id, host_candidate.base_address });
    }

    fn getFreeStunContextEntry(self: *AgentContext) ?*StunContextEntry {
        const entry = for (self.stun_context_entries) |*entry| {
            if (!entry.flags.in_use) break entry;
        } else return null;
        entry.flags.in_use = true;
        return entry;
    }

    fn getStunContextEntryFromTransactionId(self: *AgentContext, transaction_id: u96) ?*StunContextEntry {
        return for (self.stun_context_entries) |*entry| {
            if (entry.flags.in_use and entry.transaction_id == transaction_id) break entry;
        } else null;
    }

    fn handleGatheringMainTimer(self: *AgentContext, result: xev.Timer.RunError!void) void {
        _ = result catch |err| {
            if (err == error.Canceled and self.flags.stopped) return;
            log.err("{}", .{err});
            @panic("TODO");
        };

        // Get a candidate still in the .new state or disarm the timer.
        const candidate_index = self.getUncheckedCandidateIndex() orelse return;
        const socket_context = &self.socket_contexts[candidate_index];

        const address = switch (socket_context.address.any.family) {
            std.os.AF.INET => Configuration.stun_address_ipv4,
            std.os.AF.INET6 => Configuration.stun_address_ipv6,
            else => unreachable,
        };
        var buffer: [4096]u8 = undefined;
        const request = r: {
            var allocator = std.heap.FixedBufferAllocator.init(&buffer);
            break :r makeBasicBindingRequest(allocator.allocator(), null) catch unreachable;
        };

        const stun_context_entry = self.getFreeStunContextEntry() orelse unreachable;

        const write_buffer = self.buffer_pool.create() catch unreachable;
        errdefer self.buffer_pool.destroy(write_buffer);

        const read_buffer = self.buffer_pool.create() catch unreachable;
        errdefer self.buffer_pool.destroy(read_buffer);

        const transaction = Transaction.init(
            socket_context.socket,
            address,
            request,
            write_buffer,
            read_buffer,
            self,
            gatheringTransactionCompleteCallback,
        );
        errdefer transaction.deinit();

        stun_context_entry.transaction_id = request.transaction_id;
        stun_context_entry.stun_context = .{
            .gathering = .{
                .socket_index = candidate_index,
                .candidate_index = candidate_index,
                .transaction = transaction,
            },
        };

        log.debug("Agent {} - Starting transaction for base address \"{}\"", .{ self.id, socket_context.address });
        stun_context_entry.stun_context.gathering.transaction.start(
            Configuration.computeRtoGatheringMs(self.socket_contexts.len),
            self.loop,
        );

        // Set the candidate in the .checking state
        self.gathering_candidate_statuses[candidate_index] = .checking;

        // NOTE(Corendos): Small improvement could be done here. If we now that there won't be any new candidates the next time we go through this function,
        //                 we could avoid one main timer delay.
        if (!self.flags.stopped) {
            self.gathering_main_timer.run(
                self.loop,
                &self.gathering_main_timer_completion,
                Configuration.new_transaction_interval_ms,
                AgentContext,
                self,
                mainTimerCallback,
            );
        }
    }

    fn handleConnectivityCheckEvent(self: *AgentContext, result: ConnectivityCheckEventResult) void {
        switch (result) {
            .request_read => |payload| {
                const socket_context = &self.socket_contexts[payload.socket_context_index];
                self.handleConnectivityCheckRequestRead(payload.raw_message, payload.address, socket_context) catch @panic("TODO: Request Read failed");
            },
            .response_write => {
                log.debug("Agent {} - Stun response sent !", .{self.id});
            },
            .response_read => |payload| {
                self.handleConnectivityCheckResponseRead(payload.raw_message, payload.address, payload.stun_context) catch @panic("TODO: Response read failed");
            },
            .completed => |payload| {
                self.handleConnectivityCheckTransactionCompleted(payload.stun_context, payload.result) catch @panic("TODO: Transaction completed failed");

                self.releaseStunContext(payload.stun_context);
                self.checklist.updateState();
            },
            .main_timer => |payload| {
                self.handleConnectivityCheckMainTimer(payload) catch @panic("TODO: Main timer failed");
            },
        }

        // Handle response sending if required.
        if (self.check_response_queue_write_completion.state() != .active) {
            self.handleQueuedResponse();
        }

        if (result == .request_read or result == .completed) {
            self.printPairStates();
            self.printValidList();
        }

        // TODO(Corendos): handle multiple checklists.
        if (self.checklist.state == .completed) {
            self.setState(.completed);
            if (self.connectivity_checks_timer_completion.state() == .active and self.connectivity_checks_timer_cancel_completion.state() == .dead) {
                self.connectivity_checks_timer.cancel(
                    self.loop,
                    &self.connectivity_checks_timer_completion,
                    &self.connectivity_checks_timer_cancel_completion,
                    AgentContext,
                    self,
                    connectivityCheckTimerCancelCallback,
                );
            }
        }
    }

    fn readCallback(
        userdata: ?*anyopaque,
        loop: *xev.Loop,
        c: *xev.Completion,
        result: xev.Result,
    ) xev.CallbackAction {
        _ = loop;

        const self = @as(*AgentContext, @ptrCast(@alignCast(userdata.?)));
        const socket_context = @fieldParentPtr(SocketContext, "read_completion", c);
        const socket_context_index = socket_context.index;

        const bytes_read = result.recvmsg catch |err| {
            if (err == error.Canceled and self.flags.stopped) return .disarm;
            log.err("Agent {} - Got {} for base address \"{}\" while reading from socket", .{ self.id, err, socket_context.address });
            return if (self.flags.stopped) .disarm else .rearm;
        };

        const data = socket_context.read_buffer[0..bytes_read];
        const source = socket_context.read_data.address;

        const stun_header_result = b: {
            var stream = std.io.fixedBufferStream(data);
            var reader = stream.reader();
            break :b ztun.Message.readHeader(reader);
        };

        if (stun_header_result) |stun_header| {
            switch (stun_header.type.class) {
                .request => {
                    self.handleConnectivityCheckEvent(.{ .request_read = .{ .socket_context_index = socket_context_index, .raw_message = data, .address = source } });
                },
                .indication => @panic("An indication, really ?"),
                else => {
                    const stun_context_entry_opt = self.getStunContextEntryFromTransactionId(stun_header.transaction_id);

                    if (stun_context_entry_opt) |stun_context_entry| {
                        switch (stun_context_entry.stun_context) {
                            .gathering => self.handleGatheringEvent(.{ .read = .{ .stun_context = &stun_context_entry.stun_context, .raw_message = data } }),
                            .check => self.handleConnectivityCheckEvent(.{ .response_read = .{ .stun_context = &stun_context_entry.stun_context, .raw_message = data, .address = source } }),
                        }
                    } else {
                        log.debug("Agent {} - Received STUN response with unknown transaction ID", .{self.id});
                    }
                },
            }
            return if (self.flags.stopped) .disarm else .rearm;
        } else |_| {}

        // TODO(Corendos): handle other type of messages
        if (self.checklist.selected_pair) |selected_pair| {
            const remote_candidate = self.remote_candidates.items[selected_pair.remote_candidate_index];
            if (remote_candidate.transport_address.eql(source)) {
                self.on_data_callback(self.userdata, self, remote_candidate.component_id, data);
            }
        } else {
            log.debug("Agent {} - Received data but no pair has been selected yet.", .{self.id});
        }

        return if (self.flags.stopped) .disarm else .rearm;
    }

    fn gatheringTransactionCompleteCallback(userdata: ?*anyopaque, transaction: *Transaction, result: TransactionResult) void {
        const self = @as(*AgentContext, @ptrCast(@alignCast(userdata.?)));
        const stun_context_entry = self.getStunContextEntryFromTransactionId(transaction.transaction_id) orelse unreachable;

        self.handleGatheringEvent(.{ .completed = .{ .stun_context = &stun_context_entry.stun_context, .result = result } });
    }

    fn mainTimerCallback(
        userdata: ?*AgentContext,
        loop: *xev.Loop,
        c: *xev.Completion,
        result: xev.Timer.RunError!void,
    ) xev.CallbackAction {
        _ = c;
        _ = loop;
        const self = userdata.?;

        self.handleGatheringEvent(.{ .main_timer = result });

        return .disarm;
    }

    fn mainTimerCancelCallback(
        userdata: ?*AgentContext,
        loop: *xev.Loop,
        c: *xev.Completion,
        result: xev.CancelError!void,
    ) xev.CallbackAction {
        _ = result catch {};
        _ = c;
        _ = userdata;
        _ = loop;

        return .disarm;
    }

    fn handleQueuedResponse(self: *AgentContext) void {
        // Ensure we are not already waiting for a completion.
        std.debug.assert(self.check_response_queue_write_completion.state() == .dead);

        const response_entry = self.check_response_queue.pop() orelse return;

        var buffer: [4096]u8 = undefined;
        const response = r: {
            var arena_state = std.heap.FixedBufferAllocator.init(&buffer);
            if (response_entry.flags.role_conflict) {
                break :r makeRoleConflictResponse(response_entry.transaction_id, self.local_auth.password, arena_state.allocator()) catch unreachable;
            } else {
                break :r makeBindingResponse(response_entry.transaction_id, response_entry.source, self.local_auth.password, arena_state.allocator()) catch unreachable;
            }
        };

        const data = d: {
            var stream = std.io.fixedBufferStream(self.check_response_queue_write_buffer);
            response.write(stream.writer()) catch unreachable;
            break :d stream.getWritten();
        };

        self.check_response_queue_write_data.from(response_entry.source, data);

        const socket_context = &self.socket_contexts[response_entry.socket_index];
        self.check_response_queue_write_completion = xev.Completion{
            .op = .{
                .sendmsg = .{
                    .fd = socket_context.socket,
                    .msghdr = &self.check_response_queue_write_data.message_header,
                    .buffer = null,
                },
            },
            .userdata = self,
            .callback = connectivityCheckResponseWriteCallback,
        };

        // TODO(Corendos): Hide implementation details
        if (xev.backend == .epoll) {
            self.check_response_queue_write_completion.flags.dup = true;
        }

        self.loop.add(&self.check_response_queue_write_completion);
    }

    fn connectivityCheckTimerCallback(
        userdata: ?*AgentContext,
        loop: *xev.Loop,
        c: *xev.Completion,
        result: xev.Timer.RunError!void,
    ) xev.CallbackAction {
        _ = c;
        _ = loop;

        const self = userdata.?;

        self.handleConnectivityCheckEvent(.{ .main_timer = result });

        return .disarm;
    }

    fn connectivityCheckTimerCancelCallback(
        userdata: ?*AgentContext,
        loop: *xev.Loop,
        c: *xev.Completion,
        result: xev.CancelError!void,
    ) xev.CallbackAction {
        _ = result catch {};
        _ = c;
        _ = userdata;
        _ = loop;

        return .disarm;
    }

    fn connectivityCheckResponseWriteCallback(
        userdata: ?*anyopaque,
        loop: *xev.Loop,
        c: *xev.Completion,
        result: xev.Result,
    ) xev.CallbackAction {
        _ = loop;

        const self = @as(*AgentContext, @ptrCast(@alignCast(userdata.?)));
        const socket_context = for (self.socket_contexts) |*ctx| {
            if (ctx.socket == c.op.sendmsg.fd) break ctx;
        } else unreachable;
        const socket_context_index = socket_context.index;

        self.handleConnectivityCheckEvent(.{ .response_write = .{ .socket_context_index = socket_context_index, .result = result.sendmsg } });

        return .disarm;
    }

    fn connectivityCheckTransactionCompletedCallback(
        userdata: ?*anyopaque,
        transaction: *Transaction,
        result: TransactionResult,
    ) void {
        const self = @as(*AgentContext, @ptrCast(@alignCast(userdata.?)));
        const stun_context_entry = self.getStunContextEntryFromTransactionId(transaction.transaction_id) orelse unreachable;

        self.handleConnectivityCheckEvent(.{ .completed = .{ .stun_context = &stun_context_entry.stun_context, .result = result } });
    }

    fn checkMessageIntegrity(request: ztun.Message, password: []const u8) !void {
        var buffer: [4096]u8 = undefined;
        var arena_state = std.heap.FixedBufferAllocator.init(&buffer);
        if (!request.checkFingerprint(arena_state.allocator())) return error.InvalidFingerprint;

        const attribute_index = for (request.attributes, 0..) |a, i| {
            if (a.type == ztun.attr.Type.message_integrity) break i;
        } else return error.NoMessageIntegrity;

        const authentication = ztun.auth.Authentication{ .short_term = ztun.auth.ShortTermAuthentication{ .password = password } };
        const key = try authentication.computeKeyAlloc(arena_state.allocator());

        if (!try request.checkMessageIntegrity(.classic, attribute_index, key, arena_state.allocator())) return error.InvalidMessageIntegrity;
    }

    fn getRoleAndTiebreakerFromRequest(message: ztun.Message) ?struct { role: AgentRole, tiebreaker: u64 } {
        for (message.attributes) |*a| {
            if (a.type == ztun.attr.Type.ice_controlling) {
                const ice_controlling_attribute = ztun.attr.common.IceControlling.fromAttribute(a.*) catch return null;
                return .{ .role = .controlling, .tiebreaker = ice_controlling_attribute.value };
            } else if (a.type == ztun.attr.Type.ice_controlled) {
                const ice_controlled_attribute = ztun.attr.common.IceControlled.fromAttribute(a.*) catch return null;
                return .{ .role = .controlled, .tiebreaker = ice_controlled_attribute.value };
            }
        }
        return null;
    }

    /// Switch Agent role
    fn switchRole(self: *AgentContext) void {
        const old_role = self.role.?;
        self.role = if (old_role == .controlling) .controlled else .controlling;
        log.debug("Agent {} - Switching role from {s} to {s}", .{ self.id, @tagName(old_role), @tagName(self.role.?) });
        self.checklist.recomputePriorities(self.local_candidates.items, self.remote_candidates.items, self.role.?);
    }

    /// Detect and repair a potential role conflict. Returns true if there was a role conflict that requires an error response.
    fn detectAndRepairRoleConflict(self: *AgentContext, request: ztun.Message) bool {
        const remote_role_and_tiebreaker = getRoleAndTiebreakerFromRequest(request) orelse @panic("TODO: Request is missing a ICE-CONTROLLING or ICE-CONTROLLED attribute");
        if (self.role.? == .controlling and remote_role_and_tiebreaker.role == .controlling) {
            if (self.tiebreaker >= remote_role_and_tiebreaker.tiebreaker) {
                return true;
            } else {
                self.switchRole();
            }
        } else if (self.role.? == .controlled and remote_role_and_tiebreaker.role == .controlled) {
            if (self.tiebreaker >= remote_role_and_tiebreaker.tiebreaker) {
                self.switchRole();
            } else {
                return true;
            }
        }

        return false;
    }

    fn handleConnectivityCheckRequestRead(
        self: *AgentContext,
        raw_message: []const u8,
        source: std.net.Address,
        socket_context: *SocketContext,
    ) !void {
        defer self.checklist.updateState();

        // TODO(Corendos): Check if this is a peer-reflexive candidate.
        //                 See https://www.rfc-editor.org/rfc/rfc8445#section-7.3.1.3

        var buffer: [4096]u8 = undefined;
        const request = r: {
            var arena_state = std.heap.FixedBufferAllocator.init(&buffer);
            var stream = std.io.fixedBufferStream(raw_message);
            break :r try ztun.Message.readAlloc(stream.reader(), arena_state.allocator());
        };

        // Check fingerprint/integrity.
        try checkMessageIntegrity(request, self.local_auth.password);

        // Detecting and repairing role conflicts.
        if (self.detectAndRepairRoleConflict(request)) {
            // Enqueue a 487 STUN response.
            self.check_response_queue.push(ResponseEntry{
                .socket_index = socket_context.index,
                .transaction_id = request.transaction_id,
                .source = source,
                .flags = .{ .role_conflict = true },
            }) catch unreachable;

            // No further processing.
            return;
        }

        // Enqueue response.
        self.check_response_queue.push(ResponseEntry{
            .socket_index = socket_context.index,
            .transaction_id = request.transaction_id,
            .source = source,
            .flags = .{ .role_conflict = false },
        }) catch unreachable;

        const use_candidate = for (request.attributes) |a| {
            if (a.type == ztun.attr.Type.use_candidate) break true;
        } else false;

        // Find local candidate whose transport address matches the address on which the request was received.
        const local_candidate_index = self.getLocalCandidateIndexFromTransportAddress(socket_context.address) orelse unreachable;
        const remote_candidate_index = self.getRemoteCandidateIndexFromTransportAddress(source) orelse {
            log.debug("Agent {} - No remote candidate matching the source address (peer reflexive candidate maybe?)", .{self.id});
            return;
        };

        const candidate_pair = CandidatePair{ .local_candidate_index = local_candidate_index, .remote_candidate_index = remote_candidate_index };
        const is_pair_in_checklist = self.checklist.containsPair(candidate_pair);

        if (!is_pair_in_checklist) {
            const candidate_pair_data = self.makeCandidatePairData(candidate_pair);
            self.checklist.addPair(candidate_pair, candidate_pair_data) catch unreachable;
        }
        const entry = self.checklist.getEntry(candidate_pair) orelse {
            // NOTE(Corendos): Other pairs have higher priority and the pair was not added.
            return;
        };

        // Handle triggered checks.
        switch (entry.data.state) {
            .succeeded => {},
            .failed => {
                // TODO(Corendos): Find a way to make that compliant with the spec. Issue is that it's creating an infinite loop of checks.
                //
                // Let's assume Agent L is checking the pair 0:3
                // 1. Agent L sends a STUN request to R
                // 2. Agent R sends back the response. In parallel it adds the pair 0:3 to the triggered check queue and sets its state to "waiting".
                // 3. Agent L handles response and sets the pair state to "failed" due to non-symmetric transport addresses.
                // 4. Agent R sends a STUN request to L due to the triggered check.
                // 5. Agent L sends back the response. In parallel is adds the pair 0:3 to the triggered check queue and changes its state from "failed" to "waiting".
                // 6. Agent R handles the response and sets the pair state to "failed" due to non-symmetric transport addresses.
                // 7. We are back to the situation before 1. and it creates a loop
                //
                // Since the triggered check are done before any other checks, if the request-response-request happens fast enough, no other candidate pair can be checked and we have an infinite loop of checks.
            },
            else => {
                log.debug("Agent {} - Adding {}:{} to the triggered check queue", .{ self.id, candidate_pair.local_candidate_index, candidate_pair.remote_candidate_index });
                if (entry.data.state == .in_progress) {
                    for (self.stun_context_entries) |*stun_entry| {
                        if (!stun_entry.flags.in_use) continue;
                        if (stun_entry.stun_context != .check) continue;
                        const check_context: *ConnectivityCheckContext = &stun_entry.stun_context.check;
                        if (check_context.candidate_pair.eql(candidate_pair) and !check_context.flags.is_canceled) {
                            check_context.transaction.stopRetransmits(self.loop);
                            check_context.flags.is_canceled = true;
                        }
                    }
                }
                self.checklist.setPairState(candidate_pair, .waiting);

                const new_entry = TriggeredCheckEntry{ .candidate_pair = candidate_pair, .nominate = use_candidate };
                if (self.checklist.triggered_check_queue.findFirst(new_entry, TriggeredCheckEntry.eql) == null) {
                    self.checklist.triggered_check_queue.push(new_entry) catch unreachable;
                }
            },
        }

        if (entry.data.state == .succeeded and use_candidate) {
            self.handleNomination(candidate_pair, self.loop);
        }
    }

    inline fn areTransportAddressesSymmetric(request_source: std.net.Address, request_destination: std.net.Address, response_source: std.net.Address, response_destination: std.net.Address) bool {
        return response_source.eql(request_destination) and response_destination.eql(request_source);
    }

    fn constructValidPair(self: *AgentContext, mapped_address: std.net.Address, request_destination: std.net.Address) CandidatePair {
        const valid_local_candidate_index = self.getLocalCandidateIndexFromTransportAddress(mapped_address) orelse @panic("Probably a peer reflexive candidate");
        const valid_remote_candidate_index = self.getRemoteCandidateIndexFromTransportAddress(request_destination) orelse unreachable;

        return CandidatePair{ .local_candidate_index = valid_local_candidate_index, .remote_candidate_index = valid_remote_candidate_index };
    }

    fn handleConnectivityCheckSuccessResponse(self: *AgentContext, check_context: *ConnectivityCheckContext, message: ztun.Message, source: std.net.Address) !void {
        const candidate_pair = check_context.candidate_pair;

        const local_candidate = self.local_candidates.items[candidate_pair.local_candidate_index];
        const remote_candidate = self.remote_candidates.items[candidate_pair.remote_candidate_index];

        const mapped_address = getMappedAddressFromStunMessage(message) orelse @panic("TODO: Failed to get mapped address from STUN message");

        // NOTE(Corendos): handle https://www.rfc-editor.org/rfc/rfc8445#section-7.2.5.2.1.
        if (!areTransportAddressesSymmetric(local_candidate.transport_address, remote_candidate.transport_address, source, mapped_address)) {
            log.debug("Agent {} - Check failed for candidate pair ({}:{}) because source and destination are not symmetric", .{ self.id, candidate_pair.local_candidate_index, candidate_pair.remote_candidate_index });

            self.checklist.setPairState(candidate_pair, .failed);
            return;
        }

        // Discovering Peer-Reflexive Candidates
        // TODO(Corendos): implement peer-reflexive candidates handling here.

        // Constructing a Valid Pair
        const valid_candidate_pair = self.constructValidPair(mapped_address, remote_candidate.transport_address);

        // Add the valid pair to the valid list if needed.
        if (valid_candidate_pair.eql(candidate_pair) or self.checklist.containsPair(valid_candidate_pair)) {
            // TODO(Corentin): Be careful with peer-reflexive priority.

            if (!self.checklist.containsValidPair(valid_candidate_pair)) {
                var valid_candidate_pair_data = self.makeCandidatePairData(valid_candidate_pair);
                valid_candidate_pair_data.state = .succeeded;
                self.checklist.addValidPair(valid_candidate_pair, valid_candidate_pair_data) catch unreachable;
            }
        } else {
            // TODO(Corendos): Not sure about that
            if (!self.checklist.containsValidPair(valid_candidate_pair)) {
                var valid_candidate_pair_data = self.makeCandidatePairData(valid_candidate_pair);
                valid_candidate_pair_data.state = .succeeded;
                self.checklist.addValidPair(valid_candidate_pair, valid_candidate_pair_data) catch unreachable;
            }
        }

        // TODO(Corendos): What to do with response when a pair has been nominated ?
        if (!self.checklist.containsPair(candidate_pair)) {
            log.debug("Agent {} - Pair not present in the checklist, has a pair been nominated ?", .{self.id});
            return;
        }

        // Updating Candidate Pair States.
        self.checklist.setPairState(candidate_pair, .succeeded);
        self.checklist.setPairState(valid_candidate_pair, .succeeded);

        const entry = self.checklist.getEntry(candidate_pair).?;

        // Set the states for all other Frozen candidate pairs in all checklists with the same foundation to Waiting
        // NOTE(Corendos): The RFC is unclear there, do we compare to the foundation of the valid pair or to the foundation of the pair that generated the check ?
        //                 In case of failure, it says "When the ICE agent sets the candidate pair state to Failed as a result of a connectivity-check error, the
        //                 agent does not change the states of other candidate pairs with the same foundation" so I guess it's the second scenario.
        for (self.checklist.pairs.slice()) |current_entry| {
            if (current_entry.data.state == .frozen and current_entry.data.foundation.eql(entry.data.foundation)) {
                self.checklist.setPairState(current_entry.pair, .waiting);
            }
        }

        if (check_context.flags.is_nomination) {
            self.handleNomination(valid_candidate_pair, self.loop);
        }

        // TODO(Corendos): This might need to be put elsewhere.
        // Try to nominate pair
        if (self.role == .controlling and !self.checklist.nomination_in_progress) {
            self.checklist.nomination_in_progress = true;
            log.debug("Agent {} - Try to nominate pair {}:{}", .{ self.id, valid_candidate_pair.local_candidate_index, valid_candidate_pair.remote_candidate_index });
            self.checklist.triggered_check_queue.push(.{ .candidate_pair = valid_candidate_pair, .nominate = true }) catch unreachable;
        }
    }

    fn handleConnectivityCheckErrorResponse(self: *AgentContext, check_context: *ConnectivityCheckContext, message: ztun.Message) !void {
        const candidate_pair = check_context.candidate_pair;

        const error_code_attribute_opt: ?ztun.attr.common.ErrorCode = for (message.attributes) |attr| {
            if (attr.type == ztun.attr.Type.error_code) break try ztun.attr.common.ErrorCode.fromAttribute(attr);
        } else null;

        const error_code_attribute = error_code_attribute_opt orelse {
            self.checklist.setPairState(candidate_pair, .failed);
            return;
        };

        switch (error_code_attribute.value) {
            .role_conflict => {
                if (check_context.flags.role == self.role.?) {
                    self.switchRole();

                    const new_entry = TriggeredCheckEntry{ .candidate_pair = candidate_pair };
                    if (self.checklist.triggered_check_queue.findFirst(new_entry, TriggeredCheckEntry.eql) == null) {
                        self.checklist.setPairState(candidate_pair, .waiting);
                        self.checklist.triggered_check_queue.push(new_entry) catch unreachable;
                    }

                    self.tiebreaker = std.crypto.random.int(u64);
                }
            },
            else => {
                self.checklist.setPairState(candidate_pair, .failed);
            },
        }
    }

    fn handleConnectivityCheckTransactionCompleted(
        self: *AgentContext,
        stun_context: *StunContext,
        result: TransactionResult,
    ) !void {
        const check_context = &stun_context.check;
        const candidate_pair = check_context.candidate_pair;

        const payload = result catch |err| {
            // Due to triggered check, we might never receive the answer but must not treat the lack of response as a failure.
            if (!check_context.flags.is_canceled) {
                log.debug("Agent {} - Check failed for candidate pair ({}:{}) with {}", .{ self.id, candidate_pair.local_candidate_index, candidate_pair.remote_candidate_index, err });
                self.checklist.setPairState(candidate_pair, .failed);
            }
            return;
        };

        var buffer: [4096]u8 = undefined;
        const message = b: {
            var arena_state = std.heap.FixedBufferAllocator.init(&buffer);
            var stream = std.io.fixedBufferStream(payload.raw_message);
            var reader = stream.reader();
            break :b ztun.Message.readAlloc(reader, arena_state.allocator()) catch unreachable;
        };

        if (message.type.class == .success_response) {
            try self.handleConnectivityCheckSuccessResponse(check_context, message, payload.source);
        } else {
            try self.handleConnectivityCheckErrorResponse(check_context, message);
        }
    }

    fn handleConnectivityCheckResponseRead(
        self: *AgentContext,
        raw_message: []const u8,
        source: std.net.Address,
        stun_context: *StunContext,
    ) !void {
        const check_context = &stun_context.check;

        check_context.transaction.readCallback(self.loop, raw_message, source);
    }

    inline fn tryPopTriggeredCheckQueue(self: *AgentContext) ?TriggeredCheckEntry {
        return self.checklist.triggered_check_queue.pop() orelse return null;
    }

    fn startTransaction(self: *AgentContext, candidate_pair: CandidatePair, is_triggered_check: bool, is_nominated: bool) !void {
        const local_candidate = self.local_candidates.items[candidate_pair.local_candidate_index];
        const remote_candidate = self.remote_candidates.items[candidate_pair.remote_candidate_index];

        const socket_context_index = self.getSocketContextIndexFromAddress(local_candidate.base_address).?;
        const socket_context = &self.socket_contexts[socket_context_index];

        var buffer: [4096]u8 = undefined;
        const request = r: {
            var allocator = std.heap.FixedBufferAllocator.init(&buffer);
            break :r makeConnectivityCheckBindingRequest(
                self.local_auth.username_fragment,
                self.remote_auth.?.username_fragment,
                self.remote_auth.?.password,
                local_candidate.priority,
                self.role.?,
                self.tiebreaker,
                is_nominated,
                allocator.allocator(),
            ) catch unreachable;
        };

        const stun_context_entry = self.getFreeStunContextEntry() orelse unreachable;
        errdefer stun_context_entry.flags.in_use = false;

        const write_buffer = try self.buffer_pool.create();
        errdefer self.buffer_pool.destroy(write_buffer);

        const read_buffer = try self.buffer_pool.create();
        errdefer self.buffer_pool.destroy(read_buffer);

        var transaction = Transaction.init(
            socket_context.socket,
            remote_candidate.transport_address,
            request,
            write_buffer,
            read_buffer,
            self,
            connectivityCheckTransactionCompletedCallback,
        );
        errdefer transaction.deinit();

        stun_context_entry.transaction_id = request.transaction_id;
        stun_context_entry.stun_context = .{
            .check = ConnectivityCheckContext{
                .socket_index = socket_context_index,
                .candidate_pair = candidate_pair,
                .transaction = transaction,
                .flags = .{
                    .is_triggered_check = is_triggered_check,
                    .is_nomination = is_nominated,
                    .role = self.role.?,
                },
            },
        };

        log.debug("Agent {} - Starting {s}connectivity check from {} to {}", .{
            self.id,
            if (is_triggered_check) "triggered " else "",
            candidate_pair.local_candidate_index,
            candidate_pair.remote_candidate_index,
        });

        const check_count = self.checklist.pairs.slice().len;
        const waiting_count = self.checklist.getPairCount(.waiting);
        const in_progress_count = self.checklist.getPairCount(.in_progress);
        stun_context_entry.stun_context.check.transaction.start(Configuration.computeRtoCheckMs(check_count, waiting_count, in_progress_count), self.loop);

        self.checklist.setPairState(candidate_pair, .in_progress);
    }

    fn handleConnectivityCheckMainTimer(self: *AgentContext, result: xev.Timer.RunError!void) !void {
        _ = result catch |err| {
            if (err == error.Canceled) return;
            log.err("{}", .{err});
            @panic("TODO: Main timer failed");
        };
        if (self.flags.stopped) return;

        // TODO(Corendos): handle multiple checklists

        if (tryPopTriggeredCheckQueue(self)) |node| {
            try self.startTransaction(node.candidate_pair, true, node.nominate);

            if (!self.flags.stopped) {
                self.connectivity_checks_timer.run(
                    self.loop,
                    &self.connectivity_checks_timer_completion,
                    Configuration.new_transaction_interval_ms,
                    AgentContext,
                    self,
                    connectivityCheckTimerCallback,
                );
            }
            return;
        }

        if (self.checklist.getPairCount(.waiting) == 0) {
            self.unfreezePair();
        }

        if (self.getWaitingPair()) |candidate_pair| {
            try self.startTransaction(candidate_pair, false, false);

            if (!self.flags.stopped) {
                self.connectivity_checks_timer.run(
                    self.loop,
                    &self.connectivity_checks_timer_completion,
                    Configuration.new_transaction_interval_ms,
                    AgentContext,
                    self,
                    connectivityCheckTimerCallback,
                );
            }
            return;
        }

        log.debug("Agent {} - No more candidate pair to check", .{self.id});
        if (!self.flags.stopped) {
            self.connectivity_checks_timer.run(
                self.loop,
                &self.connectivity_checks_timer_completion,
                Configuration.new_transaction_interval_ms,
                AgentContext,
                self,
                connectivityCheckTimerCallback,
            );
        }
    }

    // Debug utilities

    const PairsFormatter = struct {
        ctx: *const AgentContext,
        pub fn format(self: PairsFormatter, comptime fmt_s: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
            _ = options;
            _ = fmt_s;
            try writer.print("Agent {} Candidate pairs\n", .{self.ctx.id});

            for (self.ctx.checklist.pairs.slice()) |entry| {
                const foundation_bit_size = @bitSizeOf(Foundation.IntType);
                const pair_foundation: u64 = (@as(u64, entry.data.foundation.remote.asNumber()) << foundation_bit_size) + @as(u64, entry.data.foundation.local.asNumber());
                try writer.print("    {}:{} f:{} p:{} = {s}\n", .{ entry.pair.local_candidate_index, entry.pair.remote_candidate_index, pair_foundation, entry.data.priority, @tagName(entry.data.state) });
            }
        }
    };

    fn printPairStates(self: *const AgentContext) void {
        log.debug("{}", .{PairsFormatter{ .ctx = self }});
    }

    const ValidPairsFormatter = struct {
        ctx: *const AgentContext,
        pub fn format(self: ValidPairsFormatter, comptime fmt_s: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
            _ = options;
            _ = fmt_s;
            try writer.print("Agent {} Valid pairs\n", .{self.ctx.id});

            for (self.ctx.checklist.valid_pairs.slice()) |entry| {
                const foundation_bit_size = @bitSizeOf(Foundation.IntType);
                const pair_foundation: u64 = (@as(u64, entry.data.foundation.remote.asNumber()) << foundation_bit_size) + @as(u64, entry.data.foundation.local.asNumber());
                try writer.print("    {}:{} f:{} p:{} n:{} = {s}\n", .{ entry.pair.local_candidate_index, entry.pair.remote_candidate_index, pair_foundation, entry.data.priority, entry.data.nominated, @tagName(entry.data.state) });
            }
        }
    };

    fn printValidList(self: *const AgentContext) void {
        log.debug("{}", .{ValidPairsFormatter{ .ctx = self }});
    }

    const CandidateFormatter = struct {
        ctx: *const AgentContext,
        pub fn format(self: CandidateFormatter, comptime fmt_s: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
            _ = options;
            _ = fmt_s;
            try writer.print("Agent {}\n", .{self.ctx.id});

            for (self.ctx.local_candidates.items, 0..) |candidate, index| {
                if (candidate.default) {
                    try writer.print("    Local {} (d) - {} - {}\n", .{ index, candidate.base_address, candidate.transport_address });
                } else {
                    try writer.print("    Local {} - {} - {}\n", .{ index, candidate.base_address, candidate.transport_address });
                }
            }

            for (self.ctx.remote_candidates.items, 0..) |candidate, index| {
                try writer.print("    Remote {} - {} - {}\n", .{ index, candidate.base_address, candidate.transport_address });
            }
        }
    };

    fn printCandidates(self: *const AgentContext) void {
        log.debug("{}", .{CandidateFormatter{ .ctx = self }});
    }
};

pub const CreateAgentOptions = struct {
    userdata: ?*anyopaque = null,
    on_candidate_callback: OnCandidateCallback = noopCandidateCallback,
    on_state_change_callback: OnStateChangeCallback = noopStateChangeCallback,
    on_data_callback: OnDataCallback = noopDataCallback,
};

const NetworkInterface = struct {
    name: []const u8,
    index: u32,
    type: platform.netlink.ARPHRD,
};

const InterfaceAddress = struct {
    interface_index: u32,
    address: std.net.Address,
};

/// Represents an event that can happen while gathering candidates.
const GatheringEventResult = union(enum) {
    /// A STUN response was received and it's the payload.
    read: struct { stun_context: *StunContext, raw_message: []const u8 },
    /// A STUN transaction completed.
    completed: struct { stun_context: *StunContext, result: TransactionResult },
    /// The main timer fired and the payload contains the result.
    main_timer: xev.Timer.RunError!void,
};

const ConnectivityCheckEventResult = union(enum) {
    request_read: struct { socket_context_index: usize, raw_message: []const u8, address: std.net.Address },
    response_read: struct { stun_context: *StunContext, raw_message: []const u8, address: std.net.Address },
    completed: struct { stun_context: *StunContext, result: TransactionResult },
    response_write: struct { socket_context_index: usize, result: xev.WriteError!usize },
    main_timer: xev.Timer.RunError!void,
};

pub const ContextOperationType = enum {
    create_agent,
    delete_agent,
    gather_candidates,
    set_remote_candidates,
    send,
};

pub const RemoteCandidateParameters = struct {
    agent_id: AgentId = undefined,
    candidates: []const Candidate,
    username_fragment: []const u8,
    password: []const u8,
};

pub const SendParameters = struct {
    agent_id: AgentId,
    data_stream_id: u8,
    component_id: u8,
    data: []const u8,

    write_completion: xev.Completion = .{},
    write_data: WriteData = .{},
};

pub const ContextOperation = union(ContextOperationType) {
    create_agent: CreateAgentOptions,
    delete_agent: AgentId,
    gather_candidates: AgentId,
    set_remote_candidates: RemoteCandidateParameters,
    send: SendParameters,
};

pub const InvalidError = error{
    InvalidId,
};

pub const SendError = xev.WriteError || InvalidError || error{
    NotReady,
};

pub const CreateAgentError = error{ NoSlotAvailable, Canceled, Unexpected };

pub const DeleteAgentError = InvalidError || error{ Canceled, Unexpected };

pub const ContextResult = union(ContextOperationType) {
    create_agent: CreateAgentError!AgentId,
    delete_agent: DeleteAgentError!void,
    gather_candidates: InvalidError!void,
    set_remote_candidates: InvalidError!void,
    send: SendError!usize,
};

pub const ContextCallback = *const fn (userdata: ?*anyopaque, result: ContextResult) void;
pub fn noopCallback(_: ?*anyopaque, _: ContextResult) void {}

pub const ContextCompletion = struct {
    op: ContextOperation = undefined,

    userdata: ?*anyopaque = null,
    callback: ContextCallback = noopCallback,

    next: ?*ContextCompletion = null,
};

const context_agent_slot_bit_count = 6;
const context_agent_slot_count = 1 << context_agent_slot_bit_count;

pub const AgentId = GenerationId(u16, context_agent_slot_bit_count);

const AgentContextEntry = struct {
    flags: packed struct {
        deleted: bool = false,
    } = .{},
    agent_id: AgentId = .{ .raw = 0 },
    agent_context: ?AgentContext = null,
};

pub const Context = struct {
    allocator: std.mem.Allocator,

    addresses_mutex: std.Thread.Mutex = .{},
    network_interface_map: std.AutoArrayHashMapUnmanaged(u32, NetworkInterface) = .{},
    interface_addresses: std.ArrayListUnmanaged(InterfaceAddress) = .{},

    string_storage: std.heap.ArenaAllocator,

    agent_context_entries: [context_agent_slot_count]AgentContextEntry,

    netlink_context: NetlinkContext,
    netlink_context_ready: bool = false,

    async_queue_mutex: std.Thread.Mutex = .{},
    async_queue: Intrusive(ContextCompletion) = .{},
    async_handle: xev.Async,
    async_completion: xev.Completion = .{},

    flags_mutex: std.Thread.Mutex = .{},
    flags: packed struct {
        stopped: bool = false,
    } = .{},

    loop: xev.Loop,

    pub fn init(allocator: std.mem.Allocator) !Context {
        var agent_context_entries: [context_agent_slot_count]AgentContextEntry = undefined;
        for (&agent_context_entries, 0..) |*entry, index| {
            const agent_id = AgentId{ .parts = .{ .index = @intCast(index), .details = 0 } };
            entry.* = AgentContextEntry{ .agent_id = agent_id };
        }

        return Context{
            .allocator = allocator,
            .agent_context_entries = agent_context_entries,
            .string_storage = std.heap.ArenaAllocator.init(allocator),
            .netlink_context = try NetlinkContext.init(allocator),
            .async_handle = try xev.Async.init(),
            .loop = try xev.Loop.init(.{}),
        };
    }

    pub fn deinit(self: *Context) void {
        for (&self.agent_context_entries) |*entry| {
            if (entry.agent_context) |*agent_context| agent_context.deinit();
        }

        self.netlink_context.deinit();
        self.network_interface_map.deinit(self.allocator);
        self.interface_addresses.deinit(self.allocator);
        self.string_storage.deinit();
        self.async_handle.deinit();
        self.loop.deinit();
    }

    pub fn run(self: *Context) !void {
        self.netlink_context.userdata = self;
        self.netlink_context.on_interface_callback = (struct {
            fn callback(userdata: ?*anyopaque, event: NetlinkContext.InterfaceEvent) void {
                const inner_self: *Context = @ptrCast(@alignCast(userdata.?));
                inner_self.onInterface(event);
            }
        }).callback;
        self.netlink_context.on_address_callback = (struct {
            fn callback(userdata: ?*anyopaque, event_type: NetlinkContext.EventType, interface_index: u32, address: std.net.Address) void {
                const inner_self: *Context = @ptrCast(@alignCast(userdata.?));
                inner_self.onAddress(event_type, interface_index, address);
            }
        }).callback;
        self.netlink_context.on_idle_callback = (struct {
            fn callback(userdata: ?*anyopaque) void {
                const inner_self: *Context = @ptrCast(@alignCast(userdata.?));
                inner_self.netlinkContextReady();
            }
        }).callback;
        self.async_handle.wait(&self.loop, &self.async_completion, Context, self, asyncCallback);

        try self.netlink_context.start(&self.loop);
        try self.loop.run(.until_done);
    }

    pub fn stop(self: *Context) void {
        self.flags_mutex.lock();
        defer self.flags_mutex.unlock();
        if (self.flags.stopped) return;

        self.flags.stopped = true;
        self.async_handle.notify() catch unreachable;
    }

    fn onInterface(self: *Context, event: NetlinkContext.InterfaceEvent) void {
        switch (event) {
            .add => |payload| self.addNetworkInterface(payload.index, payload.name, payload.type) catch unreachable,
            .delete => |index| self.deleteNetworkInterface(index),
        }
    }

    fn onAddress(self: *Context, event_type: NetlinkContext.EventType, interface_index: u32, address: std.net.Address) void {
        switch (event_type) {
            .add => self.addInterfaceAddress(interface_index, address) catch unreachable,
            .delete => self.deleteInterfaceAddress(interface_index, address),
        }
    }

    fn addNetworkInterface(self: *Context, index: u32, name: []const u8, interface_type: platform.netlink.ARPHRD) !void {
        self.addresses_mutex.lock();
        defer self.addresses_mutex.unlock();

        const gop = try self.network_interface_map.getOrPut(self.allocator, index);
        if (!gop.found_existing) {
            log.debug("New interface: {s}", .{name});
            gop.value_ptr.* = NetworkInterface{
                .name = try self.string_storage.allocator().dupe(u8, name),
                .index = index,
                .type = interface_type,
            };
        }
    }

    fn deleteNetworkInterface(self: *Context, index: u32) void {
        self.addresses_mutex.lock();
        defer self.addresses_mutex.unlock();

        log.debug("Delete interface {}", .{index});
        _ = self.network_interface_map.swapRemove(index);
    }

    fn searchAddress(self: *Context, interface_index: u32, address: std.net.Address) ?usize {
        return for (self.interface_addresses.items, 0..) |item, i| {
            if (item.interface_index == interface_index and item.address.eql(address)) {
                return i;
            }
        } else null;
    }

    fn addInterfaceAddress(self: *Context, interface_index: u32, address: std.net.Address) !void {
        self.addresses_mutex.lock();
        defer self.addresses_mutex.unlock();
        if (self.searchAddress(interface_index, address) != null) return;

        log.debug("New Address for interface {}: {}", .{ interface_index, address });
        try self.interface_addresses.append(self.allocator, .{
            .interface_index = interface_index,
            .address = address,
        });
    }

    fn deleteInterfaceAddress(self: *Context, interface_index: u32, address: std.net.Address) void {
        self.addresses_mutex.lock();
        defer self.addresses_mutex.unlock();
        log.debug("Delete Address for interface {}: {}", .{ interface_index, address });
        const index = self.searchAddress(interface_index, address) orelse return;
        _ = self.interface_addresses.swapRemove(index);
    }

    fn netlinkContextReady(self: *Context) void {
        self.netlink_context_ready = true;
        self.async_handle.notify() catch unreachable;
    }

    inline fn isValidAgentId(self: *const Context, agent_id: AgentId) bool {
        if (agent_id.parts.index >= self.agent_context_entries.len) return false;
        const entry = self.agent_context_entries[agent_id.parts.index];
        return entry.agent_id.raw == agent_id.raw;
    }

    inline fn getAgentEntry(self: *Context, agent_id: AgentId) InvalidError!*AgentContextEntry {
        if (!self.isValidAgentId(agent_id)) return error.InvalidId;
        return &self.agent_context_entries[agent_id.parts.index];
    }

    pub inline fn getAgentContext(self: anytype, agent_id: AgentId) InvalidError!switch (@TypeOf(self)) {
        *Context => *AgentContext,
        *const Context => *const AgentContext,
        else => unreachable,
    } {
        const entry = try self.getAgentEntry(agent_id);
        return if (entry.agent_context) |*agent_context| agent_context else error.InvalidId;
    }

    fn createAgentCallback(userdata: ?*anyopaque, result: ContextResult) void {
        var f: *Future(CreateAgentError!AgentId) = @ptrCast(@alignCast(userdata.?));
        f.set(result.create_agent);
    }

    pub fn createAgent(self: *Context, options: CreateAgentOptions) CreateAgentError!AgentId {
        var f = Future(CreateAgentError!AgentId){};
        var c = ContextCompletion{
            .op = .{ .create_agent = options },
            .userdata = &f,
            .callback = createAgentCallback,
        };

        self.addCompletion(&c);
        self.submitCompletions() catch return error.Unexpected;

        return f.get();
    }

    fn deleteAgentCallback(userdata: ?*anyopaque, result: ContextResult) void {
        var f: *Future(DeleteAgentError!void) = @ptrCast(@alignCast(userdata.?));
        f.set(result.delete_agent);
    }

    pub fn deleteAgent(self: *Context, agent_id: AgentId) DeleteAgentError!void {
        var f = Future(DeleteAgentError!void){};
        var c = ContextCompletion{
            .op = .{ .delete_agent = agent_id },
            .userdata = &f,
            .callback = deleteAgentCallback,
        };

        self.addCompletion(&c);
        self.submitCompletions() catch return error.Unexpected;

        return f.get();
    }

    fn addCompletion(self: *Context, c: *ContextCompletion) void {
        self.async_queue_mutex.lock();
        defer self.async_queue_mutex.unlock();
        self.async_queue.push(c);
    }

    fn submitCompletions(self: *Context) !void {
        try self.async_handle.notify();
    }

    pub fn gatherCandidates(self: *Context, agent_id: AgentId, c: *ContextCompletion, userdata: ?*anyopaque, callback: ContextCallback) !void {
        c.* = ContextCompletion{
            .op = .{ .gather_candidates = agent_id },
            .userdata = userdata,
            .callback = callback,
        };

        self.addCompletion(c);
        try self.submitCompletions();
    }

    pub fn setRemoteCandidates(self: *Context, agent_id: AgentId, c: *ContextCompletion, parameters: RemoteCandidateParameters, userdata: ?*anyopaque, callback: ContextCallback) !void {
        // TODO(Corendos): Improve that
        var parameters_copy = parameters;
        parameters_copy.agent_id = agent_id;

        c.* = ContextCompletion{
            .op = .{ .set_remote_candidates = parameters_copy },
            .userdata = userdata,
            .callback = callback,
        };

        self.addCompletion(c);
        try self.submitCompletions();
    }

    pub fn send(self: *Context, agent_id: AgentId, c: *ContextCompletion, data_stream_id: u8, component_id: u8, data: []const u8, userdata: ?*anyopaque, callback: ContextCallback) !void {
        c.* = ContextCompletion{
            .op = .{ .send = SendParameters{
                .agent_id = agent_id,
                .data_stream_id = data_stream_id,
                .component_id = component_id,
                .data = data,
            } },
            .userdata = userdata,
            .callback = callback,
        };

        self.addCompletion(c);
        try self.submitCompletions();
    }

    pub fn getValidCandidateAddresses(self: *Context, allocator: std.mem.Allocator) ![]std.net.Address {
        self.addresses_mutex.lock();
        defer self.addresses_mutex.unlock();

        var address_list = try std.ArrayList(std.net.Address).initCapacity(allocator, self.interface_addresses.items.len);
        defer address_list.deinit();

        for (self.interface_addresses.items) |interface_address| {
            const interface = self.network_interface_map.get(interface_address.interface_index) orelse continue;

            if (interface.type == platform.netlink.ARPHRD.LOOPBACK) continue;
            const address = interface_address.address;

            if (!net.isValidAddress(address)) continue;

            address_list.appendAssumeCapacity(address);
        }

        return try address_list.toOwnedSlice();
    }

    fn handleCreateAgent(self: *Context, options: CreateAgentOptions) CreateAgentError!AgentId {
        const unused_entry: *AgentContextEntry = for (&self.agent_context_entries) |*entry| {
            if (entry.agent_context == null) break entry;
        } else return error.NoSlotAvailable;

        // TODO(Corendos): Improve returned error.
        unused_entry.agent_context = AgentContext.init(self, unused_entry.agent_id, &self.loop, options, self.allocator) catch return error.Unexpected;

        return unused_entry.agent_id;
    }

    fn handleDeleteAgent(self: *Context, agent_id: AgentId) DeleteAgentError!void {
        const entry = try self.getAgentEntry(agent_id);
        if (entry.agent_context == null or entry.flags.deleted) return error.InvalidId;
        entry.flags.deleted = true;
        entry.agent_context.?.stop();
    }

    fn asyncCallback(
        userdata: ?*Context,
        loop: *xev.Loop,
        _: *xev.Completion,
        result: xev.Async.WaitError!void,
    ) xev.CallbackAction {
        _ = result catch unreachable;
        _ = loop;
        const self = userdata.?;

        for (&self.agent_context_entries) |*entry| {
            if (entry.flags.deleted and entry.agent_context.?.done()) {
                entry.agent_context.?.deinit();
                entry.flags.deleted = false;
                entry.agent_id.bump();
                entry.agent_context = null;
            }
        }

        var local_queue = b: {
            self.async_queue_mutex.lock();
            defer self.async_queue_mutex.unlock();
            var q = self.async_queue;
            self.async_queue = .{};
            break :b q;
        };

        var to_reenqueue = Intrusive(ContextCompletion){};

        while (local_queue.pop()) |c| {
            log.debug("Processing {s}", .{@tagName(c.op)});
            switch (c.op) {
                .create_agent => |options| {
                    const create_agent_result = self.handleCreateAgent(options);

                    c.callback(c.userdata, ContextResult{ .create_agent = create_agent_result });
                },
                .delete_agent => |agent_id| {
                    const delete_agent_result = self.handleDeleteAgent(agent_id);

                    c.callback(c.userdata, ContextResult{ .delete_agent = delete_agent_result });
                },
                .gather_candidates => |agent_id| {
                    if (!self.netlink_context_ready) {
                        to_reenqueue.push(c);
                        continue;
                    }
                    const gather_result = if (self.getAgentContext(agent_id)) |agent_context| b: {
                        agent_context.processGatherCandidates() catch unreachable;
                        break :b {};
                    } else |err| err;

                    c.callback(c.userdata, ContextResult{ .gather_candidates = gather_result });
                },
                .set_remote_candidates => |parameters| {
                    const set_remote_candidates_result = if (self.getAgentContext(parameters.agent_id)) |agent_context| b: {
                        agent_context.processSetRemoteCandidates(parameters) catch unreachable;
                        break :b {};
                    } else |err| err;

                    c.callback(c.userdata, ContextResult{ .set_remote_candidates = set_remote_candidates_result });
                },
                .send => |parameters| {
                    if (self.getAgentContext(parameters.agent_id)) |agent_context| b: {
                        agent_context.processSend(c) catch unreachable;
                        break :b {};
                    } else |err| c.callback(c.userdata, ContextResult{ .send = err });
                },
            }
        }

        self.async_queue_mutex.lock();
        defer self.async_queue_mutex.unlock();
        while (to_reenqueue.pop()) |c| {
            self.async_queue.push(c);
        }

        const stopped = b: {
            self.flags_mutex.lock();
            defer self.flags_mutex.unlock();

            break :b self.flags.stopped;
        };

        if (stopped) {
            self.netlink_context.stop(&self.loop);
        }

        return if (stopped) .disarm else .rearm;
    }
};

test "Basic structs size" {
    try std.testing.expectEqual(@as(usize, 1512), @sizeOf(StunContext));
    try std.testing.expectEqual(@as(usize, 632), @sizeOf(SocketContext));
    try std.testing.expectEqual(@as(usize, 2720), @sizeOf(AgentContext));
}

test {
    _ = Intrusive;
    _ = platform;
    _ = net;
    _ = @import("circular_buffer.zig");
    _ = @import("bounded_fifo.zig");
    _ = @import("generation_id.zig");
    _ = @import("ordered_array.zig");
}
