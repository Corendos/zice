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
pub const sdp = @import("sdp.zig");

const utils = @import("utils.zig");

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

// TODO(Corendos,@MultiChecklist):
// * Improve gathering end detection. This will let us start checks when it's the right time.
// * Improve Checklist management, I'm not happy with the shared responsibility between MediaStream and Checklist.
// * Think about what happens if we add/remove MediaStream while the ICE Session is running. What should happen ?
// * Handle nomination failure to allow other nomination to take place.

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

    pub inline fn fromString(value: []const u8) ?CandidateType {
        return if (std.mem.eql(u8, value, "host"))
            .host
        else if (std.mem.eql(u8, value, "srflx"))
            .server_reflexive
        else if (std.mem.eql(u8, value, "prflx"))
            .peer_reflexive
        else if (std.mem.eql(u8, value, "relay"))
            .relay
        else
            null;
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
    priority: u32,
    /// The candidate foundation.
    foundation: Foundation = undefined,
    /// The component ID associated to the candidate.
    component_id: u8 = 1,
    /// Is this candidate the default candidate.
    default: bool = false,

    pub fn format(value: Candidate, comptime fmt_s: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
        _ = options;
        _ = fmt_s;
        if (value.default) {
            try writer.writeAll("(d) ");
        }
        try writer.print("ty:{s} b:{} t:{} p:{} f:{} c:{}", .{
            @tagName(value.type),
            value.base_address,
            value.transport_address,
            value.priority,
            value.foundation.asNumber(),
            value.component_id,
        });
    }
};

/// Compute the priority using the type preference, local preference and component ID according to https://www.rfc-editor.org/rfc/rfc8445#section-5.1.2.1.
inline fn computePriority(type_preference: u32, local_preference: u32, component_id: u8) u32 {
    return (type_preference << 24) + (local_preference << 8) + (256 - @as(u32, component_id));
}

inline fn extractLocalPreference(priority: u32) u16 {
    return @intCast((priority >> 8) & 0xFFFF);
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

    const arena = arena_state.allocator();

    const authentication = ztun.auth.ShortTermAuthenticationParameters{ .password = password };

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

    const key = try authentication.computeKeyAlloc(arena);
    message_builder.addMessageIntegrity(key);

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

    const authentication = ztun.auth.ShortTermAuthenticationParameters{ .password = password };
    const key = try authentication.computeKeyAlloc(arena_state.allocator());
    message_builder.addMessageIntegrity(key);

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

    const authentication = ztun.auth.ShortTermAuthenticationParameters{ .password = password };
    const key = try authentication.computeKeyAlloc(arena_state.allocator());
    message_builder.addMessageIntegrity(key);

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

/// Represents the gathering state of the agent.
pub const GatheringState = enum {
    /// Waiting to start gathering candidates.
    idle,
    /// Candidates are being gathered.
    gathering,
    /// Candidates have been gathered,
    done,
};

pub const CandidateEventPayload = struct {
    /// The id of Media Stream to which the event is associated.
    media_stream_id: usize,
    /// The candidate we gathered.
    candidate: Candidate,
};

/// Represents the payload of the OnCandidateCallback callback.
pub const CandidateEvent = union(enum) {
    /// Candidate gathering is done and there won't be any new candidates.
    done: void,
    /// A candidate has been found,
    candidate: CandidateEventPayload,
};

/// Callback that is called when a candidate has been found or when all the candidates have been found.
pub const OnCandidateCallback = *const fn (userdata: ?*anyopaque, agent: *AgentContext, event: CandidateEvent) void;
fn noopCandidateCallback(_: ?*anyopaque, _: *AgentContext, _: CandidateEvent) void {}

/// Callback that is called when the ICE state changes.
pub const OnStateChangeCallback = *const fn (userdata: ?*anyopaque, agent: *AgentContext, state: AgentState) void;
fn noopStateChangeCallback(_: ?*anyopaque, _: *AgentContext, _: AgentState) void {}

/// Callback that is called when the agent receives data.
pub const OnDataCallback = *const fn (userdate: ?*anyopaque, agent: *AgentContext, media_stream_id: usize, component_id: u8, data: []const u8) void;
fn noopDataCallback(_: ?*anyopaque, _: *AgentContext, _: usize, _: u8, _: []const u8) void {}

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
pub const SocketData = struct {
    /// The index of the socket we are associated to.
    socket_index: usize,
    /// The buffer used to read a message.
    read_buffer: [4096]u8 = undefined,
    /// The associated xev.Completion.
    read_completion: xev.Completion = .{},
    /// The completion to cancel reads.
    read_cancel_completion: xev.Completion = .{},
    /// The iovec used in recvmsg.
    iovec: std.os.iovec = undefined,
    /// The message_header used in recvmsg.
    message_header: std.os.msghdr = undefined,
    /// The address used in recvmsg.
    address_storage: std.os.sockaddr.storage = undefined,

    /// Returns a std.net.Address from the address_storage field.
    pub inline fn getAddress(self: SocketData) std.net.Address {
        return std.net.Address.initPosix(@ptrCast(@alignCast(&self.address_storage)));
    }
};

pub const Socket = struct {
    /// Our associated socket.
    fd: std.os.fd_t,
    /// Our bound address.
    address: std.net.Address,

    /// The associated socket data.
    data: *SocketData,

    // NOTE(Corendos): The bound address corresponds to the base address of candidates.

    pub fn init(address: std.net.Address, data: *SocketData) !Socket {
        const fd = try std.os.socket(address.any.family, std.os.SOCK.DGRAM, std.os.IPPROTO.UDP);
        errdefer std.os.close(fd);

        try std.os.bind(fd, &address.any, address.getOsSockLen());
        const bound_address = try net.getSocketAddress(fd);

        return Socket{
            .fd = fd,
            .address = bound_address,
            .data = data,
        };
    }

    pub fn start(
        self: Socket,
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
        self.data.iovec = .{
            .iov_len = self.data.read_buffer.len,
            .iov_base = &self.data.read_buffer,
        };
        self.data.message_header = .{
            .name = @ptrCast(@alignCast(&self.data.address_storage)),
            .namelen = @sizeOf(std.os.sockaddr.storage),
            .control = null,
            .controllen = 0,
            .iov = @ptrCast(&self.data.iovec),
            .iovlen = 1,
            .flags = 0,
        };

        self.data.read_completion = xev.Completion{
            .op = .{
                .recvmsg = .{
                    .fd = self.fd,
                    .msghdr = &self.data.message_header,
                },
            },
            .userdata = userdata,
            .callback = callback,
        };

        // TODO(Corendos): Hide implementation details
        if (xev.backend == .epoll) {
            self.data.read_completion.flags.dup = true;
        }

        loop.add(&self.data.read_completion);
    }

    pub fn cancel(self: Socket, loop: *xev.Loop) void {
        if (self.data.read_completion.state() == .dead) return;

        self.data.read_cancel_completion = .{
            .op = .{ .cancel = .{ .c = &self.data.read_completion } },
        };

        loop.add(&self.data.read_cancel_completion);
    }

    pub inline fn done(self: Socket) bool {
        return self.data.read_completion.state() == .dead and self.data.read_cancel_completion.state() == .dead;
    }

    pub fn deinit(self: Socket) void {
        std.os.close(self.fd);
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
    // NOTE(Corendos): Since pairs are made from candidates with the same component id, we can store it here.
    /// The component id of the pair.
    component_id: u8,
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
    is_nomination: bool = false,

    /// Compares two entries.
    pub fn eql(a: TriggeredCheckEntry, b: TriggeredCheckEntry) bool {
        return a.candidate_pair.eql(b.candidate_pair);
    }
};

/// Stores data related to a component in a checklist.
const ChecklistComponentData = struct {
    /// The id of the associated component.
    component_id: u8,
    /// The selected pair for the associated component.
    selected_pair: ?CandidatePair = null,
    /// Various flags.
    flags: packed struct {
        /// Is a nomination in progress for that component ?
        nomination_in_progress: bool = false,
    } = .{},
};

const OrderedPairArray = OrderedBoundedArray(CandidatePairEntry, 16, CandidatePairEntry.Context);

/// Represents a checklist that will be used to check candidate pairs.
const Checklist = struct {
    /// The state of the checklist.
    state: ChecklistState = .running,
    /// The candidate pairs to check ordered by priority.
    pairs: OrderedPairArray,

    /// The valid candidate pairs.
    valid_pairs: OrderedPairArray,

    /// The triggered check FIFO associated with this checklist.
    triggered_check_queue: BoundedFifo(TriggeredCheckEntry, 16) = .{},

    /// Data related to each component.
    component_data: [16]ChecklistComponentData = undefined,
    /// Actual number of component in use.
    component_count: usize = 0,

    /// Initializes a checklist.
    pub fn init(component_count: u8) Checklist {
        std.debug.assert(component_count <= 16);

        var component_data: [16]ChecklistComponentData = undefined;

        for (0..component_count) |index| {
            const component_id: u8 = @intCast(index + 1);
            component_data[index] = .{ .component_id = component_id };
        }

        return Checklist{
            .pairs = OrderedPairArray.init(),
            .valid_pairs = OrderedPairArray.init(),
            .component_data = component_data,
            .component_count = component_count,
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
    pub fn setPairState(self: *Checklist, candidate_pair: CandidatePair, state: CandidatePairState) bool {
        const entry = self.getEntry(candidate_pair) orelse {
            log.warn("Unknown pair state: {}:{}", .{ candidate_pair.local_candidate_index, candidate_pair.remote_candidate_index });
            return false;
        };

        const old_state = entry.data.state;
        return if (state != old_state) b: {
            log.debug("Pair {}:{} state changed from \"{s}\" to \"{s}\"", .{ candidate_pair.local_candidate_index, candidate_pair.remote_candidate_index, @tagName(old_state), @tagName(state) });
            entry.data.state = state;
            break :b true;
        } else false;
    }

    /// Returns true if there is a valid pair for the given component id.
    fn hasValidPairForComponent(self: Checklist, component_id: usize) bool {
        return for (self.valid_pairs.slice()) |entry| {
            if (entry.data.component_id == component_id) break true;
        } else false;
    }

    /// Returns true if there is a nominated pair for the given component id.
    fn hasNominatedPairForComponent(self: Checklist, component_id: usize) bool {
        return for (self.valid_pairs.slice()) |entry| {
            if (entry.data.component_id == component_id and entry.data.nominated) break true;
        } else false;
    }

    /// Updates the checklist state from the state of each candidate pair.
    pub fn updateState(self: *Checklist) void {
        const new_state: ChecklistState = b: {
            const has_nominated_pair_for_each_component = for (self.component_data[0..self.component_count]) |component_data| {
                if (!self.hasNominatedPairForComponent(component_data.component_id)) break false;
            } else true;

            if (has_nominated_pair_for_each_component) {
                break :b .completed;
            }

            const has_valid_pair_for_each_component = for (self.component_data[0..self.component_count]) |component_data| {
                if (!self.hasValidPairForComponent(component_data.component_id)) break false;
            } else true;

            const are_pairs_done = for (self.pairs.slice()) |entry| {
                if (entry.data.state != .succeeded and entry.data.state != .failed) break false;
            } else true;

            break :b if (!has_valid_pair_for_each_component and are_pairs_done)
                .failed
            else
                .running;
        };

        if (new_state == .completed) {
            for (self.component_data[0..self.component_count]) |*component_data| {
                component_data.selected_pair = for (self.valid_pairs.slice()) |entry| {
                    if (entry.data.component_id == component_data.component_id and entry.data.nominated) break entry.pair;
                } else unreachable;
            }
        }

        if (new_state != self.state) {
            log.debug("New Checklist state: {s} -> {s}", .{ @tagName(self.state), @tagName(new_state) });
            self.state = new_state;
        }
    }

    pub fn addTriggeredCheck(self: *Checklist, candidate_pair: CandidatePair, is_nomination: bool) bool {
        const new_entry = TriggeredCheckEntry{ .candidate_pair = candidate_pair, .is_nomination = is_nomination };
        // If it's a nomination or there is no check already in the queue, we add it.
        if (is_nomination or self.triggered_check_queue.findFirst(new_entry, TriggeredCheckEntry.eql) == null) {
            self.triggered_check_queue.push(new_entry) catch unreachable;
            return true;
        }
        return false;
    }

    fn tryPopTriggeredCheckQueue(self: *Checklist) ?TriggeredCheckEntry {
        return self.triggered_check_queue.pop() orelse return null;
    }
};

const MediaStream = struct {
    /// The id of the MediaStream.
    id: usize,
    /// The local authentication parameters used for connectivity checks.
    local_auth: AuthParameters,
    /// The remote authentication parameters used for connectivity checks.
    remote_auth: ?AuthParameters = null,

    /// The allocator used for all allocation related to the MediaStream.
    allocator: std.mem.Allocator,

    /// The local candidates associated with the MediaStream.
    local_candidates: std.ArrayList(Candidate),
    /// The remote candidates associated with the MediaStream.
    remote_candidates: std.ArrayList(Candidate),

    gathering_queue: CircularBuffer(usize, 16) = .{},
    gathering_in_progress: usize = 0,

    component_count: u8,

    /// The associated checklist.
    checklist: Checklist,

    pub fn init(id: usize, component_count: u8, local_auth: AuthParameters, allocator: std.mem.Allocator) !MediaStream {
        return MediaStream{
            .id = id,
            .local_auth = try AuthParameters.initFrom(local_auth.username_fragment, local_auth.password, allocator),
            .allocator = allocator,
            .local_candidates = std.ArrayList(Candidate).init(allocator),
            .remote_candidates = std.ArrayList(Candidate).init(allocator),
            .component_count = component_count,
            .checklist = Checklist.init(component_count),
        };
    }

    pub fn deinit(self: *MediaStream) void {
        self.local_auth.deinit(self.allocator);
        if (self.remote_auth) |remote_auth| remote_auth.deinit(self.allocator);
        self.local_candidates.deinit();
        self.remote_candidates.deinit();
    }

    pub fn setRemoteAuth(self: *MediaStream, username_fragment: []const u8, password: []const u8) !void {
        if (self.remote_auth) |remote_auth| remote_auth.deinit(self.allocator);
        self.remote_auth = try AuthParameters.initFrom(username_fragment, password, self.allocator);
    }

    /// Tries to unfreeze a candidate pair.
    fn unfreezePair(self: *MediaStream) void {
        pair: for (self.checklist.pairs.slice()) |entry| {
            if (entry.data.state != .frozen) continue;

            for (self.checklist.pairs.slice()) |other_entry| {
                if (entry.pair.eql(other_entry.pair)) continue;

                const have_same_foundation = entry.data.foundation.eql(other_entry.data.foundation);
                const other_state = other_entry.data.state;
                if ((other_state == .waiting or other_state == .in_progress) and have_same_foundation) continue :pair;
            }

            // If we are here, we didn't find another pair with the same foundation in the waiting or in_progress state.
            self.setPairState(entry.pair, .waiting);
            return;
        }
    }

    /// Returns the candidate pair in "waiting" state with the highest priority and lowest component ID, or null if there is none.
    fn getWaitingPair(self: *MediaStream) ?CandidatePair {
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

    fn getLocalCandidateIndexFromTransportAddress(self: *const MediaStream, address: std.net.Address) ?usize {
        return for (self.local_candidates.items, 0..) |c, i| {
            if (c.transport_address.eql(address)) break i;
        } else null;
    }

    fn getRemoteCandidateIndexFromTransportAddress(self: *const MediaStream, address: std.net.Address) ?usize {
        return for (self.remote_candidates.items, 0..) |c, i| {
            if (c.transport_address.eql(address)) break i;
        } else null;
    }

    /// Form candidate pairs.
    fn formPairs(local_candidates: []const Candidate, remote_candidates: []const Candidate, role: AgentRole, allocator: std.mem.Allocator) !std.ArrayList(CandidatePairEntry) {
        var pair_list = std.ArrayList(CandidatePairEntry).init(allocator);
        errdefer pair_list.deinit();

        for (local_candidates, 0..) |local_candidate, i| {
            const local_component_id = local_candidate.component_id;
            const local_address_family = local_candidate.transport_address.any.family;
            for (remote_candidates, 0..) |remote_candidate, j| {
                const remote_component_id = remote_candidate.component_id;
                const remote_address_family = remote_candidate.transport_address.any.family;
                if (local_component_id == remote_component_id and local_address_family == remote_address_family) {
                    const candidate_pair = CandidatePair{ .local_candidate_index = i, .remote_candidate_index = j };
                    const candidate_pair_data = CandidatePairData{
                        .priority = computePairPriority(local_candidate.priority, remote_candidate.priority, role),
                        .foundation = CandidatePairFoundation{ .local = local_candidate.foundation, .remote = remote_candidate.foundation },
                        .component_id = local_candidate.component_id,
                    };
                    try pair_list.append(CandidatePairEntry{ .pair = candidate_pair, .data = candidate_pair_data });
                }
            }
        }

        return pair_list;
    }

    /// Prune pairs by removing redundant ones.
    fn prunePairs(self: MediaStream, pair_list: *std.ArrayList(CandidatePairEntry)) void {
        // Replace reflexive candidate with their base as per https://www.rfc-editor.org/rfc/rfc8445#section-6.1.2.4.
        for (pair_list.items) |*candidate_pair_entry| {
            const local_candidate = self.local_candidates.items[candidate_pair_entry.pair.local_candidate_index];

            if (local_candidate.type == .server_reflexive) {
                const new_local_candidate_index = for (self.local_candidates.items, 0..) |c, i| {
                    if (c.type == .host and c.transport_address.eql(local_candidate.base_address)) break i;
                } else unreachable;
                candidate_pair_entry.pair.local_candidate_index = new_local_candidate_index;
            }
        }

        // Remove redundant pairs as per https://www.rfc-editor.org/rfc/rfc8445#section-6.1.2.4.
        var current_index: usize = 0;
        while (current_index < pair_list.items.len - 1) : (current_index += 1) {
            const current_candidate_pair_entry = pair_list.items[current_index];

            const current_local_candidate_index = current_candidate_pair_entry.pair.local_candidate_index;
            const current_local_candidate = self.local_candidates.items[current_local_candidate_index];
            const current_remote_candidate_index = current_candidate_pair_entry.pair.remote_candidate_index;

            var other_index: usize = current_index + 1;
            while (other_index < pair_list.items.len) {
                const other_candidate_pair_entry = pair_list.items[other_index];
                const other_local_candidate_index = other_candidate_pair_entry.pair.local_candidate_index;
                const other_local_candidate = self.local_candidates.items[other_local_candidate_index];
                const other_remote_candidate_index = other_candidate_pair_entry.pair.remote_candidate_index;

                const have_same_local_candidate_base = std.net.Address.eql(current_local_candidate.base_address, other_local_candidate.base_address);
                const have_same_remote_candidate = current_remote_candidate_index == other_remote_candidate_index;

                if (have_same_local_candidate_base and have_same_remote_candidate) {
                    // The list should already be ordered. Otherwise, something is wrong.
                    std.debug.assert(current_candidate_pair_entry.data.priority >= other_candidate_pair_entry.data.priority);

                    // Remove lower priority redundant pairs but keep ordering.
                    _ = pair_list.orderedRemove(other_index);

                    continue;
                }

                other_index += 1;
            }
        }
    }

    pub fn recomputePairs(self: *MediaStream, role: AgentRole) !void {
        var arena_state = std.heap.ArenaAllocator.init(self.allocator);
        defer arena_state.deinit();

        const arena = arena_state.allocator();

        var pair_list = try formPairs(self.local_candidates.items, self.remote_candidates.items, role, arena);
        defer pair_list.deinit();

        const SortContext = struct {
            entries: []CandidatePairEntry,
            pub fn lessThan(ctx: @This(), a: usize, b: usize) bool {
                return ctx.entries[a].data.priority > ctx.entries[b].data.priority;
            }
            pub fn swap(ctx: @This(), a: usize, b: usize) void {
                std.mem.swap(CandidatePairEntry, &ctx.entries[a], &ctx.entries[b]);
            }
        };

        std.sort.heapContext(0, pair_list.items.len, SortContext{ .entries = pair_list.items });

        self.prunePairs(&pair_list);

        if (pair_list.items.len > Configuration.candidate_pair_limit) {
            try pair_list.resize(Configuration.candidate_pair_limit);
        }

        var new_pairs = OrderedPairArray.init();

        for (pair_list.items) |candidate_pair_entry| {
            const new_entry = self.checklist.getEntry(candidate_pair_entry.pair) orelse &candidate_pair_entry;
            new_pairs.insert(new_entry.*);
        }
        self.checklist.pairs = new_pairs;
    }

    pub fn addLocalCandidate(self: *MediaStream, candidate: Candidate) !void {
        const candidate_index = self.local_candidates.items.len;
        try self.local_candidates.append(candidate);

        if (candidate.type == .host) {
            self.gathering_queue.push(candidate_index) catch {
                log.warn("Failed to add candidate to gathering queue", .{});
                return;
            };
            self.gathering_in_progress += 1;
        }
    }

    /// Remove redundant local candidates.
    fn removeRedundantCandidates(self: *MediaStream) void {
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

    fn setPairState(self: *MediaStream, candidate_pair: CandidatePair, state: CandidatePairState) void {
        if (self.checklist.setPairState(candidate_pair, state)) {
            self.checklist.updateState();
        }
    }

    fn printLocalCandidates(self: MediaStream) void {
        for (self.local_candidates.items, 0..) |c, i| {
            log.debug("{}: {}", .{ i, c });
        }
    }

    fn printRemoteCandidates(self: MediaStream) void {
        for (self.remote_candidates.items, 0..) |c, i| {
            log.debug("{}: {}", .{ i, c });
        }
    }
};

/// Represents the context used in a connectivity check.
const ConnectivityCheckContext = struct {
    /// The socket associated with the check.
    socket_index: usize,
    /// The id of the media stream associated with the check.
    media_stream_id: usize,
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
    /// The id of the media stream associated with the gathering.
    media_stream_id: usize,
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

    pub inline fn transactionId(self: StunContext) u96 {
        return switch (self) {
            inline else => |v| v.transaction.transaction_id,
        };
    }

    pub fn cancel(self: *StunContext, loop: *xev.Loop) void {
        switch (self.*) {
            inline else => |*v| v.transaction.cancel(loop),
        }
    }
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

        const base64_buffer = try allocator.alloc(u8, 8 + 24);
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

const GatheringQueue = CircularBuffer(struct { media_stream_id: usize, candidate_index: usize }, 16);

/// Represents an address from a local interface as well as its associated preference.
const AddressEntry = struct {
    address: std.net.Address,
    preference: u16,
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

    // TODO(Corendos,@Temporary):
    has_remote_parameters: bool = false,

    /// A pool of buffer that can be used for network IO.
    buffer_pool: std.heap.MemoryPool([4096]u8),

    /// A fixed size array of STUN context entry that can be used to gather candidates or perform connectivity checks.
    stun_context_entries: *[64]?StunContext,

    /// Contains bound sockets.
    sockets: std.ArrayList(Socket),
    /// A pool of socket data.
    socket_data_pool: std.heap.MemoryPool(SocketData),

    // Gathering related fields.

    /// The timer that fires when a new candidate can be checked.
    gathering_main_timer: xev.Timer,
    /// The associated xev.Completion.
    gathering_main_timer_completion: xev.Completion = .{},
    /// The xev.Completion used to cancel the gathering timer.
    gathering_main_timer_cancel_completion: xev.Completion = .{},
    /// The agent gathering state.
    gathering_state: GatheringState = .idle,

    // Connectivity checks related fields.

    /// The checklists used to check candidate pairs.
    media_streams: std.ArrayList(MediaStream),

    /// The timer that fires when a connectivity check needs to be done.
    connectivity_checks_timer: xev.Timer,
    /// The associated xev.Completion.
    connectivity_checks_timer_completion: xev.Completion = .{},
    /// The completion used to cancel the connectivity checks timer.
    connectivity_checks_timer_cancel_completion: xev.Completion = .{},

    /// Represents the current checklist to use for connectivity checks.
    current_checklist_index: usize = 0,

    /// Queue of response to send when ready.
    check_response_queue: *CircularBuffer(ResponseEntry, 64),
    check_response_queue_write_buffer: []u8 = &.{},
    check_response_queue_write_data: WriteData = .{},
    check_response_queue_write_completion: xev.Completion = .{},

    // NOTE(Corendos): ^ We could have one completion/buffer/data per socket.

    // Other fields.
    address_entries: []AddressEntry = &.{},

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

        var socket_data_pool = std.heap.MemoryPool(SocketData).init(allocator);
        errdefer socket_data_pool.deinit();

        const check_response_queue_write_buffer = try buffer_pool.create();
        errdefer buffer_pool.destroy(check_response_queue_write_buffer);

        const stun_context_entries = try allocator.create([64]?StunContext);
        errdefer allocator.destroy(stun_context_entries);
        @memset(stun_context_entries[0..], null);

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
            .sockets = std.ArrayList(Socket).init(allocator),
            .socket_data_pool = socket_data_pool,
            .media_streams = std.ArrayList(MediaStream).init(allocator),
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

        for (self.sockets.items) |s| s.cancel(self.loop);

        for (self.stun_context_entries) |*maybe_stun_context| if (maybe_stun_context.*) |*stun_context| {
            stun_context.cancel(self.loop);
        };

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
        for (self.sockets.items) |s| if (!s.done()) return false;
        for (self.stun_context_entries) |maybe_stun_context| if (maybe_stun_context) |_| return false;
        if (self.gathering_main_timer_completion.state() != .dead or self.gathering_main_timer_cancel_completion.state() != .dead) return false;
        if (self.connectivity_checks_timer_completion.state() != .dead or self.connectivity_checks_timer_cancel_completion.state() != .dead) return false;

        return true;
    }

    /// Deinitializes an agent.
    pub fn deinit(self: *AgentContext) void {
        std.debug.assert(self.done());

        self.allocator.free(self.address_entries);

        self.allocator.destroy(self.check_response_queue);
        self.allocator.destroy(self.stun_context_entries);
        for (self.media_streams.items) |*media_stream| media_stream.deinit();
        self.media_streams.deinit();

        self.socket_data_pool.deinit();
        for (self.sockets.items) |s| s.deinit();
        self.sockets.deinit();

        self.buffer_pool.deinit();
        self.connectivity_checks_timer.deinit();
        self.gathering_main_timer.deinit();

        self.local_auth.deinit(self.allocator);
        if (self.remote_auth) |remote_auth| {
            remote_auth.deinit(self.allocator);
        }
    }

    /// Returns a MediaStream index from its id, or null if not found.
    fn getMediaStreamIndexFromId(self: *AgentContext, media_stream_id: usize) ?usize {
        return for (self.media_streams.items, 0..) |*media_stream, i| {
            if (media_stream.id == media_stream_id) break i;
        } else null;
    }

    /// Returns a MediaStream from its id, or null if not found.
    fn getMediaStreamFromId(self: *AgentContext, media_stream_id: usize) ?*MediaStream {
        const index = self.getMediaStreamIndexFromId(media_stream_id) orelse return null;
        return &self.media_streams.items[index];
    }

    fn restartGathering(self: *AgentContext) void {
        if (self.flags.stopped) return;
        if (self.gathering_main_timer_completion.state() == .active) return;

        self.gathering_main_timer.run(
            self.loop,
            &self.gathering_main_timer_completion,
            Configuration.new_transaction_interval_ms,
            AgentContext,
            self,
            mainTimerCallback,
        );
    }

    /// Computes the local preference associated with the given addresses.
    fn computeAddressPreferences(addresses: []std.net.Address, allocator: std.mem.Allocator) ![]u16 {
        const preferences = try allocator.alloc(u16, addresses.len);
        errdefer allocator.free(preferences);

        var ipv4_count: usize = 0;
        var ipv6_count: usize = 0;
        for (addresses) |a| {
            switch (a.any.family) {
                std.os.AF.INET => ipv4_count += 1,
                std.os.AF.INET6 => ipv6_count += 1,
                else => unreachable,
            }
        }

        const head_start = (ipv4_count + ipv6_count) / ipv4_count;

        // This handles the intermingling of IPv4 and IPv6 as well as the head start for IPv6 (as specified in https://datatracker.ietf.org/doc/html/rfc8421#section-4)
        var current_ipv4_preference: usize = 65535 - 2 * head_start + 1;
        var current_ipv6_preference: usize = 65535;

        // NOTE(Corendos): by initalizing the ipv4 preference to `max - 2 * head_start + 1`, we make sure that `head_start` ipv6 are inserted before the first ipv4.
        //                 Since it's easier to understand with an example, here it goes with (head_start == 1):
        //                 65535 <- First IPv6
        //                 65534 <- First IPv4
        //                 65533 <- Second IPv6
        //                 65532 <- Second IPv4
        //                 ...

        // NOTE(Corendos): number is not optimal as when there is only one type of IP left, we decrement by 2. But I guess that's ok for now.

        for (preferences, addresses) |*p, a| {
            switch (a.any.family) {
                std.os.AF.INET => {
                    p.* = @intCast(current_ipv4_preference);
                    current_ipv4_preference -= 2;
                },
                std.os.AF.INET6 => {
                    p.* = @intCast(current_ipv6_preference);
                    current_ipv6_preference -= 2;
                },
                else => unreachable,
            }
        }

        return preferences;
    }

    pub fn processAddMediaStream(self: *AgentContext, media_stream_id: usize, component_count: u8) AddMediaStreamError!void {
        if (self.getMediaStreamIndexFromId(media_stream_id)) |_| return error.AlreadyExists;

        var media_stream = MediaStream.init(media_stream_id, component_count, self.local_auth, self.allocator) catch return error.Unexpected;
        errdefer media_stream.deinit();

        self.media_streams.append(media_stream) catch return error.Unexpected;
    }

    pub fn processRemoveMediaStream(self: *AgentContext, media_stream_id: usize) !void {
        _ = media_stream_id;
        _ = self;
        @panic("TODO: Implement MediaStream removal");
    }

    /// Starts any required operation to gather candidates.
    /// This should only be called by the zice Context.
    pub fn processGatherCandidates(self: *AgentContext) !void {
        // By default, assume that we are in the controlling role if we are explicitly asked to gather candidates.
        if (self.role == null) {
            self.role = .controlling;
        }

        self.gathering_state = .gathering;

        self.address_entries = b: {
            const addresses = try self.context.getValidCandidateAddresses(self.allocator);
            defer self.allocator.free(addresses);

            const address_preferences = try computeAddressPreferences(addresses, self.allocator);
            defer self.allocator.free(address_preferences);

            const entries = try self.allocator.alloc(AddressEntry, addresses.len);
            for (entries, addresses, address_preferences) |*entry, address, preference| {
                entry.* = .{ .address = address, .preference = preference };
            }

            break :b entries;
        };

        for (self.media_streams.items) |*media_stream| {
            for (1..media_stream.component_count + 1) |component_id| {
                for (self.address_entries, 0..) |entry, i| {
                    const socket_data = try self.socket_data_pool.create();
                    socket_data.* = .{
                        .socket_index = self.sockets.items.len,
                    };
                    errdefer self.socket_data_pool.destroy(socket_data);

                    const socket = try Socket.init(entry.address, socket_data);
                    errdefer socket.deinit();

                    socket.start(self.loop, self, readCallback);
                    errdefer socket.cancel(self.loop);

                    try self.sockets.append(socket);

                    const candidate = Candidate{
                        .type = .host,
                        .base_address = socket.address,
                        .transport_address = socket.address,
                        .priority = computePriority(CandidateType.preference(.host), entry.preference, @intCast(component_id)),
                        .foundation = Foundation{
                            .type = .host,
                            // TODO(Corentin): When supported, get that from the socket.
                            .protocol = .udp,
                            .address_index = @intCast(i),
                        },
                        .component_id = @intCast(component_id),
                    };
                    try media_stream.addLocalCandidate(candidate);
                    self.on_candidate_callback(self.userdata, self, .{
                        .candidate = .{
                            .media_stream_id = media_stream.id,
                            .candidate = candidate,
                        },
                    });
                }
            }
        }

        self.restartGathering();
    }

    /// Sets the remote candidates and starts any required operations.
    /// This should only be called by the zice Context.
    fn processSetRemoteCandidates(self: *AgentContext, parameters: RemoteCandidateParameters) !void {
        // If we don't have a role yet, we can assume that the other agent is the controlling one.
        if (self.role == null) {
            self.role = .controlled;
        }

        for (parameters.media_stream_parameters) |media_stream_parameters| {
            const media_stream = self.getMediaStreamFromId(media_stream_parameters.media_stream_id) orelse {
                log.warn("Agent {} - No MediaStream with id={} found", .{ self.id, media_stream_parameters.media_stream_id });
                continue;
            };
            try media_stream.remote_candidates.appendSlice(media_stream_parameters.candidates);
            try media_stream.setRemoteAuth(media_stream_parameters.username_fragment, media_stream_parameters.password);
        }
        self.has_remote_parameters = true;

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
        const media_stream = self.getMediaStreamFromId(completion.op.send.data_stream_id) orelse return error.InvalidId;
        const component_data = for (media_stream.checklist.component_data[0..media_stream.checklist.component_count]) |*component_data| {
            if (component_data.component_id == completion.op.send.component_id) break component_data;
        } else return error.InvalidId;

        if (component_data.selected_pair) |selected_pair| {
            const local_candidate = media_stream.local_candidates.items[selected_pair.local_candidate_index];
            const remote_candidate = media_stream.remote_candidates.items[selected_pair.remote_candidate_index];

            const socket = self.sockets.items[self.getSocketIndexFromAddress(local_candidate.base_address).?];

            const parameters = &completion.op.send;

            parameters.write_data.from(remote_candidate.transport_address, parameters.data);
            parameters.write_completion = xev.Completion{
                .op = .{
                    .sendmsg = .{
                        .fd = socket.fd,
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
        for (self.media_streams.items) |*media_stream| {
            media_stream.recomputePairs(self.role.?) catch unreachable;
        }
        self.computeInitialCandidatePairsState();
        self.printPairStates();

        self.handleConnectivityCheckMainTimer({}) catch unreachable;
    }

    inline fn getSocketIndexFromAddress(self: *AgentContext, address: std.net.Address) ?usize {
        return for (self.sockets.items, 0..) |socket, i| {
            if (socket.address.eql(address)) break i;
        } else null;
    }

    fn computeInitialCandidatePairsState(self: *AgentContext) void {
        var arena_state = std.heap.ArenaAllocator.init(self.allocator);
        defer arena_state.deinit();

        var foundation_map = std.AutoHashMap(CandidatePairFoundation, struct { media_stream_index: usize, candidate_pair: CandidatePair }).init(arena_state.allocator());

        for (self.media_streams.items, 0..) |media_stream, media_stream_index| {
            const checklist = media_stream.checklist;

            for (checklist.pairs.slice()) |entry| {
                // Compute pair foundation
                const local_candidate = media_stream.local_candidates.items[entry.pair.local_candidate_index];

                // Get hash map entry if it exists.
                const gop = foundation_map.getOrPut(entry.data.foundation) catch unreachable;

                if (!gop.found_existing) {
                    // If it doesn't exist yet, we store this checklist and pair as the one that will be put in the Waiting state.
                    gop.value_ptr.* = .{ .media_stream_index = media_stream_index, .candidate_pair = entry.pair };
                } else {
                    // Otherwise, we compare the component IDs and/or priorities to select the one that will be put in the Waiting state.
                    const stored_candidate_pair = gop.value_ptr.candidate_pair;

                    const stored_media_stream = &self.media_streams.items[gop.value_ptr.media_stream_index];
                    const stored_local_candidate = stored_media_stream.local_candidates.items[stored_candidate_pair.local_candidate_index];

                    const has_lower_component_id = local_candidate.component_id < stored_local_candidate.component_id;
                    const has_higher_priority = local_candidate.component_id == stored_local_candidate.component_id and local_candidate.priority > stored_local_candidate.priority;
                    if (has_lower_component_id or has_higher_priority) {
                        gop.value_ptr.* = .{ .media_stream_index = media_stream_index, .candidate_pair = entry.pair };
                    }
                }
            }
        }

        var it = foundation_map.iterator();
        while (it.next()) |entry| {
            const media_stream = &self.media_streams.items[entry.value_ptr.media_stream_index];
            const candidate_pair = entry.value_ptr.candidate_pair;
            media_stream.setPairState(candidate_pair, .waiting);
        }
    }

    pub fn handleNomination(self: *AgentContext, media_stream: *MediaStream, candidate_pair: CandidatePair, loop: *xev.Loop) void {
        log.debug("Agent {} - Candidate pair {}:{} nominated for media stream {}", .{ self.id, candidate_pair.local_candidate_index, candidate_pair.remote_candidate_index, media_stream.id });
        const nominated_entry = media_stream.checklist.getValidEntry(candidate_pair) orelse @panic("TODO: Nominated a candidate pair that is not in the valid list yet");
        nominated_entry.data.nominated = true;

        const valid_local_candidate = media_stream.local_candidates.items[candidate_pair.local_candidate_index];

        if (media_stream.checklist.state == .running) {
            // Remove pairs with same component ID from the triggered_check_queue.
            var index: usize = 0;
            while (index < media_stream.checklist.triggered_check_queue.count()) {
                const current = media_stream.checklist.triggered_check_queue.get(index);
                const current_local_candidate = media_stream.local_candidates.items[current.candidate_pair.local_candidate_index];
                if (current_local_candidate.component_id == valid_local_candidate.component_id) {
                    _ = media_stream.checklist.triggered_check_queue.orderedRemove(index);
                    continue;
                }
                index += 1;
            }

            // Remove pairs with same component ID from the checklist.
            index = 0;
            while (index < media_stream.checklist.pairs.slice().len) {
                const current_entry = &media_stream.checklist.pairs.slice()[index];

                const current_local_candidate = media_stream.local_candidates.items[current_entry.pair.local_candidate_index];

                if (!current_entry.pair.eql(candidate_pair) and current_local_candidate.component_id == valid_local_candidate.component_id) {
                    // Cancel in-progress transaction for the removed entry.
                    for (self.stun_context_entries) |*maybe_stun_context| {
                        if (maybe_stun_context.*) |*stun_context| {
                            if (stun_context.* != .check) continue;
                            const check_context = &stun_context.check;
                            if (check_context.candidate_pair.eql(current_entry.pair)) {
                                check_context.transaction.stopRetransmits(loop);
                                check_context.flags.is_canceled = true;
                            }
                        }
                    }

                    _ = media_stream.checklist.pairs.remove(index);

                    continue;
                }

                index += 1;
            }
        }
    }

    pub fn updateState(self: *AgentContext) void {
        log.debug("Agent {} - Updating state", .{self.id});
        var completed_state_count: usize = 0;
        var failed_state_count: usize = 0;
        for (self.media_streams.items) |*media_stream| {
            media_stream.checklist.updateState();
            switch (media_stream.checklist.state) {
                // If at least one checklist is still in the running state, the ICE process can't be failed nor completed.
                .running => {
                    self.setState(.running);
                    return;
                },
                .failed => failed_state_count += 1,
                .completed => completed_state_count += 1,
            }
        }
        if (failed_state_count == self.media_streams.items.len) {
            self.setState(.failed);
        } else if (completed_state_count == self.media_streams.items.len) {
            self.setState(.completed);
        } else {
            self.setState(.running);
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

    pub fn setGatheringState(self: *AgentContext, new_state: GatheringState) void {
        const old_state = self.gathering_state;
        if (new_state == old_state) return;
        self.gathering_state = new_state;

        log.debug("Agent {} - Gathering State changed from \"{s}\" to \"{s}\"", .{ self.id, @tagName(old_state), @tagName(new_state) });

        if (new_state == .done) {
            for (self.media_streams.items) |*media_stream| {
                media_stream.removeRedundantCandidates();

                // Select the first server reflexive candidate to be the default candidate.
                for (media_stream.local_candidates.items) |*candidate| {
                    if (candidate.type == .server_reflexive) {
                        candidate.default = true;
                        break;
                    }
                }
            }

            self.on_candidate_callback(self.userdata, self, .{ .done = {} });

            if (self.has_remote_parameters) {
                self.startChecks();
            }
        }
    }

    /// Single entrypoint for all gathering related events (STUN message received, transaction completed or main timer fired).
    /// The rationale to have a single function instead of multiple callback is that it makes it easier to know exactly when the gathering is done.
    fn handleGatheringEvent(
        self: *AgentContext,
        result: GatheringEventResult,
    ) void {
        switch (result) {
            .read => |r| {
                const gathering_context = &self.stun_context_entries[r.stun_context_index].?.gathering;
                self.handleGatheringResponseRead(gathering_context, r.raw_message) catch @panic("TODO");
            },
            .completed => |r| {
                const gathering_context = &self.stun_context_entries[r.stun_context_index].?.gathering;
                self.handleGatheringTransactionCompleted(gathering_context, r.result);
                self.releaseStunContextIndex(r.stun_context_index);

                if (self.gathering_state == .gathering) {
                    const gathering_still_in_progress = for (self.media_streams.items) |media_stream| {
                        if (media_stream.gathering_in_progress != 0) break true;
                    } else false;

                    if (!gathering_still_in_progress) {
                        self.setGatheringState(.done);
                    }
                }
            },
            .main_timer => |r| self.handleGatheringMainTimer(r),
        }
    }

    fn handleGatheringResponseRead(
        self: *AgentContext,
        gathering_context: *GatheringContext,
        raw_message: []const u8,
    ) !void {
        const media_stream = self.getMediaStreamFromId(gathering_context.media_stream_id) orelse {
            log.warn("Agent {} - Received gathering response for unknown Media Stream {}", .{ self.id, gathering_context.media_stream_id });
            return;
        };
        const candidate = media_stream.local_candidates.items[gathering_context.candidate_index];
        log.debug("Agent {} - Received STUN response for base address \"{}\"", .{ self.id, candidate.base_address });

        gathering_context.transaction.readCallback(self.loop, raw_message, undefined);
    }

    fn handleGatheringTransactionCompleted(
        self: *AgentContext,
        gathering_context: *GatheringContext,
        result: TransactionResult,
    ) void {
        const media_stream = self.getMediaStreamFromId(gathering_context.media_stream_id) orelse {
            log.warn("Agent {} - Gathering transaction complete for unknown Media Stream {}", .{ self.id, gathering_context.media_stream_id });
            return;
        };
        const host_candidate = media_stream.local_candidates.items[gathering_context.candidate_index];

        media_stream.gathering_in_progress -= 1;

        const payload = result catch |err| {
            log.debug("Agent {} - Gathering failed with {} for base address \"{}\"", .{ self.id, err, host_candidate.base_address });
            return;
        };

        var buffer: [4096]u8 = undefined;
        const message = b: {
            var arena_state = std.heap.FixedBufferAllocator.init(&buffer);
            var stream = std.io.fixedBufferStream(payload.raw_message);
            const reader = stream.reader();
            break :b ztun.Message.readAlloc(arena_state.allocator(), reader) catch unreachable;
        };

        if (getMappedAddressFromStunMessage(message)) |transport_address| {
            const candidate = Candidate{
                .type = .server_reflexive,
                .transport_address = transport_address,
                .base_address = host_candidate.base_address,
                .priority = computePriority(
                    CandidateType.preference(.server_reflexive),
                    extractLocalPreference(host_candidate.priority),
                    host_candidate.component_id,
                ),
                .foundation = Foundation{
                    .type = .server_reflexive,
                    // TODO(Corentin): When supported, get that from the socket.
                    .protocol = .udp,
                    .address_index = @intCast(gathering_context.candidate_index),
                },
                .component_id = host_candidate.component_id,
            };
            media_stream.addLocalCandidate(candidate) catch unreachable;
            self.on_candidate_callback(self.userdata, self, .{
                .candidate = .{
                    .media_stream_id = media_stream.id,
                    .candidate = candidate,
                },
            });
        }

        log.debug("Agent {} - Gathering done for base address \"{}\"", .{ self.id, host_candidate.base_address });
    }

    fn getFreeStunContextIndex(self: *AgentContext) ?usize {
        return for (self.stun_context_entries, 0..) |*maybe_stun_context, index| {
            if (maybe_stun_context.* == null) {
                break index;
            }
        } else return null;
    }

    fn releaseStunContextIndex(self: *AgentContext, index: usize) void {
        if (self.stun_context_entries[index]) |*stun_context| {
            switch (stun_context.*) {
                inline else => |*ctx| {
                    self.buffer_pool.destroy(@alignCast(ctx.transaction.write_buffer[0..4096]));
                    self.buffer_pool.destroy(@alignCast(ctx.transaction.read_buffer[0..4096]));
                    ctx.transaction.deinit();
                },
            }
            self.stun_context_entries[index] = null;
        }
    }

    fn getStunContextIndexFromTransactionId(self: *AgentContext, transaction_id: u96) ?usize {
        return for (self.stun_context_entries, 0..) |*maybe_stun_context, i| {
            if (maybe_stun_context.*) |*stun_context| {
                if (stun_context.transactionId() == transaction_id) break i;
            }
        } else null;
    }

    fn handleGatheringMainTimer(self: *AgentContext, result: xev.Timer.RunError!void) void {
        _ = result catch |err| {
            if (err == error.Canceled and self.flags.stopped) return;
            log.err("{}", .{err});
            @panic("TODO");
        };

        const media_stream, const candidate_index = for (self.media_streams.items) |*media_stream| {
            if (media_stream.gathering_queue.pop()) |candidate_index| break .{ media_stream, candidate_index };
        } else {
            return;
        };

        const candidate = media_stream.local_candidates.items[candidate_index];

        const socket_index = self.getSocketIndexFromAddress(candidate.base_address) orelse unreachable;
        const socket = self.sockets.items[socket_index];

        const address = switch (candidate.base_address.any.family) {
            std.os.AF.INET => Configuration.stun_address_ipv4,
            std.os.AF.INET6 => Configuration.stun_address_ipv6,
            else => unreachable,
        };

        var buffer: [4096]u8 = undefined;
        const request = r: {
            var allocator = std.heap.FixedBufferAllocator.init(&buffer);
            break :r makeBasicBindingRequest(allocator.allocator(), null) catch unreachable;
        };

        const stun_context_index = self.getFreeStunContextIndex() orelse unreachable;

        const write_buffer = self.buffer_pool.create() catch unreachable;
        errdefer self.buffer_pool.destroy(write_buffer);

        const read_buffer = self.buffer_pool.create() catch unreachable;
        errdefer self.buffer_pool.destroy(read_buffer);

        const transaction = Transaction.init(
            socket.fd,
            address,
            request,
            write_buffer,
            read_buffer,
            self,
            gatheringTransactionCompleteCallback,
        );
        errdefer transaction.deinit();

        self.stun_context_entries[stun_context_index] = .{
            .gathering = .{
                .socket_index = candidate_index,
                .media_stream_id = media_stream.id,
                .candidate_index = candidate_index,
                .transaction = transaction,
            },
        };
        errdefer self.releaseStunContextIndex(stun_context_index);

        const stun_context = &self.stun_context_entries[stun_context_index].?;

        log.debug("Agent {} - Starting transaction for base address \"{}\"", .{ self.id, candidate.base_address });
        stun_context.gathering.transaction.start(
            Configuration.computeRtoGatheringMs(self.sockets.items.len),
            self.loop,
        );

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
                self.handleConnectivityCheckRequestRead(payload.raw_message, payload.address, payload.socket_index) catch @panic("TODO: Request Read failed");
            },
            .response_write => {
                log.debug("Agent {} - Stun response sent !", .{self.id});
            },
            .response_read => |payload| {
                self.handleConnectivityCheckResponseRead(payload.raw_message, payload.address, payload.stun_context_index) catch @panic("TODO: Response read failed");
            },
            .completed => |payload| {
                self.handleConnectivityCheckTransactionCompleted(payload.stun_context_index, payload.result) catch @panic("TODO: Transaction completed failed");
                self.releaseStunContextIndex(payload.stun_context_index);
            },
            .main_timer => |payload| {
                self.handleConnectivityCheckMainTimer(payload) catch @panic("TODO: Main timer failed");
            },
        }

        // Handle response sending if required.
        if (self.check_response_queue_write_completion.state() != .active) {
            self.handleQueuedResponse();
        }

        // TODO(Corendos): This might need to be put elsewhere.
        if (self.role == .controlling) {
            for (self.media_streams.items) |*media_stream| {
                for (media_stream.checklist.component_data[0..media_stream.checklist.component_count]) |*component_data| {
                    if (!component_data.flags.nomination_in_progress) {
                        const valid_candidate_pair = for (media_stream.checklist.valid_pairs.slice()) |entry| {
                            if (entry.data.component_id == component_data.component_id and !entry.data.nominated) break entry.pair;
                        } else continue;
                        log.debug("Agent {} - Try to nominate pair {}:{} for component {} of media stream {}", .{
                            self.id,
                            valid_candidate_pair.local_candidate_index,
                            valid_candidate_pair.remote_candidate_index,
                            component_data.component_id,
                            media_stream.id,
                        });
                        if (media_stream.checklist.addTriggeredCheck(valid_candidate_pair, true)) {
                            component_data.flags.nomination_in_progress = true;
                            self.restartConnectivityCheckTimer();
                        }
                    }
                }
            }
        }

        self.updateState();
    }

    fn restartConnectivityCheckTimer(self: *AgentContext) void {
        if (self.connectivity_checks_timer_completion.state() == .active or self.flags.stopped) return;

        self.connectivity_checks_timer.run(
            self.loop,
            &self.connectivity_checks_timer_completion,
            Configuration.new_transaction_interval_ms,
            AgentContext,
            self,
            connectivityCheckTimerCallback,
        );
    }

    fn readCallback(
        userdata: ?*anyopaque,
        loop: *xev.Loop,
        c: *xev.Completion,
        result: xev.Result,
    ) xev.CallbackAction {
        _ = loop;

        const self = @as(*AgentContext, @ptrCast(@alignCast(userdata.?)));
        const socket_data = @fieldParentPtr(SocketData, "read_completion", c);
        const socket = self.sockets.items[socket_data.socket_index];

        const bytes_read = result.recvmsg catch |err| {
            if (err == error.Canceled and self.flags.stopped) return .disarm;
            log.err("Agent {} - Got {} for base address \"{}\" while reading from socket", .{ self.id, err, socket.address });
            return if (self.flags.stopped) .disarm else .rearm;
        };

        const data = socket_data.read_buffer[0..bytes_read];
        const source = socket_data.getAddress();

        const stun_header_result = b: {
            var stream = std.io.fixedBufferStream(data);
            const reader = stream.reader();
            break :b ztun.Message.readHeader(reader);
        };

        if (stun_header_result) |stun_header| {
            switch (stun_header.type.class) {
                .request => {
                    self.handleConnectivityCheckEvent(.{ .request_read = .{ .socket_index = socket_data.socket_index, .raw_message = data, .address = source } });
                },
                .indication => @panic("An indication, really ?"),
                else => {
                    if (self.getStunContextIndexFromTransactionId(stun_header.transaction_id)) |stun_context_index| {
                        switch (self.stun_context_entries[stun_context_index].?) {
                            .gathering => self.handleGatheringEvent(.{ .read = .{ .stun_context_index = stun_context_index, .raw_message = data } }),
                            .check => self.handleConnectivityCheckEvent(.{ .response_read = .{ .stun_context_index = stun_context_index, .raw_message = data, .address = source } }),
                        }
                    } else {
                        log.debug("Agent {} - Received STUN response with unknown transaction ID", .{self.id});
                    }
                },
            }
            return if (self.flags.stopped) .disarm else .rearm;
        } else |_| {}

        for (self.media_streams.items) |media_stream| {
            const remote_candidate_index = media_stream.getRemoteCandidateIndexFromTransportAddress(source) orelse continue;
            const remote_candidate = media_stream.remote_candidates.items[remote_candidate_index];
            self.on_data_callback(self.userdata, self, media_stream.id, remote_candidate.component_id, data);
        }

        return if (self.flags.stopped) .disarm else .rearm;
    }

    fn gatheringTransactionCompleteCallback(userdata: ?*anyopaque, transaction: *Transaction, result: TransactionResult) void {
        const self = @as(*AgentContext, @ptrCast(@alignCast(userdata.?)));
        const stun_context_index = self.getStunContextIndexFromTransactionId(transaction.transaction_id) orelse unreachable;

        self.handleGatheringEvent(.{ .completed = .{ .stun_context_index = stun_context_index, .result = result } });
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

        const socket = self.sockets.items[response_entry.socket_index];
        self.check_response_queue_write_completion = xev.Completion{
            .op = .{
                .sendmsg = .{
                    .fd = socket.fd,
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
        const socket_index = for (self.sockets.items, 0..) |socket, i| {
            if (socket.fd == c.op.sendmsg.fd) break i;
        } else unreachable;

        self.handleConnectivityCheckEvent(.{ .response_write = .{ .socket_index = socket_index, .result = result.sendmsg } });

        return .disarm;
    }

    fn connectivityCheckTransactionCompletedCallback(
        userdata: ?*anyopaque,
        transaction: *Transaction,
        result: TransactionResult,
    ) void {
        const self = @as(*AgentContext, @ptrCast(@alignCast(userdata.?)));
        const stun_context_index = self.getStunContextIndexFromTransactionId(transaction.transaction_id) orelse unreachable;

        self.handleConnectivityCheckEvent(.{ .completed = .{ .stun_context_index = stun_context_index, .result = result } });
    }

    fn checkMessageIntegrity(request: ztun.Message, password: []const u8) !void {
        var buffer: [4096]u8 = undefined;
        var arena_state = std.heap.FixedBufferAllocator.init(&buffer);
        if (!request.checkFingerprint(arena_state.allocator())) return error.InvalidFingerprint;

        const attribute_index = for (request.attributes, 0..) |a, i| {
            if (a.type == ztun.attr.Type.message_integrity) break i;
        } else return error.NoMessageIntegrity;

        const authentication = ztun.auth.ShortTermAuthenticationParameters{ .password = password };
        const key = try authentication.computeKeyAlloc(arena_state.allocator());

        if (!try request.checkMessageIntegrity(arena_state.allocator(), .classic, attribute_index, key)) return error.InvalidMessageIntegrity;
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

    // TODO(Corendos,@Improvement): Improve that by clearly stating the new role that is required.
    /// Switch Agent role
    fn switchRole(self: *AgentContext) void {
        const old_role = self.role.?;
        self.role = if (old_role == .controlling) .controlled else .controlling;
        log.debug("Agent {} - Switching role from {s} to {s}", .{ self.id, @tagName(old_role), @tagName(self.role.?) });
        for (self.media_streams.items) |*media_stream| {
            media_stream.recomputePairs(self.role.?) catch unreachable;
        }
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
        socket_index: usize,
    ) !void {
        // TODO(Corendos): Check if this is a peer-reflexive candidate.
        //                 See https://www.rfc-editor.org/rfc/rfc8445#section-7.3.1.3

        var buffer: [4096]u8 = undefined;
        const request = r: {
            var arena_state = std.heap.FixedBufferAllocator.init(&buffer);
            var stream = std.io.fixedBufferStream(raw_message);
            break :r try ztun.Message.readAlloc(arena_state.allocator(), stream.reader());
        };

        // Check fingerprint/integrity.
        try checkMessageIntegrity(request, self.local_auth.password);

        // Detecting and repairing role conflicts.
        if (self.detectAndRepairRoleConflict(request)) {
            // Enqueue a 487 STUN response.
            self.check_response_queue.push(ResponseEntry{
                .socket_index = socket_index,
                .transaction_id = request.transaction_id,
                .source = source,
                .flags = .{ .role_conflict = true },
            }) catch unreachable;

            // No further processing.
            return;
        }

        // Enqueue response.
        self.check_response_queue.push(ResponseEntry{
            .socket_index = socket_index,
            .transaction_id = request.transaction_id,
            .source = source,
            .flags = .{ .role_conflict = false },
        }) catch unreachable;

        const use_candidate = for (request.attributes) |a| {
            if (a.type == ztun.attr.Type.use_candidate) break true;
        } else false;

        const socket = self.sockets.items[socket_index];

        // Find local candidate whose transport address matches the address on which the request was received.
        const match_result = for (self.media_streams.items, 0..) |*media_stream, index| {
            const local_candidate_index = media_stream.getLocalCandidateIndexFromTransportAddress(socket.address) orelse continue;
            const remote_candidate_index = media_stream.getRemoteCandidateIndexFromTransportAddress(source) orelse continue;
            break .{
                .media_stream_index = index,
                .candidate_pair = CandidatePair{ .local_candidate_index = local_candidate_index, .remote_candidate_index = remote_candidate_index },
            };
        } else {
            log.warn("Failed to find a pair for local address {} and remote address {}", .{ socket.address, source });
            return;
        };
        const candidate_pair = match_result.candidate_pair;
        const media_stream = &self.media_streams.items[match_result.media_stream_index];

        log.debug("Agent {} - Received Binding request for {}:{} of media stream {}", .{ self.id, candidate_pair.local_candidate_index, candidate_pair.remote_candidate_index, media_stream.id });

        const maybe_entry = media_stream.checklist.getEntry(candidate_pair);

        if (maybe_entry) |entry| {
            // Handle triggered checks.
            switch (entry.data.state) {
                .succeeded => {
                    if (use_candidate) {
                        self.handleNomination(media_stream, candidate_pair, self.loop);
                    }
                },
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
                    log.debug("Agent {} - Adding {}:{} to the triggered check queue of media stream {}", .{ self.id, candidate_pair.local_candidate_index, candidate_pair.remote_candidate_index, media_stream.id });
                    if (entry.data.state == .in_progress) {
                        for (self.stun_context_entries) |*maybe_stun_context| {
                            if (maybe_stun_context.*) |*stun_context| {
                                if (stun_context.* != .check) continue;

                                const check_context: *ConnectivityCheckContext = &stun_context.check;
                                if (check_context.candidate_pair.eql(candidate_pair) and !check_context.flags.is_canceled) {
                                    check_context.transaction.stopRetransmits(self.loop);
                                    check_context.flags.is_canceled = true;
                                }
                            }
                        }
                    }
                    media_stream.setPairState(candidate_pair, .waiting);

                    if (media_stream.checklist.addTriggeredCheck(candidate_pair, use_candidate)) {
                        self.restartConnectivityCheckTimer();
                    }
                },
            }
        } else {
            const local_candidate = media_stream.local_candidates.items[candidate_pair.local_candidate_index];
            const remote_candidate = media_stream.remote_candidates.items[candidate_pair.remote_candidate_index];
            const candidate_pair_data = CandidatePairData{
                .priority = computePairPriority(local_candidate.priority, remote_candidate.priority, self.role.?),
                .foundation = CandidatePairFoundation{ .local = local_candidate.foundation, .remote = remote_candidate.foundation },
                .component_id = local_candidate.component_id,
                .state = .waiting,
            };
            media_stream.checklist.addPair(candidate_pair, candidate_pair_data) catch unreachable;

            if (media_stream.checklist.addTriggeredCheck(candidate_pair, use_candidate)) {
                self.restartConnectivityCheckTimer();
            }
        }
    }

    inline fn areTransportAddressesSymmetric(request_source: std.net.Address, request_destination: std.net.Address, response_source: std.net.Address, response_destination: std.net.Address) bool {
        std.log.debug("request_source: {}", .{request_source});
        std.log.debug("request_destination: {}", .{request_destination});
        std.log.debug("response_source: {}", .{response_source});
        std.log.debug("response_destination: {}", .{response_destination});
        return response_source.eql(request_destination) and response_destination.eql(request_source);
    }

    fn handleConnectivityCheckSuccessResponse(
        self: *AgentContext,
        media_stream: *MediaStream,
        candidate_pair: CandidatePair,
        is_nomination: bool,
        message: ztun.Message,
        source: std.net.Address,
    ) !void {
        _ = source;
        const local_candidate = media_stream.local_candidates.items[candidate_pair.local_candidate_index];
        const remote_candidate = media_stream.remote_candidates.items[candidate_pair.remote_candidate_index];

        const mapped_address = getMappedAddressFromStunMessage(message) orelse @panic("TODO: Failed to get mapped address from STUN message");

        // TODO(Corendos): Disabled since spec might be flawed and following it exactly results in weird behavior.
        // NOTE(Corendos): handle https://www.rfc-editor.org/rfc/rfc8445#section-7.2.5.2.1.
        //if (!areTransportAddressesSymmetric(local_candidate.transport_address, remote_candidate.transport_address, source, mapped_address)) {
        //    log.debug("Agent {} - Check failed for candidate pair ({}:{}) because source and destination are not symmetric", .{ self.id, candidate_pair.local_candidate_index, candidate_pair.remote_candidate_index });

        //    self.setPairState(candidate_pair, .failed);
        //    return;
        //}

        // Discovering Peer-Reflexive Candidates
        // TODO(Corendos): implement peer-reflexive candidates handling here.

        // Constructing a Valid Pair
        const valid_local_candidate_index = media_stream.getLocalCandidateIndexFromTransportAddress(mapped_address) orelse {
            std.log.warn("Agent {} - Failed to find a local candidate matching the mapped address: {}", .{ self.id, mapped_address });
            media_stream.setPairState(candidate_pair, .failed);
            return;
        };
        const valid_remote_candidate_index = media_stream.getRemoteCandidateIndexFromTransportAddress(remote_candidate.transport_address) orelse unreachable;

        const valid_candidate_pair = CandidatePair{ .local_candidate_index = valid_local_candidate_index, .remote_candidate_index = valid_remote_candidate_index };
        _ = valid_candidate_pair;

        // NOTE(Corendos): This is not exactly what is mentioned in the RFC but that makes things actually work, so...
        if (!media_stream.checklist.containsValidPair(candidate_pair)) {
            const candidate_pair_data = CandidatePairData{
                .priority = computePairPriority(local_candidate.priority, remote_candidate.priority, self.role.?),
                .foundation = CandidatePairFoundation{ .local = local_candidate.foundation, .remote = remote_candidate.foundation },
                .component_id = local_candidate.component_id,
                .state = .succeeded,
            };
            log.debug("Agent {} - Adding {}:{} to the valid list for media stream {}", .{ self.id, candidate_pair.local_candidate_index, candidate_pair.remote_candidate_index, media_stream.id });
            media_stream.checklist.addValidPair(candidate_pair, candidate_pair_data) catch unreachable;
        }

        // TODO(Corendos): Disabled since spec might be flawed and following it exactly results in weird behavior.
        //if (!valid_candidate_pair.eql(candidate_pair) and !self.checklist.containsValidPair(valid_candidate_pair)) {
        //    var valid_candidate_pair_data = self.makeCandidatePairData(valid_candidate_pair);
        //    valid_candidate_pair_data.state = .succeeded;
        //    log.debug("Agent {} - Adding {}:{} to the valid list", .{ self.id, valid_candidate_pair.local_candidate_index, valid_candidate_pair.remote_candidate_index });
        //    self.checklist.addValidPair(valid_candidate_pair, valid_candidate_pair_data) catch unreachable;
        //}

        // Add the valid pair to the valid list if needed.
        //if (valid_candidate_pair.eql(candidate_pair) or self.checklist.containsPair(valid_candidate_pair)) {
        //    // TODO(Corentin): Be careful with peer-reflexive priority.

        //    if (!self.checklist.containsValidPair(valid_candidate_pair)) {
        //        var valid_candidate_pair_data = self.makeCandidatePairData(valid_candidate_pair);
        //        valid_candidate_pair_data.state = .succeeded;
        //        log.debug("Agent {} - Adding {}:{} to the valid list", .{ self.id, valid_candidate_pair.local_candidate_index, valid_candidate_pair.remote_candidate_index });
        //        self.checklist.addValidPair(valid_candidate_pair, valid_candidate_pair_data) catch unreachable;
        //    }
        //} else {
        //    // TODO(Corendos): Not sure about that
        //    if (!self.checklist.containsValidPair(valid_candidate_pair)) {
        //        var valid_candidate_pair_data = self.makeCandidatePairData(valid_candidate_pair);
        //        valid_candidate_pair_data.state = .succeeded;
        //        log.debug("Agent {} - Adding {}:{} to the valid list", .{ self.id, valid_candidate_pair.local_candidate_index, valid_candidate_pair.remote_candidate_index });
        //        self.checklist.addValidPair(valid_candidate_pair, valid_candidate_pair_data) catch unreachable;
        //    }
        //}

        // TODO(Corendos): What to do with response when a pair has been nominated ?
        if (!media_stream.checklist.containsPair(candidate_pair)) {
            log.debug("Agent {} - Pair not present in the checklist, has a pair been nominated ?", .{self.id});
            return;
        }

        // Updating Candidate Pair States.
        media_stream.setPairState(candidate_pair, .succeeded);

        const entry = media_stream.checklist.getEntry(candidate_pair).?;

        // Set the states for all other Frozen candidate pairs in all checklists with the same foundation to Waiting
        // NOTE(Corendos): The RFC is unclear there, do we compare to the foundation of the valid pair or to the foundation of the pair that generated the check ?
        //                 In case of failure, it says "When the ICE agent sets the candidate pair state to Failed as a result of a connectivity-check error, the
        //                 agent does not change the states of other candidate pairs with the same foundation" so I guess it's the second scenario.
        for (self.media_streams.items) |*other_media_stream| {
            for (other_media_stream.checklist.pairs.slice()) |current_entry| {
                if (current_entry.data.state == .frozen and current_entry.data.foundation.eql(entry.data.foundation)) {
                    other_media_stream.setPairState(current_entry.pair, .waiting);
                }
            }
        }

        if (is_nomination) {
            self.handleNomination(media_stream, candidate_pair, self.loop);
        }
    }

    fn handleConnectivityCheckErrorResponse(self: *AgentContext, media_stream: *MediaStream, candidate_pair: CandidatePair, request_role: AgentRole, message: ztun.Message) !void {
        const error_code_attribute_opt: ?ztun.attr.common.ErrorCode = for (message.attributes) |attr| {
            if (attr.type == ztun.attr.Type.error_code) break try ztun.attr.common.ErrorCode.fromAttribute(attr);
        } else null;

        const error_code_attribute = error_code_attribute_opt orelse {
            media_stream.setPairState(candidate_pair, .failed);
            return;
        };

        switch (error_code_attribute.value) {
            .role_conflict => {
                if (request_role == self.role.?) {
                    self.switchRole();

                    if (media_stream.checklist.addTriggeredCheck(candidate_pair, false)) {
                        media_stream.setPairState(candidate_pair, .waiting);
                        self.restartConnectivityCheckTimer();
                    }

                    self.tiebreaker = std.crypto.random.int(u64);
                }
            },
            else => {
                media_stream.setPairState(candidate_pair, .failed);
            },
        }
    }

    fn handleConnectivityCheckTransactionCompleted(
        self: *AgentContext,
        stun_context_index: usize,
        result: TransactionResult,
    ) !void {
        const check_context = &self.stun_context_entries[stun_context_index].?.check;
        const media_stream = self.getMediaStreamFromId(check_context.media_stream_id) orelse unreachable;
        const candidate_pair = check_context.candidate_pair;

        const payload = result catch |err| {
            // Due to triggered check, we might never receive the answer but must not treat the lack of response as a failure.
            if (!check_context.flags.is_canceled) {
                log.debug("Agent {} - Check failed for candidate pair ({}:{}) of media stream {} with {}", .{ self.id, candidate_pair.local_candidate_index, candidate_pair.remote_candidate_index, media_stream.id, err });
                media_stream.setPairState(candidate_pair, .failed);
            }
            return;
        };

        var buffer: [4096]u8 = undefined;
        const message = b: {
            var arena_state = std.heap.FixedBufferAllocator.init(&buffer);
            var stream = std.io.fixedBufferStream(payload.raw_message);
            const reader = stream.reader();
            break :b ztun.Message.readAlloc(arena_state.allocator(), reader) catch unreachable;
        };

        if (message.type.class == .success_response) {
            try self.handleConnectivityCheckSuccessResponse(media_stream, candidate_pair, check_context.flags.is_nomination, message, payload.source);
        } else {
            try self.handleConnectivityCheckErrorResponse(media_stream, candidate_pair, check_context.flags.role, message);
        }
    }

    fn handleConnectivityCheckResponseRead(
        self: *AgentContext,
        raw_message: []const u8,
        source: std.net.Address,
        stun_context_index: usize,
    ) !void {
        const check_context = &self.stun_context_entries[stun_context_index].?.check;

        check_context.transaction.readCallback(self.loop, raw_message, source);
    }

    fn startTransaction(self: *AgentContext, media_stream: *MediaStream, candidate_pair: CandidatePair, is_triggered_check: bool, is_nominated: bool) !void {
        const local_candidate = media_stream.local_candidates.items[candidate_pair.local_candidate_index];
        const remote_candidate = media_stream.remote_candidates.items[candidate_pair.remote_candidate_index];

        const socket_index = self.getSocketIndexFromAddress(local_candidate.base_address).?;
        const socket = self.sockets.items[socket_index];

        var buffer: [4096]u8 = undefined;
        const request = r: {
            var allocator = std.heap.FixedBufferAllocator.init(&buffer);
            break :r makeConnectivityCheckBindingRequest(
                media_stream.remote_auth.?.username_fragment,
                media_stream.local_auth.username_fragment,
                media_stream.remote_auth.?.password,
                local_candidate.priority,
                self.role.?,
                self.tiebreaker,
                is_nominated,
                allocator.allocator(),
            ) catch unreachable;
        };

        const stun_context_index = self.getFreeStunContextIndex() orelse unreachable;
        errdefer self.releaseStunContextIndex(stun_context_index);

        const write_buffer = try self.buffer_pool.create();
        errdefer self.buffer_pool.destroy(write_buffer);

        const read_buffer = try self.buffer_pool.create();
        errdefer self.buffer_pool.destroy(read_buffer);

        var transaction = Transaction.init(
            socket.fd,
            remote_candidate.transport_address,
            request,
            write_buffer,
            read_buffer,
            self,
            connectivityCheckTransactionCompletedCallback,
        );
        errdefer transaction.deinit();

        self.stun_context_entries[stun_context_index] = .{
            .check = ConnectivityCheckContext{
                .socket_index = socket_index,
                .media_stream_id = media_stream.id,
                .candidate_pair = candidate_pair,
                .transaction = transaction,
                .flags = .{
                    .is_triggered_check = is_triggered_check,
                    .is_nomination = is_nominated,
                    .role = self.role.?,
                },
            },
        };

        log.debug("Agent {} - Starting {s}connectivity check from {} to {} for media stream {}", .{
            self.id,
            if (is_triggered_check) "triggered " else "",
            candidate_pair.local_candidate_index,
            candidate_pair.remote_candidate_index,
            media_stream.id,
        });

        const stun_context = &self.stun_context_entries[stun_context_index].?;

        const check_count = media_stream.checklist.pairs.slice().len;
        const waiting_count = media_stream.checklist.getPairCount(.waiting);
        const in_progress_count = media_stream.checklist.getPairCount(.in_progress);
        stun_context.check.transaction.start(Configuration.computeRtoCheckMs(check_count, waiting_count, in_progress_count), self.loop);

        media_stream.setPairState(candidate_pair, .in_progress);
    }

    fn handleConnectivityCheckMainTimer(self: *AgentContext, result: xev.Timer.RunError!void) !void {
        _ = result catch |err| {
            if (err == error.Canceled) return;
            log.err("{}", .{err});
            @panic("TODO: Main timer failed");
        };
        if (self.flags.stopped) return;

        var checklist_tried: usize = 0;

        const rearm = rearm: while (checklist_tried < self.media_streams.items.len) : (checklist_tried += 1) {
            const media_stream = &self.media_streams.items[self.current_checklist_index];

            while (media_stream.checklist.tryPopTriggeredCheckQueue()) |node| {
                const entry = media_stream.checklist.getEntry(node.candidate_pair) orelse unreachable;
                if (!node.is_nomination and entry.data.state == .succeeded) continue;
                try self.startTransaction(media_stream, node.candidate_pair, true, node.is_nomination);

                // Rearm the timer if we are not stopped.
                break :rearm if (!self.flags.stopped) true else false;
            }

            if (media_stream.checklist.getPairCount(.waiting) == 0) {
                media_stream.unfreezePair();
            }

            if (media_stream.getWaitingPair()) |candidate_pair| {
                try self.startTransaction(media_stream, candidate_pair, false, false);

                // Rearm the timer if we are not stopped.
                break if (!self.flags.stopped) true else false;
            }

            self.current_checklist_index = (self.current_checklist_index + 1) % self.media_streams.items.len;
        } else false;

        if (rearm) {
            self.connectivity_checks_timer.run(
                self.loop,
                &self.connectivity_checks_timer_completion,
                Configuration.new_transaction_interval_ms,
                AgentContext,
                self,
                connectivityCheckTimerCallback,
            );
        } else {
            log.debug("Agent {} - No more candidate pair to check", .{self.id});
        }
    }

    // Debug utilities

    const PairsFormatter = struct {
        ctx: *const MediaStream,
        pub fn format(self: PairsFormatter, comptime fmt_s: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
            _ = options;
            _ = fmt_s;
            try writer.print("Media Stream {}\n", .{self.ctx.id});

            for (self.ctx.checklist.pairs.slice()) |entry| {
                const foundation_bit_size = @bitSizeOf(Foundation.IntType);
                const pair_foundation: u64 = (@as(u64, entry.data.foundation.remote.asNumber()) << foundation_bit_size) + @as(u64, entry.data.foundation.local.asNumber());
                try writer.print("    {}:{} f:{} p:{} = {s}\n", .{ entry.pair.local_candidate_index, entry.pair.remote_candidate_index, pair_foundation, entry.data.priority, @tagName(entry.data.state) });
            }
        }
    };

    fn printPairStates(self: *const AgentContext) void {
        for (self.media_streams.items) |*media_stream| {
            log.debug("Agent {}\n{}", .{ self.id, PairsFormatter{ .ctx = media_stream } });
        }
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
        ctx: *const MediaStream,
        pub fn format(self: CandidateFormatter, comptime fmt_s: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
            _ = options;
            _ = fmt_s;
            try writer.print("Media Stream {}\n", .{self.ctx.id});

            for (self.ctx.local_candidates.items, 0..) |candidate, index| {
                try writer.print("    Local {} - {}\n", .{ index, candidate });
                //if (candidate.default) {
                //    try writer.print("    Local {} (d) - {} - {}\n", .{ index, candidate.base_address, candidate.transport_address });
                //} else {
                //    try writer.print("    Local {} - {} - {}\n", .{ index, candidate.base_address, candidate.transport_address });
                //}
            }

            for (self.ctx.remote_candidates.items, 0..) |candidate, index| {
                try writer.print("    Remote {} - {}\n", .{ index, candidate });
                //try writer.print("    Remote {} - {} - {}\n", .{ index, candidate.base_address, candidate.transport_address });
            }
        }
    };

    fn printCandidates(self: *const AgentContext) void {
        for (self.media_streams.items) |*media_stream| {
            log.debug("Agent {}\n{}", .{ self.id, CandidateFormatter{ .ctx = media_stream } });
        }
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
    read: struct { stun_context_index: usize, raw_message: []const u8 },
    /// A STUN transaction completed.
    completed: struct { stun_context_index: usize, result: TransactionResult },
    /// The main timer fired and the payload contains the result.
    main_timer: xev.Timer.RunError!void,
};

const ConnectivityCheckEventResult = union(enum) {
    request_read: struct { socket_index: usize, raw_message: []const u8, address: std.net.Address },
    response_read: struct { stun_context_index: usize, raw_message: []const u8, address: std.net.Address },
    completed: struct { stun_context_index: usize, result: TransactionResult },
    response_write: struct { socket_index: usize, result: xev.WriteError!usize },
    main_timer: xev.Timer.RunError!void,
};

pub const ContextOperationType = enum {
    add_media_stream,
    remove_media_stream,
    gather_candidates,
    set_remote_candidates,
    send,
};

pub const MediaStreamRemoteParameters = struct {
    media_stream_id: usize,
    candidates: []const Candidate,
    username_fragment: []const u8,
    password: []const u8,
};

pub const RemoteCandidateParameters = struct {
    agent_id: AgentId = undefined,
    media_stream_parameters: []MediaStreamRemoteParameters,
};

pub const MediaStreamParameters = struct {
    agent_id: AgentId,
    media_stream_id: usize,
    component_count: u8,
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
    add_media_stream: MediaStreamParameters,
    remove_media_stream: MediaStreamParameters,
    gather_candidates: AgentId,
    set_remote_candidates: RemoteCandidateParameters,
    send: SendParameters,
};

pub const InvalidError = error{
    InvalidId,
};

pub const SendError = error{NotReady} || xev.WriteError || InvalidError;

pub const AddMediaStreamError = error{ AlreadyExists, Unexpected } || InvalidError;

pub const RemoveMediaStreamError = error{} || InvalidError;

pub const ContextResult = union(ContextOperationType) {
    add_media_stream: AddMediaStreamError!void,
    remove_media_stream: RemoveMediaStreamError!void,
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

pub const CreateAgentError = error{ NoSlotAvailable, Unexpected };

pub const DeleteAgentError = InvalidError || error{Unexpected};

const context_agent_slot_bit_count = 6;
const context_agent_slot_count = 1 << context_agent_slot_bit_count;

pub const AgentId = GenerationId(u16, context_agent_slot_bit_count);

const AgentContextEntry = struct {
    flags: packed struct {
        stopped: bool = false,
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

    agent_context_entries_mutex: std.Thread.Mutex = .{},
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

    pub fn createAgent(self: *Context, options: CreateAgentOptions) CreateAgentError!AgentId {
        log.debug("Creating agent...", .{});
        self.agent_context_entries_mutex.lock();
        defer self.agent_context_entries_mutex.unlock();

        const unused_entry: *AgentContextEntry = for (&self.agent_context_entries) |*entry| {
            if (entry.agent_context == null) break entry;
        } else return error.NoSlotAvailable;

        // TODO(Corendos): Improve returned error.
        unused_entry.agent_context = AgentContext.init(self, unused_entry.agent_id, &self.loop, options, self.allocator) catch return error.Unexpected;

        return unused_entry.agent_id;
    }

    pub fn deleteAgent(self: *Context, agent_id: AgentId) DeleteAgentError!void {
        log.debug("Deleting agent with id={}...", .{agent_id.raw});
        self.agent_context_entries_mutex.lock();
        defer self.agent_context_entries_mutex.unlock();

        const entry = try self.getAgentEntry(agent_id);
        if (entry.agent_context == null or entry.flags.deleted) return error.InvalidId;
        entry.flags.deleted = true;
        self.async_handle.notify() catch {};
    }

    pub fn addMediaStream(self: *Context, agent_id: AgentId, c: *ContextCompletion, media_stream_id: usize, component_count: u8, userdata: ?*anyopaque, callback: ContextCallback) !void {
        c.* = ContextCompletion{
            .op = .{
                .add_media_stream = .{
                    .agent_id = agent_id,
                    .media_stream_id = media_stream_id,
                    .component_count = component_count,
                },
            },
            .userdata = userdata,
            .callback = callback,
        };

        self.addCompletion(c);
        try self.submitCompletions();
    }

    pub fn removeMediaStream(self: *Context, agent_id: AgentId, c: *ContextCompletion, media_stream_id: usize, userdata: ?*anyopaque, callback: ContextCallback) !void {
        c.* = ContextCompletion{
            .op = .{
                .remove_media_stream = .{
                    .agent_id = agent_id,
                    .media_stream_id = media_stream_id,
                },
            },
            .userdata = userdata,
            .callback = callback,
        };

        self.addCompletion(c);
        try self.submitCompletions();
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

    fn handleDeletion(self: *Context) void {
        self.agent_context_entries_mutex.lock();
        defer self.agent_context_entries_mutex.unlock();

        for (self.agent_context_entries[0..]) |*entry| {
            if (entry.flags.deleted) {
                if (!entry.flags.stopped) {
                    entry.agent_context.?.stop();
                } else if (entry.agent_context.?.done()) {
                    entry.agent_context.?.deinit();
                    entry.flags.deleted = false;
                    entry.agent_id.bump();
                    entry.agent_context = null;
                }
            }
        }
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

        self.handleDeletion();

        var local_queue = b: {
            self.async_queue_mutex.lock();
            defer self.async_queue_mutex.unlock();
            const q = self.async_queue;
            self.async_queue = .{};
            break :b q;
        };

        var to_reenqueue = Intrusive(ContextCompletion){};

        while (local_queue.pop()) |c| {
            log.debug("Processing {s}", .{@tagName(c.op)});
            switch (c.op) {
                .add_media_stream => |parameters| {
                    const add_media_stream_result = if (self.getAgentContext(parameters.agent_id)) |agent_context| b: {
                        agent_context.processAddMediaStream(parameters.media_stream_id, parameters.component_count) catch unreachable;
                        break :b {};
                    } else |err| err;

                    c.callback(c.userdata, ContextResult{ .add_media_stream = add_media_stream_result });
                },
                .remove_media_stream => |parameters| {
                    const remove_media_stream_result = if (self.getAgentContext(parameters.agent_id)) |agent_context| b: {
                        agent_context.processRemoveMediaStream(parameters.media_stream_id) catch unreachable;
                        break :b {};
                    } else |err| err;

                    c.callback(c.userdata, ContextResult{ .remove_media_stream = remove_media_stream_result });
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
    try std.testing.expectEqual(@as(usize, 504), @sizeOf(SocketData));
    try std.testing.expectEqual(@as(usize, 2840), @sizeOf(AgentContext));
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
