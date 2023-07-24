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

const NetlinkContext = @import("netlink.zig").NetlinkContext;

const log = std.log.scoped(.zice);

// TODO(Corendos,@Global):
// * Handle Triggered checks
// * Handle peer-reflexive
// * Properly handle connectivity checks with retry etc.

/// Represents an ICE candidate type. See https://www.rfc-editor.org/rfc/rfc8445#section-4 for definitions.
pub const CandidateType = enum(u2) {
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

/// Represents the type of the Transport Address.
pub const Protocol = enum(u2) {
    /// The addresses uses the UDP protocol.
    udp,
    /// The addresses uses the TCP protocol.
    tcp,

    // NOTE(Corendos): TCP is not supported yet.
};

pub const Foundation = packed struct {
    type: CandidateType,
    protocol: Protocol,
    address_index: u8,

    pub const IntType = std.meta.Int(.unsigned, @bitSizeOf(Foundation));

    pub inline fn as_number(self: Foundation) IntType {
        return @intCast(@as(IntType, @bitCast(self)));
    }

    pub inline fn eql(a: Foundation, b: Foundation) bool {
        return a.as_number() == b.as_number();
    }
};

test "Foundation conversions" {
    const f = Foundation{ .address_index = 1, .type = .server_reflexive, .protocol = .udp };
    try std.testing.expectEqual(@as(u16, 17), f.as_number());
}

// TODO(Corendos): Implement https://www.rfc-editor.org/rfc/rfc8421#section-4 for local preference computation

/// Represents an ICE candidate.
pub const Candidate = struct {
    /// The type of candidate.
    type: CandidateType,
    /// The candidate transport address.
    transport_address: std.net.Address,
    /// The candidate base address.
    base_address: std.net.Address,
    /// The base address id (used to compute foundation).
    base_address_id: u8,
    /// The protocol used by the candidate.
    protocol: Protocol,
    /// The candidate local preference.
    local_preference: u16 = 0,
    /// The component ID associated to the candidate.
    component_id: u8 = 1,

    // TODO(Corendos): multiple component ID support

    /// Compute the candidate Foundation.
    pub inline fn foundation(self: Candidate) Foundation {
        return Foundation{ .address_index = self.base_address_id, .type = self.type, .protocol = self.protocol };
    }

    /// Compute the candidate priority according to https://www.rfc-editor.org/rfc/rfc8445#section-5.1.2.1
    pub inline fn priority(self: Candidate) u32 {
        const type_preference: u32 = self.type.preference();
        const local_preference: u32 = self.local_preference;
        const component_id: u32 = self.component_id;
        return (type_preference << 24) + (local_preference << 8) + (256 - component_id);
    }
};

test "candidate priority" {
    const candidate_1 = Candidate{
        .type = .host,
        .transport_address = undefined,
        .base_address = undefined,
        .base_address_id = undefined,
        .protocol = undefined,
    };
    const candidate_2 = Candidate{
        .type = .server_reflexive,
        .transport_address = undefined,
        .base_address = undefined,
        .base_address_id = undefined,
        .protocol = undefined,
    };

    try std.testing.expectEqual(@as(u32, 0x7E_0000_FF), candidate_1.priority());
    try std.testing.expectEqual(@as(u32, 0x64_0000_FF), candidate_2.priority());
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

    //const stun_address_ipv4 = std.net.Address.parseIp4("91.134.140.104", 3478) catch unreachable;
    const stun_address_ipv4 = std.net.Address.parseIp4("172.253.120.127", 19302) catch unreachable;
    const stun_address_ipv6 = std.net.Address.parseIp6("2a00:1450:400c:c00::7f", 19302) catch unreachable;

    pub inline fn computeRtoMs(candidate_count: u64) u64 {
        return @max(500, candidate_count * new_transaction_interval_ms);
    }
};

/// Convenience to build a basic STUN request.
fn makeBasicBindingRequest(allocator: std.mem.Allocator) !ztun.Message {
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

fn makeUsername(
    local_username_fragment: [8]u8,
    remote_username_fragment: [8]u8,
) [17]u8 {
    var result: [17]u8 = undefined;

    @memcpy(result[0..8], &local_username_fragment);
    result[8] = ':';
    @memcpy(result[9..17], &remote_username_fragment);

    return result;
}

fn makeConnectivityCheckBindingRequest(
    local_username_fragment: [8]u8,
    remote_username_fragment: [8]u8,
    password: [24]u8,
    priority: u32,
    role: AgentRole,
    tiebreaker: u64,
    allocator: std.mem.Allocator,
) !ztun.Message {
    var message_builder = ztun.MessageBuilder.init(allocator);
    defer message_builder.deinit();

    const authentication = ztun.auth.Authentication{ .short_term = ztun.auth.ShortTermAuthentication{ .password = &password } };

    // Binding request with random transaction ID.
    message_builder.setClass(ztun.Class.request);
    message_builder.setMethod(ztun.Method.binding);
    message_builder.randomTransactionId();

    const username = makeUsername(local_username_fragment, remote_username_fragment);
    const username_attribute = try (ztun.attr.common.Username{ .value = &username }).toAttribute(allocator);
    try message_builder.addAttribute(username_attribute);

    const priority_attribute = try (ztun.attr.common.Priority{ .value = priority }).toAttribute(allocator);
    try message_builder.addAttribute(priority_attribute);

    const role_attribute = switch (role) {
        .controlling => try (ztun.attr.common.IceControlling{ .value = tiebreaker }).toAttribute(allocator),
        .controlled => try (ztun.attr.common.IceControlled{ .value = tiebreaker }).toAttribute(allocator),
    };
    try message_builder.addAttribute(role_attribute);

    message_builder.addMessageIntegrity(authentication);

    // Add a fingerprint for validity check.
    message_builder.addFingerprint();

    const message = try message_builder.build();

    return message;
}

fn makeBindingResponse(request: ztun.Message, source: std.net.Address, password: [24]u8, allocator: std.mem.Allocator) !ztun.Message {
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();

    var message_builder = ztun.MessageBuilder.init(arena_state.allocator());

    message_builder.setClass(ztun.Class.success_response);
    message_builder.setMethod(ztun.Method.binding);
    message_builder.transactionId(request.transaction_id);

    const mapped_address = toStunAddress(source);
    const xor_mapped_address = ztun.attr.common.encode(mapped_address, request.transaction_id);
    const xor_mapped_address_attribute = try xor_mapped_address.toAttribute(arena_state.allocator());
    try message_builder.addAttribute(xor_mapped_address_attribute);

    const authentication = ztun.auth.Authentication{ .short_term = .{ .password = &password } };
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
pub const OnCandidateCallback = *const fn (userdata: ?*anyopaque, agent_id: u32, result: CandidateResult) void;
fn noopCandidateCallback(_: ?*anyopaque, _: u32, _: CandidateResult) void {}

/// Callback that is called when the ICE state changes.
pub const OnStateChangeCallback = *const fn (userdata: ?*anyopaque, agent_id: u32, state: GatheringState) void;
fn noopStateChangeCallback(_: ?*anyopaque, _: u32, _: GatheringState) void {}

pub const TransactionContext = struct {
    /// The index of associated agent.
    agent_id: u32,
    /// The index of the associated socket.
    socket_index: u32,
    /// Our own index.
    index: u32,

    /// The timer that is used for retry and failure.
    timer: xev.Timer,
    /// The current timeout for the retry timer.
    timer_timeout_ms: u64 = 0,
    /// Is the timer used for a retry or for a failure.
    is_retry_timer: bool = true,
    /// The associated xev.Completion.
    timer_completion: xev.Completion = .{},
    /// The associated cancel xev.Completion
    timer_cancel_completion: xev.Completion = .{},

    /// The buffer used to send a message.
    write_buffer: []u8 = &.{},
    /// The data required to send a message.
    write_data: WriteData = undefined,
    /// The associated xev.Completion.
    write_completion: xev.Completion = .{},
    /// The transaction id of the request being sent to the STUN server.
    transaction_id: ?u96 = null,

    /// Counts the number of request sent.
    request_sent_count: u64 = 0,
    /// The current RTO (see RFC).
    rto: u64,

    /// Initialize a Candidate context from the given socket, address and rto.
    pub fn init(agent_id: u32, index: u32, socket_index: u32, write_buffer: []u8, rto: u64) !TransactionContext {
        const timer = try xev.Timer.init();
        errdefer timer.deinit();

        return .{
            .agent_id = agent_id,
            .index = index,
            .socket_index = socket_index,
            .timer = timer,
            .write_buffer = write_buffer,
            .rto = rto,
        };
    }

    /// Deinitialize a candidate context.
    pub fn deinit(self: *TransactionContext) void {
        self.timer.deinit();
    }

    /// Returns true if the gathering process seems to be done.
    pub inline fn isDone(self: *const TransactionContext) bool {
        // TODO(Corendos): Shound't we check for write_completion state ?
        return self.timer_completion.state() == .dead and
            self.timer_cancel_completion.state() == .dead;
    }
};

// TODO(Corendos): Handle socket closing properly.
pub const SocketContext = struct {
    /// The index of associated agent.
    agent_id: u32,
    /// Our index in the Agent Context.
    index: u32,

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

    pub fn init(agent_id: u32, index: u32, socket: std.os.fd_t, address: std.net.Address, read_buffer: []u8) SocketContext {
        return SocketContext{
            .agent_id = agent_id,
            .index = index,
            .socket = socket,
            .address = address,
            .read_buffer = read_buffer,
        };
    }
};

const CandidateEntry = struct {
    /// The actual candidate.
    candidate: Candidate,
    /// The socket context this candidate is associated to.
    socket_index: u32,
};

/// Represents the role of the agent in an ICE process.
const AgentRole = enum {
    /// The agent is controlling the ICE process.
    controlling,
    /// The agent is controlled by another agent.
    controlled,
};

/// Represents the state of the agent.
const AgentState = enum {
    /// The agent has been created.
    created,
    /// The agent is checking candidate pairs.
    checking,
    /// The agent connection process completed.
    completed,
    /// The agent is connected to another agent.
    connected,
    /// The agent has been disconnected from another agent.
    disconnected,
    /// The agent failed to connect to another agent.
    failed,
    /// The agent connection has been closed.
    closed,
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

/// Represents a candidate pair to check.
const CandidatePair = struct {
    /// The index of the local candidate.
    local_candidate_index: usize,
    /// The index of the remote candidate.
    remote_candidate_index: usize,
    /// The pair priority.
    priority: u64,
    /// The candidate pair state.
    state: CandidatePairState = .frozen,
    /// Has this pair been nominated ? (Only used when in a valid list).
    nominated: bool = false,
};

const CandidatePairFoundation = packed struct {
    local: Foundation,
    remote: Foundation,

    pub inline fn eql(a: CandidatePairFoundation, b: CandidatePairFoundation) bool {
        return a.local.eql(b.local) and a.remote.eql(b.remote);
    }
};

const TriggeredCheckNode = struct {
    next: ?*TriggeredCheckNode = null,
};

/// Represents a checklist that will be used to check candidate pairs.
const Checklist = struct {
    /// The state of the checklist.
    state: ChecklistState = .running,
    /// The list of candidate pairs to check.
    pairs: std.ArrayListUnmanaged(CandidatePair) = .{},
    /// Store the number of pairs in a specific state.
    state_count: [CandidatePairState.count]u8 = [_]u8{0} ** CandidatePairState.count,
    /// Valid candidate pair list.
    valid_list: std.ArrayListUnmanaged(CandidatePair) = .{},

    triggered_check_node_storage: []TriggeredCheckNode = &.{},
    free_triggered_check_node: Intrusive(TriggeredCheckNode) = .{},
    triggered_check_queue: Intrusive(TriggeredCheckNode) = .{},

    pub fn init(pairs: std.ArrayListUnmanaged(CandidatePair), allocator: std.mem.Allocator) !Checklist {
        var storage = try allocator.alloc(TriggeredCheckNode, 100);

        var free_triggered_check_node: Intrusive(TriggeredCheckNode) = .{};
        for (storage) |*node| {
            node.* = .{};
            free_triggered_check_node.push(node);
        }

        var state_count = [_]u8{0} ** CandidatePairState.count;
        for (pairs.items) |p| {
            state_count[@intFromEnum(p.state)] += 1;
        }

        return Checklist{
            .pairs = pairs,
            .state_count = state_count,
            .triggered_check_node_storage = storage,
            .free_triggered_check_node = free_triggered_check_node,
        };
    }

    pub fn deinit(self: *Checklist, allocator: std.mem.Allocator) void {
        allocator.free(self.triggered_check_node_storage);
    }

    pub inline fn setPairState(self: *Checklist, index: usize, state: CandidatePairState) void {
        const old_state = self.pairs.items[index].state;
        self.state_count[@intFromEnum(old_state)] -= 1;
        self.state_count[@intFromEnum(state)] += 1;
        self.pairs.items[index].state = state;
    }

    pub fn resize(self: *Checklist, allocator: std.mem.Allocator, new_size: usize) !void {
        std.debug.assert(new_size <= self.pairs.items.len);
        for (self.pairs.items[new_size..]) |p| {
            self.state_count[@intFromEnum(p.state)] -= 1;
        }
        try self.pairs.resize(allocator, new_size);
    }
};

const ConnectivityCheckContext = struct {
    agent_id: u32,
    socket_index: u32,

    write_buffer: []u8 = &.{},
    write_data: WriteData = .{},
    write_completion: xev.Completion = .{},

    timeout_timer: xev.Timer,
    timeout_completion: xev.Completion = .{},
    timeout_cancel_completion: xev.Completion = .{},
    timeout_occurred: bool = false,

    last_transaction_id: ?u96 = null,

    pair_foundation: CandidatePairFoundation,
};

pub const AgentContext = struct {
    const CheckContextMap = std.AutoHashMap(CandidatePairFoundation, ConnectivityCheckContext);

    /// The id of this agent.
    id: u32,

    /// The allocator used by the AgentContext.
    allocator: std.mem.Allocator,

    /// The agent state.
    state: AgentState = .created,
    /// The agent role.
    role: ?AgentRole = null,

    /// The username fragment used for connectivity checks.
    username_fragment: [8]u8,
    /// The password used for connectivity checks.
    password: [24]u8,
    /// Tiebreaker value.
    tiebreaker: u64,

    /// The remote username fragment used for connectivity checks.
    remote_username_fragment: ?[8]u8 = null,
    /// The remote password used for connectivity checks.
    remote_password: ?[24]u8 = null,

    local_candidates: std.ArrayListUnmanaged(CandidateEntry) = .{},
    remote_candidates: std.ArrayListUnmanaged(Candidate) = .{},
    has_remote_candidates: bool = false,

    buffer_arena_state: ?std.heap.ArenaAllocator = null,

    /// Contexts for each bound sockets.
    socket_contexts: []SocketContext = &.{},

    // Gathering related fields.

    /// The timer that fires when a new candidate can be checked.
    gathering_main_timer: xev.Timer,
    /// The associated xev.Completion.
    gathering_main_timer_completion: xev.Completion = .{},
    /// The agent gathering state.
    gathering_state: GatheringState = .idle,
    /// The gathering status of each server reflexive candidate.
    gathering_candidate_statuses: []CandidateGatheringStatus = &.{},
    /// The transaction context of each server reflexive candidate we are trying to gather.
    gathering_transaction_contexts: []TransactionContext = &.{},

    // Connectivity checks related fields.

    // TODO(Corendos): handle multiple data-stream.
    /// The checklists used to check candidate pairs.
    checklist: Checklist = .{},

    /// Contains the connectivity check context for each candidate pair foundation.
    check_context_map: CheckContextMap,

    /// The timer that fires when a connectivity check needs to be done.
    connectivity_checks_timer: xev.Timer,
    /// The associated xev.Completion.
    connectivity_checks_timer_completion: xev.Completion = .{},

    // TODO(Corendos): This is temporary to test how it could work.
    binding_request_queue: [64]struct { source: std.net.Address, response: ztun.Message, storage: [4096]u8 } = undefined,
    binding_queue_head: usize = 0,
    binding_queue_tail: usize = 0,

    binding_request_queue_write_buffer: []u8 = &.{},
    binding_request_queue_write_data: WriteData = .{},
    binding_request_queue_write_completion: xev.Completion = .{},

    // Other fields.

    /// Userdata that is given back in callbacks.
    userdata: ?*anyopaque,
    /// Callbacks to call when a new candidate is found during gathering (or when there won't be any new candidates).
    on_candidate_callback: OnCandidateCallback,
    /// Callback to call when the gathering state changes.
    on_state_change_callback: OnStateChangeCallback,

    inline fn computePairFoundation(self: *const AgentContext, pair: CandidatePair) CandidatePairFoundation {
        const local_foundation = self.local_candidates.items[pair.local_candidate_index].candidate.foundation();
        const remote_foundation = self.remote_candidates.items[pair.remote_candidate_index].foundation();
        return CandidatePairFoundation{ .local = local_foundation, .remote = remote_foundation };
    }

    fn generateUsernameFragmentAndPassword() struct { username: [8]u8, password: [24]u8 } {
        var buffer: [6 + 18]u8 = undefined;
        std.crypto.random.bytes(&buffer);

        var base64_buffer: [8 + 24]u8 = undefined;
        const result = std.base64.standard.Encoder.encode(&base64_buffer, &buffer);

        return .{ .username = result[0..8].*, .password = result[8..32].* };
    }

    pub fn init(
        id: u32,
        userdata: ?*anyopaque,
        on_candidate_callback: OnCandidateCallback,
        on_state_change_callback: OnStateChangeCallback,
        allocator: std.mem.Allocator,
    ) !AgentContext {
        const result = generateUsernameFragmentAndPassword();

        var gathering_main_timer = try xev.Timer.init();
        errdefer gathering_main_timer.deinit();
        var connectivity_checks_timer = try xev.Timer.init();
        errdefer connectivity_checks_timer.deinit();

        var buffer_arena_state = std.heap.ArenaAllocator.init(allocator);
        errdefer buffer_arena_state.deinit();

        var binding_request_queue_write_buffer = try buffer_arena_state.allocator().alloc(u8, 4096);
        errdefer buffer_arena_state.allocator().free(binding_request_queue_write_buffer);

        const tiebreaker = std.crypto.random.int(u64);

        return AgentContext{
            .id = id,
            .allocator = allocator,
            .gathering_main_timer = gathering_main_timer,
            .buffer_arena_state = buffer_arena_state,
            .check_context_map = CheckContextMap.init(allocator),
            .connectivity_checks_timer = connectivity_checks_timer,
            .binding_request_queue_write_buffer = binding_request_queue_write_buffer,
            .username_fragment = result.username,
            .password = result.password,
            .tiebreaker = tiebreaker,
            .userdata = userdata,
            .on_candidate_callback = on_candidate_callback,
            .on_state_change_callback = on_state_change_callback,
        };
    }

    pub fn deinit(self: *AgentContext) void {
        self.gathering_main_timer.deinit();
        self.connectivity_checks_timer.deinit();
        self.check_context_map.deinit();
        if (self.buffer_arena_state) |*s| s.deinit();

        self.allocator.free(self.socket_contexts);

        for (self.gathering_transaction_contexts) |*ctx| ctx.deinit();
        self.allocator.free(self.gathering_transaction_contexts);
        self.allocator.free(self.gathering_candidate_statuses);

        self.local_candidates.deinit(self.allocator);
        self.remote_candidates.deinit(self.allocator);

        self.checklist.pairs.deinit(self.allocator);
        self.checklist.valid_list.deinit(self.allocator);
        self.checklist.deinit(self.allocator);
    }

    pub fn initSocketContexts(self: *AgentContext, sockets: []const std.os.fd_t, addresses: []const std.net.Address) !void {
        std.debug.assert(sockets.len == addresses.len);
        const socket_count = sockets.len;
        const buffer_arena = self.buffer_arena_state.?.allocator();

        var socket_contexts = try self.allocator.alloc(SocketContext, socket_count);
        errdefer self.allocator.free(socket_contexts);
        for (0..socket_count) |index| {
            const read_buffer = try buffer_arena.alloc(u8, 4096);
            socket_contexts[index] = SocketContext.init(self.id, @intCast(index), sockets[index], addresses[index], read_buffer);
        }

        self.socket_contexts = socket_contexts;
    }

    pub fn initGathering(self: *AgentContext) !void {
        const socket_count = self.socket_contexts.len;
        const buffer_arena = self.buffer_arena_state.?.allocator();

        var gathering_candidate_statuses = try self.allocator.alloc(CandidateGatheringStatus, socket_count);
        errdefer self.allocator.free(gathering_candidate_statuses);
        @memset(gathering_candidate_statuses, .new);

        var transaction_context_list = try std.ArrayList(TransactionContext).initCapacity(self.allocator, socket_count);
        defer transaction_context_list.deinit();
        errdefer for (transaction_context_list.items) |*ctx| ctx.deinit();

        for (0..socket_count) |index| {
            const write_buffer = try buffer_arena.alloc(u8, 4096);
            transaction_context_list.appendAssumeCapacity(try TransactionContext.init(self.id, @intCast(index), @intCast(index), write_buffer, Configuration.computeRtoMs(socket_count)));
        }

        self.gathering_candidate_statuses = gathering_candidate_statuses;
        self.gathering_transaction_contexts = transaction_context_list.toOwnedSlice() catch unreachable;
    }

    inline fn getSocketContextFrom(self: *AgentContext, transaction_context: *const TransactionContext) ?*SocketContext {
        return &self.socket_contexts[transaction_context.socket_index];
    }

    inline fn getTransactionContextFrom(self: *AgentContext, socket_context: *const SocketContext) ?*TransactionContext {
        return for (self.gathering_transaction_contexts) |*ctx| {
            if (ctx.socket_index == socket_context.index) break ctx;
        } else null;
    }

    inline fn getPairFrom(self: *AgentContext, pair_foundation: CandidatePairFoundation) ?*CandidatePair {
        const index = self.getPairIndexFrom(pair_foundation) orelse return null;
        return &self.checklist.pairs.items[index];
    }

    inline fn getPairIndexFrom(self: *AgentContext, pair_foundation: CandidatePairFoundation) ?usize {
        return for (self.checklist.pairs.items, 0..) |*pair, index| {
            if (self.computePairFoundation(pair.*).eql(pair_foundation)) break index;
        } else null;
    }

    inline fn getConnectivityCheckContextFromTransactionId(self: *AgentContext, transaction_id: u96) ?*ConnectivityCheckContext {
        var it = self.check_context_map.iterator();
        return while (it.next()) |entry| {
            if (entry.value_ptr.last_transaction_id == transaction_id) break entry.value_ptr;
        } else null;
    }

    /// Returns true if the gathering is done and we can call the callback with a valid result.
    fn isGatheringDone(self: *const AgentContext) bool {
        return self.gathering_main_timer_completion.state() == .dead and for (self.gathering_transaction_contexts, 0..) |*ctx, i| {
            const status = self.gathering_candidate_statuses[i];
            if (!ctx.isDone() or (status != .done and status != .failed)) break false;
        } else true;
    }

    /// Return the index of a candidate that has not been checked yet or null.
    fn getUncheckedCandidate(self: *const AgentContext) ?usize {
        for (self.gathering_candidate_statuses, 0..) |s, i| {
            if (s == .new) {
                return i;
            }
        }
        return null;
    }

    fn addLocalCandidate(self: *AgentContext, candidate: Candidate, socket_index: u32) !void {
        try self.local_candidates.append(self.allocator, CandidateEntry{ .candidate = candidate, .socket_index = socket_index });
    }

    fn computePriorities(self: *AgentContext) void {
        // TODO(Corendos): Handle component ID as well.

        var arena_state = std.heap.ArenaAllocator.init(self.allocator);
        defer arena_state.deinit();

        const candidate_type_count = std.meta.tags(CandidateType).len;
        var candidate_lists_per_type: [candidate_type_count * 2]std.ArrayList(usize) = undefined;
        for (&candidate_lists_per_type) |*list| list.* = std.ArrayList(usize).initCapacity(arena_state.allocator(), self.local_candidates.items.len) catch unreachable;

        for (self.local_candidates.items, 0..) |entry, i| {
            const address_family = entry.candidate.transport_address.any.family;
            const address_index: usize = if (address_family == std.os.AF.INET) 0 else if (address_family == std.os.AF.INET6) 1 else unreachable;
            candidate_lists_per_type[@intFromEnum(entry.candidate.type) * 2 + address_index].appendAssumeCapacity(i);
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

                self.local_candidates.items[candidate_index].candidate.local_preference = current_local_preference;
                current_local_preference -= 128;
            }
        }
    }

    fn removeRedundantAndSortCandidates(self: *AgentContext) void {
        self.computePriorities();

        // Sort candidates
        std.sort.heap(CandidateEntry, self.local_candidates.items, {}, (struct {
            fn lessThan(context: void, lhs: CandidateEntry, rhs: CandidateEntry) bool {
                _ = context;
                return lhs.candidate.priority() > rhs.candidate.priority();
            }
        }).lessThan);

        // TODO(Corendos): Remove redundant candidates.
    }

    fn computeCandidatePairs(self: *AgentContext) !void {
        self.formCandidatesPairs();
        self.pruneCandidatePairs();
        self.removeLowerPriorityPairs();
        std.sort.heap(CandidatePair, self.checklist.pairs.items, {}, (struct {
            fn greaterThan(_: void, a: CandidatePair, b: CandidatePair) bool {
                return a.priority > b.priority;
            }
        }).greaterThan);

        for (self.checklist.pairs.items) |pair| {
            const pair_foundation = self.computePairFoundation(pair);
            const gop = try self.check_context_map.getOrPut(pair_foundation);
            if (!gop.found_existing) {
                const local_candidate_entry: CandidateEntry = self.local_candidates.items[pair.local_candidate_index];
                gop.value_ptr.* = ConnectivityCheckContext{
                    .agent_id = self.id,
                    .socket_index = @intCast(local_candidate_entry.socket_index),
                    .write_buffer = try self.buffer_arena_state.?.allocator().alloc(u8, 4096),
                    .timeout_timer = try xev.Timer.init(),
                    .pair_foundation = pair_foundation,
                };
            }
        }
    }

    fn formCandidatesPairs(self: *AgentContext) void {
        // TODO(Corendos): Better handle checklist size
        var pairs = std.ArrayListUnmanaged(CandidatePair).initCapacity(self.allocator, 100) catch unreachable;

        for (self.local_candidates.items, 0..) |local_entry, i| {
            const local_component_id = local_entry.candidate.component_id;
            const local_address_family = local_entry.candidate.transport_address.any.family;
            for (self.remote_candidates.items, 0..) |remote_candidate, j| {
                const remote_component_id = remote_candidate.component_id;
                const remote_address_family = remote_candidate.transport_address.any.family;
                if (local_component_id == remote_component_id and local_address_family == remote_address_family) {
                    const g = if (self.role == .controlling) local_entry.candidate.priority() else remote_candidate.priority();
                    const d = if (self.role == .controlled) local_entry.candidate.priority() else remote_candidate.priority();
                    pairs.appendAssumeCapacity(CandidatePair{
                        .local_candidate_index = i,
                        .remote_candidate_index = j,
                        .priority = (@as(u64, @min(g, d)) << 32) + (@as(u64, @max(g, d) << 1)) + @as(u64, if (g > d) 1 else 0),
                    });
                }
            }
        }

        self.checklist = Checklist.init(pairs, self.allocator) catch unreachable;
    }

    fn pruneCandidatePairs(self: *AgentContext) void {
        var index: usize = 0;
        var count: usize = self.checklist.pairs.items.len;
        while (index < count - 1) : (index += 1) {
            const source_pair = &self.checklist.pairs.items[index];
            const source_local_candidate_index = source_pair.local_candidate_index;
            const source_local_candidate = self.local_candidates.items[source_local_candidate_index].candidate;
            const source_remote_candidate_index = source_pair.remote_candidate_index;

            var other_index: usize = index + 1;

            while (other_index < count) {
                const dest_pair = &self.checklist.pairs.items[other_index];
                const dest_local_candidate_index = dest_pair.local_candidate_index;
                const dest_local_candidate = self.local_candidates.items[dest_local_candidate_index].candidate;
                const dest_remote_candidate_index = dest_pair.remote_candidate_index;

                const have_same_local_candidate_base = std.net.Address.eql(source_local_candidate.base_address, dest_local_candidate.base_address);
                const have_same_remote_candidate = source_remote_candidate_index == dest_remote_candidate_index;

                if (have_same_local_candidate_base and have_same_remote_candidate) {
                    if (source_pair.priority < dest_pair.priority) {
                        // Swap higher priority pair with current one
                        std.mem.swap(CandidatePair, source_pair, dest_pair);
                    }

                    // Swap redundant candidate pair with last one and reduce the number of candidate pair by one.
                    std.mem.swap(CandidatePair, dest_pair, &self.checklist.pairs.items[count - 1]);
                    count -= 1;

                    continue;
                }

                other_index += 1;
            }
        }

        std.debug.assert(count <= self.checklist.pairs.items.len);
        self.checklist.resize(self.allocator, count) catch unreachable;
    }

    fn removeLowerPriorityPairs(self: *AgentContext) void {
        if (self.checklist.pairs.items.len > Configuration.candidate_pair_limit) {
            self.checklist.resize(self.allocator, Configuration.candidate_pair_limit) catch unreachable;
        }
    }

    fn computeInitialCandidatePairsState(self: *AgentContext) void {
        var arena_state = std.heap.ArenaAllocator.init(self.allocator);
        defer arena_state.deinit();

        var foundation_map = std.AutoHashMap(CandidatePairFoundation, usize).init(arena_state.allocator());

        for (self.checklist.pairs.items, 0..) |p, i| {
            // Compute pair foundation
            const local_candidate = self.local_candidates.items[p.local_candidate_index].candidate;
            const pair_foundation = self.computePairFoundation(p);

            // Get hash map entry if it exists.
            const gop = foundation_map.getOrPut(pair_foundation) catch unreachable;

            if (!gop.found_existing) {
                // If it doesn't exist yet, we store this pair as the one that will be put in the Waiting state.
                gop.value_ptr.* = i;
            } else {
                // Otherwise, we compare the component IDs and/or priorities to select the one that will be put in the Waiting state.
                const stored_pair = self.checklist.pairs.items[gop.value_ptr.*];
                const stored_local_candidate = self.local_candidates.items[stored_pair.local_candidate_index].candidate;

                const has_lower_component_id = local_candidate.component_id < stored_local_candidate.component_id;
                const has_higher_priority = local_candidate.component_id == stored_local_candidate.component_id and local_candidate.priority() > stored_local_candidate.priority();
                if (has_lower_component_id or has_higher_priority) {
                    gop.value_ptr.* = i;
                }
            }
        }

        var it = foundation_map.iterator();
        while (it.next()) |entry| {
            const pair_index = entry.value_ptr.*;
            self.checklist.setPairState(pair_index, .waiting);
        }
    }

    fn pushResponseFromRequest(self: *AgentContext, request: ztun.Message, source: std.net.Address) !void {
        const index = self.binding_queue_head % self.binding_request_queue.len;

        self.binding_queue_head += 1;
        if (self.binding_queue_head == self.binding_queue_tail) @panic("Uh oh");

        var arena_state = std.heap.FixedBufferAllocator.init(&self.binding_request_queue[index].storage);
        self.binding_request_queue[index].response = try makeBindingResponse(request, source, self.password, arena_state.allocator());
        self.binding_request_queue[index].source = source;
    }

    fn popResponse(self: *AgentContext) struct { response: ztun.Message, source: std.net.Address } {
        // TODO(Corendos): Don't release slot before the write has been done, that might be risky.
        const index = self.binding_queue_tail % self.binding_request_queue.len;
        self.binding_queue_tail += 1;

        return .{ .response = self.binding_request_queue[index].response, .source = self.binding_request_queue[index].source };
    }

    fn getWaitingPair(self: *AgentContext) ?*CandidatePair {
        const index = self.getWaitingPairIndex() orelse return null;
        return &self.checklist.pairs.items[index];
    }

    fn getWaitingPairIndex(self: *AgentContext) ?usize {
        var pair_index: ?usize = null;

        var max_priority: u64 = 0;
        var min_component_id: u8 = 255;
        for (self.checklist.pairs.items, 0..) |*p, index| {
            if (p.state == .waiting) {
                const has_higher_priority = p.priority > max_priority;
                const has_same_priority = p.priority == max_priority;
                const has_lower_component_id = self.local_candidates.items[p.local_candidate_index].candidate.component_id < min_component_id;
                if (has_higher_priority or (has_same_priority and has_lower_component_id)) {
                    pair_index = index;
                    max_priority = p.priority;
                    min_component_id = self.local_candidates.items[p.local_candidate_index].candidate.component_id;
                }
            }
        }

        return pair_index;
    }

    inline fn getWaitingPairCount(self: *const AgentContext) usize {
        var count: usize = 0;

        for (self.checklist.pairs.items) |pair| {
            if (pair.state == .waiting) count += 1;
        }

        return count;
    }

    fn unfreezePair(self: *AgentContext) void {
        pair: for (self.checklist.pairs.items, 0..) |*p, index| {
            if (p.state != .frozen) continue;
            const pair_foundation = self.computePairFoundation(p.*);
            for (self.checklist.pairs.items) |*p2| {
                if (p2 == p) continue;
                const other_pair_foundation = self.computePairFoundation(p2.*);
                if (p2.state == .waiting or p2.state == .in_progress and pair_foundation.eql(other_pair_foundation)) continue :pair;
            }

            // If we are here, we didn't find another pair with the same foundation in the waiting or in_progress state.
            self.checklist.setPairState(index, .waiting);
            return;
        }
    }

    fn printPairStates(self: *AgentContext) void {
        for (std.meta.tags(CandidatePairState)) |t| {
            log.debug("{s}: {}", .{ @tagName(t), self.checklist.state_count[@intFromEnum(t)] });
        }
        for (self.checklist.pairs.items) |p| {
            const foundation_bit_size = @bitSizeOf(Foundation.IntType);
            const foundation = self.computePairFoundation(p);
            const pair_foundation: u64 = (@as(u64, foundation.remote.as_number()) << foundation_bit_size) + @as(u64, foundation.local.as_number());
            log.debug("{}:{} ({}): {s}", .{ p.local_candidate_index, p.remote_candidate_index, pair_foundation, @tagName(p.state) });
        }
    }
};

pub const CreateAgentOptions = struct {
    userdata: ?*anyopaque = null,
    on_candidate_callback: OnCandidateCallback = noopCandidateCallback,
    on_state_change_callback: OnStateChangeCallback = noopStateChangeCallback,
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

pub const OperationType = enum {
    gather_candidates,
    set_remote_candidates,
};

pub const RemoteCandidateParameters = struct {
    candidates: []Candidate,
    username_fragment: [8]u8,
    password: [24]u8,
};

pub const Operation = union(OperationType) {
    gather_candidates: void,
    set_remote_candidates: RemoteCandidateParameters,
};

pub const Callback = *const fn (?*anyopaque) void;

pub fn noopCallback(userdata: ?*anyopaque) void {
    _ = userdata;
}

pub const Completion = struct {
    agent_id: u32 = 0,
    op: Operation = undefined,

    userdata: ?*anyopaque = null,
    callback: Callback = noopCallback,

    next: ?*Completion = null,
};

/// Represents an event that can happen while gathering candidates.
const GatheringEventResult = union(enum) {
    /// A STUN response was received and it's the payload.
    read: struct { socket_context_index: usize, message: ztun.Message },
    /// A STUN message was sent and the payload contains the result.
    write: struct { transaction_context_index: usize, result: xev.WriteError!usize },
    /// The retry timer fired and the payload contains the result.
    retry_timer: struct { transaction_context_index: usize, result: xev.Timer.RunError!void },
    /// The retry timer was cancelled and the payload contains the result.
    cancel_retry_timer: struct { transaction_context_index: usize, result: xev.CancelError!void },
    /// The main timer fired and the payload contains the result.
    main_timer: xev.Timer.RunError!void,
};

const ConnectivityCheckEventResult = union(enum) {
    request_read: struct { socket_context_index: usize, message: ztun.Message, address: std.net.Address },
    response_read: struct { socket_context_index: usize, message: ztun.Message, address: std.net.Address },
    request_write: struct { check_context: *ConnectivityCheckContext, result: xev.WriteError!usize },
    response_write: struct { socket_context_index: usize, result: xev.WriteError!usize },
    response_timeout: struct { check_context: *ConnectivityCheckContext },
    main_timer: xev.Timer.RunError!void,
};

pub const Context = struct {
    allocator: std.mem.Allocator,

    network_interface_map: std.AutoArrayHashMapUnmanaged(u32, NetworkInterface) = .{},
    interface_addresses: std.ArrayListUnmanaged(InterfaceAddress) = .{},

    agent_map_mutex: std.Thread.Mutex = .{},
    // TODO(Corendos): Maybe make that not a pointer ?
    agent_map: std.AutoArrayHashMapUnmanaged(u32, *AgentContext) = .{},
    agent_id: u32 = 1024,

    string_storage: std.heap.ArenaAllocator,

    netlink_context: NetlinkContext,
    netlink_context_ready: bool = false,
    waiting_netlink_queue: Intrusive(Completion) = .{},

    async_queue_mutex: std.Thread.Mutex = .{},
    async_queue: Intrusive(Completion) = .{},
    async_handle: xev.Async,
    async_completion: xev.Completion = .{},

    // TODO(Corendos): Remove parameter everywhere it's not useful anymore.
    loop: *xev.Loop = undefined,

    pub fn init(allocator: std.mem.Allocator) !Context {
        return Context{
            .allocator = allocator,
            .string_storage = std.heap.ArenaAllocator.init(allocator),
            .netlink_context = try NetlinkContext.init(allocator),
            .async_handle = try xev.Async.init(),
        };
    }

    pub fn deinit(self: *Context) void {
        self.async_handle.deinit();
        self.netlink_context.deinit();
        self.network_interface_map.deinit(self.allocator);
        self.interface_addresses.deinit(self.allocator);
        self.string_storage.deinit();
        self.agent_map.deinit(self.allocator);
    }

    pub fn start(self: *Context, loop: *xev.Loop) !void {
        self.loop = loop;

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

        try self.netlink_context.start(loop);
        self.async_handle.wait(loop, &self.async_completion, Context, self, Context.asyncCallback);
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
        if (self.searchAddress(interface_index, address) != null) return;

        log.debug("New Address for interface {}: {}", .{ interface_index, address });
        try self.interface_addresses.append(self.allocator, .{
            .interface_index = interface_index,
            .address = address,
        });
    }

    fn deleteInterfaceAddress(self: *Context, interface_index: u32, address: std.net.Address) void {
        log.debug("Delete Address for interface {}: {}", .{ interface_index, address });
        const index = self.searchAddress(interface_index, address) orelse return;
        _ = self.interface_addresses.swapRemove(index);
    }

    fn netlinkContextReady(self: *Context) void {
        self.netlink_context_ready = true;

        if (self.waiting_netlink_queue.empty()) return;

        self.async_queue_mutex.lock();
        defer self.async_queue_mutex.unlock();

        while (self.waiting_netlink_queue.pop()) |completion| {
            self.async_queue.push(completion);
        }
        self.async_handle.notify() catch unreachable;
    }

    // TODO(Corendos): Maybe that should be async as well ?
    //                 I struggle with the fact that agent can be deleted on a separate thread and mess
    //                 up the internal state of the zice Context...

    pub fn newAgent(self: *Context, options: CreateAgentOptions) !u32 {
        self.agent_map_mutex.lock();
        defer self.agent_map_mutex.unlock();

        const agent_id = a: {
            defer self.agent_id += 1;
            break :a self.agent_id;
        };

        const gop = try self.agent_map.getOrPut(self.allocator, agent_id);
        std.debug.assert(!gop.found_existing);

        const new_agent = try self.allocator.create(AgentContext);
        errdefer self.allocator.destroy(new_agent);

        new_agent.* = try AgentContext.init(agent_id, options.userdata, options.on_candidate_callback, options.on_state_change_callback, self.allocator);
        errdefer new_agent.deinit();

        gop.value_ptr.* = new_agent;

        return agent_id;
    }

    pub fn deleteAgent(self: *Context, agent_id: u32) void {
        self.agent_map_mutex.lock();
        defer self.agent_map_mutex.unlock();

        const entry = self.agent_map.fetchSwapRemove(agent_id) orelse return;
        entry.value.deinit();
        self.allocator.destroy(entry.value);
    }

    pub fn getAgentUsernameAndPassword(self: *Context, agent_id: u32) !struct { username: [8]u8, password: [24]u8 } {
        self.agent_map_mutex.lock();
        defer self.agent_map_mutex.unlock();

        const entry = self.agent_map.getEntry(agent_id) orelse return error.Unexpected;

        return .{ .username = entry.value_ptr.*.username_fragment, .password = entry.value_ptr.*.password };
    }

    pub fn gatherCandidates(self: *Context, c: *Completion, agent_id: u32) !void {
        c.* = Completion{
            .agent_id = agent_id,
            .op = .{ .gather_candidates = {} },
        };

        {
            self.async_queue_mutex.lock();
            defer self.async_queue_mutex.unlock();
            self.async_queue.push(c);
        }
        try self.async_handle.notify();
    }

    pub fn setRemoteCandidates(self: *Context, c: *Completion, agent_id: u32, parameters: RemoteCandidateParameters) !void {
        c.* = Completion{
            .agent_id = agent_id,
            .op = .{ .set_remote_candidates = parameters },
        };

        {
            self.async_queue_mutex.lock();
            defer self.async_queue_mutex.unlock();
            self.async_queue.push(c);
        }

        try self.async_handle.notify();
    }

    pub fn processGatherCandidates(self: *Context, agent_context: *AgentContext, loop: *xev.Loop) !void {
        var address_list = try std.ArrayList(std.net.Address).initCapacity(self.allocator, self.interface_addresses.items.len);
        defer address_list.deinit();

        var socket_list = try std.ArrayList(std.os.fd_t).initCapacity(self.allocator, self.interface_addresses.items.len);
        defer socket_list.deinit();

        errdefer for (socket_list.items) |socket| {
            std.os.close(socket);
        };

        for (self.interface_addresses.items) |interface_address| {
            const interface = self.network_interface_map.get(interface_address.interface_index) orelse continue;

            if (interface.type == platform.netlink.ARPHRD.LOOPBACK) continue;
            const address = interface_address.address;

            if (!net.isValidAddress(address)) continue;

            const socket = try std.os.socket(address.any.family, std.os.SOCK.DGRAM, std.os.IPPROTO.UDP);
            try std.os.bind(socket, &address.any, address.getOsSockLen());
            const bound_address = try net.getSocketAddress(socket);
            socket_list.appendAssumeCapacity(socket);
            address_list.appendAssumeCapacity(bound_address);
        }

        if (agent_context.role == null) {
            agent_context.role = .controlling;
        }

        agent_context.gathering_state = .gathering;
        agent_context.on_state_change_callback(agent_context.userdata, agent_context.id, agent_context.gathering_state);

        try agent_context.initSocketContexts(socket_list.items, address_list.items);

        for (agent_context.socket_contexts, 0..) |ctx, index| {
            const candidate = Candidate{
                .type = .host,
                .base_address = ctx.address,
                .base_address_id = @intCast(index),
                .transport_address = ctx.address,
                .protocol = .udp,
            };
            agent_context.addLocalCandidate(candidate, @intCast(index)) catch unreachable;
            agent_context.on_candidate_callback(agent_context.userdata, agent_context.id, .{ .candidate = candidate });
        }

        try agent_context.initGathering();

        agent_context.gathering_main_timer.run(
            loop,
            &agent_context.gathering_main_timer_completion,
            Configuration.new_transaction_interval_ms,
            Context,
            self,
            Context.mainTimerCallback,
        );
    }

    fn processSetRemoteCandidates(self: *Context, agent_context: *AgentContext, parameters: RemoteCandidateParameters, loop: *xev.Loop) !void {
        try agent_context.remote_candidates.appendSlice(agent_context.allocator, parameters.candidates);
        agent_context.has_remote_candidates = true;
        agent_context.remote_username_fragment = parameters.username_fragment;
        agent_context.remote_password = parameters.password;

        if (agent_context.role == null) {
            agent_context.role = .controlled;
        }

        switch (agent_context.role.?) {
            .controlling => {
                if (agent_context.gathering_state == .done) {
                    self.startChecks(agent_context);
                }
            },
            .controlled => {
                try self.processGatherCandidates(agent_context, loop);
            },
        }
    }

    fn startChecks(
        self: *Context,
        agent_context: *AgentContext,
    ) void {
        agent_context.computeCandidatePairs() catch unreachable;
        agent_context.computeInitialCandidatePairsState();

        self.handleConnectivityCheckMainTimer(agent_context) catch unreachable;
    }

    fn swapAsyncQueue(self: *Context) Intrusive(Completion) {
        self.async_queue_mutex.lock();
        defer self.async_queue_mutex.unlock();

        var temp = self.async_queue;
        self.async_queue = .{};
        return temp;
    }

    fn asyncCallback(
        userdata: ?*Context,
        loop: *xev.Loop,
        _: *xev.Completion,
        result: xev.Async.WaitError!void,
    ) xev.CallbackAction {
        const self = userdata orelse unreachable;
        _ = result catch {};

        self.agent_map_mutex.lock();
        defer self.agent_map_mutex.unlock();

        var local_async_queue = self.swapAsyncQueue();

        while (local_async_queue.pop()) |completion| {
            log.debug("Received {s} completion for agent {}", .{ @tagName(completion.op), completion.agent_id });
            const agent_context: *AgentContext = self.agent_map.get(completion.agent_id) orelse continue;
            switch (completion.op) {
                .gather_candidates => {
                    if (!self.netlink_context_ready) {
                        log.debug("Waiting for Netlink completion", .{});
                        self.waiting_netlink_queue.push(completion);
                        continue;
                    }
                    self.processGatherCandidates(agent_context, loop) catch @panic("TODO");
                },
                .set_remote_candidates => |candidates| {
                    self.processSetRemoteCandidates(agent_context, candidates, loop) catch @panic("TODO");
                },
            }
            completion.callback(completion.userdata);
        }

        return .rearm;
    }

    /// Single entrypoint for all gathering related events (STUN message received/sent, retry timer fired, etc).
    /// The rationale to have a single function instead of multiple callback is that it makes it easier to know exactly when the gathering is done.
    fn handleGatheringEvent(
        self: *Context,
        agent_context: *AgentContext,
        result: GatheringEventResult,
    ) void {
        std.debug.assert(agent_context.gathering_state != .done);

        switch (result) {
            .write => |r| {
                const transaction_context = &agent_context.gathering_transaction_contexts[r.transaction_context_index];
                const socket_context = &agent_context.socket_contexts[transaction_context.socket_index];
                self.handleStunMessageWrite(agent_context, socket_context, transaction_context, r.result);
            },
            .read => |r| {
                const socket_context = &agent_context.socket_contexts[r.socket_context_index];
                const transaction_context = agent_context.getTransactionContextFrom(socket_context).?;
                self.handleStunMessageRead(agent_context, socket_context, transaction_context, r.message);
            },
            .retry_timer => |r| {
                const transaction_context = &agent_context.gathering_transaction_contexts[r.transaction_context_index];
                const socket_context = &agent_context.socket_contexts[transaction_context.socket_index];
                self.handleRetryTimer(agent_context, socket_context, transaction_context, r.result);
            },
            .cancel_retry_timer => {},
            .main_timer => |r| self.handleMainTimer(agent_context, r),
        }

        if (!agent_context.isGatheringDone()) return;

        agent_context.gathering_state = .done;
        agent_context.on_state_change_callback(agent_context.userdata, agent_context.id, agent_context.gathering_state);

        agent_context.on_candidate_callback(agent_context.userdata, agent_context.id, .{ .done = {} });

        agent_context.removeRedundantAndSortCandidates();

        if (agent_context.has_remote_candidates) {
            self.startChecks(agent_context);
        }
    }

    fn handleStunMessageWrite(
        self: *Context,
        agent_context: *AgentContext,
        socket_context: *SocketContext,
        transaction_context: *TransactionContext,
        result: xev.WriteError!usize,
    ) void {
        _ = result catch |err| {
            log.err("Agent {} - Got {} when sending STUN request from base address \"{}\"", .{ agent_context.id, err, socket_context.address });
            agent_context.gathering_candidate_statuses[transaction_context.index] = .failed;
            return;
        };

        transaction_context.request_sent_count += 1;
        log.debug("Agent {} - STUN request sent for base address \"{}\"", .{ agent_context.id, socket_context.address });

        const is_first_request = transaction_context.request_sent_count == 1;
        transaction_context.timer_timeout_ms = if (is_first_request) transaction_context.rto else transaction_context.timer_timeout_ms * 2;

        const is_last_request = transaction_context.request_sent_count == Configuration.request_count;
        if (is_last_request) {
            transaction_context.timer_timeout_ms = transaction_context.rto * Configuration.last_request_factor;
            transaction_context.is_retry_timer = false;
        }

        transaction_context.timer.run(
            self.loop,
            &transaction_context.timer_completion,
            transaction_context.timer_timeout_ms,
            Context,
            self,
            timerCallback,
        );
    }

    fn handleStunMessageRead(
        self: *Context,
        agent_context: *AgentContext,
        socket_context: *SocketContext,
        transaction_context: *TransactionContext,
        message: ztun.Message,
    ) void {
        if (agent_context.gathering_candidate_statuses[transaction_context.index] != .checking) return;
        log.debug("Agent {} - Received STUN response for base address \"{}\"", .{ agent_context.id, socket_context.address });

        agent_context.gathering_candidate_statuses[transaction_context.index] = .done;
        log.debug("Agent {} - Gathering done for base address \"{}\"", .{ agent_context.id, socket_context.address });

        if (getMappedAddressFromStunMessage(message)) |transport_address| {
            const candidate = Candidate{
                .type = .server_reflexive,
                .transport_address = transport_address,
                .base_address = socket_context.address,
                .base_address_id = @intCast(socket_context.index),
                .protocol = .udp,
            };
            agent_context.addLocalCandidate(candidate, socket_context.index) catch unreachable;
            agent_context.on_candidate_callback(agent_context.userdata, agent_context.id, .{ .candidate = candidate });
        }

        transaction_context.timer.cancel(
            self.loop,
            &transaction_context.timer_completion,
            &transaction_context.timer_cancel_completion,
            Context,
            self,
            timerCancelCallback,
        );
    }

    fn handleRetryTimer(
        self: *Context,
        agent_context: *AgentContext,
        socket_context: *SocketContext,
        transaction_context: *TransactionContext,
        result: xev.Timer.RunError!void,
    ) void {
        _ = result catch return;

        if (transaction_context.is_retry_timer) {
            log.debug("Agent {} - STUN request {}/{} from base address \"{}\" timed out", .{ agent_context.id, transaction_context.request_sent_count, Configuration.request_count, socket_context.address });
            var buffer: [4096]u8 = undefined;
            const request = r: {
                var allocator = std.heap.FixedBufferAllocator.init(&buffer);
                break :r makeBasicBindingRequest(allocator.allocator()) catch unreachable;
            };
            self.sendRequestToStunServer(request, socket_context, transaction_context);
        } else {
            log.debug("Agent {} - Gathering timed out for base address \"{}\"", .{ agent_context.id, socket_context.address });
            agent_context.gathering_candidate_statuses[transaction_context.index] = .failed;
        }
    }

    fn handleMainTimer(self: *Context, agent_context: *AgentContext, result: xev.Timer.RunError!void) void {
        _ = result catch |err| {
            log.err("{}", .{err});
            @panic("TODO");
        };

        // Get a candidate still in the .new state or disarm the timer.
        const transaction_context_index = agent_context.getUncheckedCandidate() orelse return;

        const transaction_context = &agent_context.gathering_transaction_contexts[transaction_context_index];
        const socket_context = &agent_context.socket_contexts[transaction_context.socket_index];

        // Set the candidate in the .checking state
        agent_context.gathering_candidate_statuses[transaction_context_index] = .checking;

        // Start to listen for activity on the socket.
        var read_data = &socket_context.read_data;
        read_data.iovec = .{ .iov_len = socket_context.read_buffer.len, .iov_base = socket_context.read_buffer.ptr };
        read_data.message_header = .{
            .name = &read_data.address.any,
            .namelen = read_data.address.any.data.len,
            .control = null,
            .controllen = 0,
            .iov = @ptrCast(&read_data.iovec),
            .iovlen = 1,
            .flags = 0,
        };

        socket_context.read_completion = xev.Completion{
            .op = .{
                .recvmsg = .{
                    .fd = socket_context.socket,
                    .msghdr = &read_data.message_header,
                },
            },
            .userdata = self,
            .callback = readCallback,
        };
        self.loop.add(&socket_context.read_completion);

        log.debug("Agent {} - Sending message for base address \"{}\"", .{ agent_context.id, socket_context.address });
        var buffer: [4096]u8 = undefined;
        const request = r: {
            var allocator = std.heap.FixedBufferAllocator.init(&buffer);
            break :r makeBasicBindingRequest(allocator.allocator()) catch unreachable;
        };
        self.sendRequestToStunServer(request, socket_context, transaction_context);

        // NOTE(Corendos): Small improvement could be done here. If we now that there won't be any new candidates the next time we go through this function,
        //                 we could avoid one main timer delay.

        agent_context.gathering_main_timer.run(
            self.loop,
            &agent_context.gathering_main_timer_completion,
            Configuration.new_transaction_interval_ms,
            Context,
            self,
            mainTimerCallback,
        );
    }

    fn handleConnectivityCheckEvent(self: *Context, agent_context: *AgentContext, result: ConnectivityCheckEventResult) void {
        switch (result) {
            .request_read => |payload| {
                const socket_context = &agent_context.socket_contexts[payload.socket_context_index];
                self.handleConnectivityCheckRequestRead(payload.message, payload.address, agent_context, socket_context) catch @panic("TODO");
            },
            .response_read => |payload| {
                const socket_context = &agent_context.socket_contexts[payload.socket_context_index];
                self.handleConnectivityCheckResponseRead(payload.message, payload.address, agent_context, socket_context) catch @panic("TODO");
            },
            .request_write => |payload| {
                const socket_context = &agent_context.socket_contexts[payload.check_context.socket_index];
                self.handleConnectivityCheckRequestWrite(agent_context, socket_context, payload.check_context, payload.result) catch @panic("TODO");
            },
            .response_write => {
                log.debug("Agent {} - Stun response sent !", .{agent_context.id});

                if (agent_context.binding_queue_head > agent_context.binding_queue_tail) {
                    log.debug("Agent {} - More response to send!", .{agent_context.id});
                } else {
                    log.debug("Agent {} - Done sending queued response...", .{agent_context.id});
                }
            },
            .response_timeout => |payload| {
                self.handleConnectivityCheckResponseTimeout(agent_context, payload.check_context) catch @panic("TODO");
            },
            .main_timer => {
                self.handleConnectivityCheckMainTimer(agent_context) catch @panic("TODO");
            },
        }

        agent_context.printPairStates();
    }

    fn tryDecodeStunMessage(allocator: std.mem.Allocator, data: []const u8) ?ztun.Message {
        var stream = std.io.fixedBufferStream(data);
        return ztun.Message.readAlloc(stream.reader(), allocator) catch return null;
    }

    inline fn isAgentStunResponse(message: ztun.Message) bool {
        return for (message.attributes) |a| {
            switch (a.type) {
                ztun.attr.Type.ice_controlled, ztun.attr.Type.ice_controlling => break true,
                else => {},
            }
        } else false;
    }

    fn readCallback(
        userdata: ?*anyopaque,
        loop: *xev.Loop,
        c: *xev.Completion,
        result: xev.Result,
    ) xev.CallbackAction {
        _ = loop;

        const self = @as(*Context, @ptrCast(@alignCast(userdata.?)));
        const socket_context = @fieldParentPtr(SocketContext, "read_completion", c);
        const socket_context_index = socket_context.index;
        const agent_context = self.agent_map.get(socket_context.agent_id).?;

        const bytes_read = result.recvmsg catch |err| {
            log.err("Agent {} - Got {} for base address \"{}\" while reading from socket", .{ agent_context.id, err, socket_context.address });
            return .rearm;
        };

        const data = socket_context.read_buffer[0..bytes_read];

        var buffer: [4096]u8 = undefined;
        var allocator_state = std.heap.FixedBufferAllocator.init(&buffer);
        var allocator = allocator_state.allocator();

        const source = socket_context.read_data.address;
        if (tryDecodeStunMessage(allocator, data)) |stun_message| {
            defer stun_message.deinit(allocator);

            switch (stun_message.type.class) {
                .success_response => {
                    const is_gathering_response = for (agent_context.gathering_transaction_contexts) |ctx| {
                        if (stun_message.transaction_id == ctx.transaction_id) break true;
                    } else false;

                    if (is_gathering_response) {
                        self.handleGatheringEvent(agent_context, .{ .read = .{ .socket_context_index = socket_context_index, .message = stun_message } });
                    } else {
                        self.handleConnectivityCheckEvent(agent_context, .{ .response_read = .{ .socket_context_index = socket_context_index, .message = stun_message, .address = source } });
                    }
                },
                .request => {
                    self.handleConnectivityCheckEvent(agent_context, .{ .request_read = .{ .socket_context_index = socket_context_index, .message = stun_message, .address = source } });
                },
                else => unreachable,
            }
        } else {
            // TODO(Corendos): handle other type of messages
            @panic("TODO: Received message that is not a STUN message");
        }

        return .rearm;
    }

    fn stunWriteCallback(
        userdata: ?*anyopaque,
        loop: *xev.Loop,
        c: *xev.Completion,
        result: xev.Result,
    ) xev.CallbackAction {
        _ = loop;
        const self = @as(*Context, @ptrCast(@alignCast(userdata.?)));
        const transaction_context = @fieldParentPtr(TransactionContext, "write_completion", c);
        const transaction_context_index = transaction_context.index;
        const agent_context = self.agent_map.get(transaction_context.agent_id).?;

        self.handleGatheringEvent(agent_context, .{ .write = .{ .transaction_context_index = transaction_context_index, .result = result.sendmsg } });

        return .disarm;
    }

    fn timerCallback(
        userdata: ?*Context,
        loop: *xev.Loop,
        c: *xev.Completion,
        result: xev.Timer.RunError!void,
    ) xev.CallbackAction {
        _ = loop;
        const self = userdata.?;
        const transaction_context = @fieldParentPtr(TransactionContext, "timer_completion", c);
        const transaction_context_index = transaction_context.index;
        const agent_context = self.agent_map.get(transaction_context.agent_id).?;

        self.handleGatheringEvent(agent_context, .{ .retry_timer = .{ .transaction_context_index = transaction_context_index, .result = result } });

        return .disarm;
    }

    fn timerCancelCallback(
        userdata: ?*Context,
        loop: *xev.Loop,
        c: *xev.Completion,
        result: xev.CancelError!void,
    ) xev.CallbackAction {
        _ = loop;
        const self = userdata.?;
        const transaction_context = @fieldParentPtr(TransactionContext, "timer_cancel_completion", c);
        const transaction_context_index = transaction_context.index;
        const agent_context = self.agent_map.get(transaction_context.agent_id).?;

        self.handleGatheringEvent(agent_context, .{ .cancel_retry_timer = .{ .transaction_context_index = transaction_context_index, .result = result } });

        return .disarm;
    }

    fn mainTimerCallback(
        userdata: ?*Context,
        loop: *xev.Loop,
        c: *xev.Completion,
        result: xev.Timer.RunError!void,
    ) xev.CallbackAction {
        _ = loop;
        const self = userdata.?;
        const agent_context = @fieldParentPtr(AgentContext, "gathering_main_timer_completion", c);

        self.handleGatheringEvent(agent_context, .{ .main_timer = result });

        return .disarm;
    }

    fn sendRequestToStunServer(self: *Context, request: ztun.Message, socket_context: *SocketContext, transaction_context: *TransactionContext) void {
        const address = switch (socket_context.address.any.family) {
            std.os.AF.INET => Configuration.stun_address_ipv4,
            std.os.AF.INET6 => Configuration.stun_address_ipv6,
            else => unreachable,
        };

        const data = d: {
            var stream = std.io.fixedBufferStream(transaction_context.write_buffer);
            request.write(stream.writer()) catch unreachable;
            break :d stream.getWritten();
        };

        transaction_context.transaction_id = request.transaction_id;
        transaction_context.write_data.from(address, data);

        transaction_context.write_completion = xev.Completion{
            .op = .{
                .sendmsg = .{
                    .fd = socket_context.socket,
                    .msghdr = &transaction_context.write_data.message_header,
                    .buffer = null,
                },
            },
            .userdata = self,
            .callback = stunWriteCallback,
        };
        self.loop.add(&transaction_context.write_completion);
    }

    fn sendRequestToRemoteAgent(self: *Context, request: ztun.Message, check_context: *ConnectivityCheckContext, socket_context: *SocketContext, address: std.net.Address) void {
        const data = d: {
            var stream = std.io.fixedBufferStream(check_context.write_buffer);
            request.write(stream.writer()) catch unreachable;
            break :d stream.getWritten();
        };

        check_context.write_data.from(address, data);
        check_context.last_transaction_id = request.transaction_id;

        check_context.write_completion = xev.Completion{
            .op = .{
                .sendmsg = .{
                    .fd = socket_context.socket,
                    .msghdr = &check_context.write_data.message_header,
                    .buffer = null,
                },
            },
            .userdata = self,
            .callback = connectivityCheckWriteCallback,
        };
        self.loop.add(&check_context.write_completion);
    }

    fn connectivityCheckTimerCallback(
        userdata: ?*Context,
        loop: *xev.Loop,
        c: *xev.Completion,
        result: xev.Timer.RunError!void,
    ) xev.CallbackAction {
        _ = loop;

        const self = userdata.?;
        const agent_context = @fieldParentPtr(AgentContext, "connectivity_checks_timer_completion", c);

        self.handleConnectivityCheckEvent(agent_context, .{ .main_timer = result });

        return .disarm;
    }

    fn connectivityCheckWriteCallback(
        userdata: ?*anyopaque,
        loop: *xev.Loop,
        c: *xev.Completion,
        result: xev.Result,
    ) xev.CallbackAction {
        _ = loop;

        const self = @as(*Context, @ptrCast(@alignCast(userdata.?)));
        const check_context = @fieldParentPtr(ConnectivityCheckContext, "write_completion", c);
        const agent_context = self.agent_map.get(check_context.agent_id).?;

        self.handleConnectivityCheckEvent(agent_context, .{ .request_write = .{ .check_context = check_context, .result = result.sendmsg } });

        return .disarm;
    }

    fn connectivityCheckResponseWriteCallback(
        userdata: ?*anyopaque,
        loop: *xev.Loop,
        c: *xev.Completion,
        result: xev.Result,
    ) xev.CallbackAction {
        _ = loop;

        const self = @as(*Context, @ptrCast(@alignCast(userdata.?)));
        const agent_context = @fieldParentPtr(AgentContext, "binding_request_queue_write_completion", c);
        const socket_context = for (agent_context.socket_contexts) |*ctx| {
            if (ctx.socket == c.op.sendmsg.fd) break ctx;
        } else unreachable;
        const socket_context_index = socket_context.index;

        self.handleConnectivityCheckEvent(agent_context, .{ .response_write = .{ .socket_context_index = socket_context_index, .result = result.sendmsg } });

        return .disarm;
    }

    fn connectivityCheckTimeoutCallback(
        userdata: ?*Context,
        loop: *xev.Loop,
        c: *xev.Completion,
        result: xev.Timer.RunError!void,
    ) xev.CallbackAction {
        _ = loop;

        const self = userdata.?;
        const check_context = @fieldParentPtr(ConnectivityCheckContext, "timeout_completion", c);
        const agent_context = self.agent_map.get(check_context.agent_id).?;

        check_context.timeout_occurred = if (result) true else |_| false;

        if (check_context.timeout_completion.state() == .dead and check_context.timeout_cancel_completion.state() == .dead and check_context.timeout_occurred) {
            self.handleConnectivityCheckEvent(agent_context, .{ .response_timeout = .{ .check_context = check_context } });
        }

        return .disarm;
    }

    fn connectivityCheckTimeoutCancelCallback(
        userdata: ?*Context,
        loop: *xev.Loop,
        c: *xev.Completion,
        result: xev.CancelError!void,
    ) xev.CallbackAction {
        _ = result catch {};
        _ = loop;

        const self = userdata.?;
        const check_context = @fieldParentPtr(ConnectivityCheckContext, "timeout_cancel_completion", c);
        const agent_context = self.agent_map.get(check_context.agent_id).?;

        if (check_context.timeout_completion.state() == .dead and check_context.timeout_cancel_completion.state() == .dead and check_context.timeout_occurred) {
            self.handleConnectivityCheckEvent(agent_context, .{ .response_timeout = .{ .check_context = check_context } });
        }

        return .disarm;
    }

    fn handleConnectivityCheckRequestRead(
        self: *Context,
        request: ztun.Message,
        source: std.net.Address,
        agent_context: *AgentContext,
        socket_context: *SocketContext,
    ) !void {
        log.debug("Agent {} - Received Binding request from \"{}\"", .{ agent_context.id, source });

        // TODO(Corendos): Check if this is a peer-reflexive candidate.
        //                 See https://www.rfc-editor.org/rfc/rfc8445#section-7.3.1.3

        var buffer: [4096]u8 = undefined;
        // Check fingerprint/integrity
        {
            var arena_state = std.heap.FixedBufferAllocator.init(&buffer);
            if (!request.checkFingerprint(arena_state.allocator())) return error.InvalidFingerprint;

            const attribute_index = for (request.attributes, 0..) |a, i| {
                if (a.type == ztun.attr.Type.message_integrity) break i;
            } else return error.NoMessageIntegrity;

            const key = try (ztun.auth.Authentication{ .short_term = ztun.auth.ShortTermAuthentication{ .password = &agent_context.password } }).computeKeyAlloc(arena_state.allocator());

            if (!try request.checkMessageIntegrity(.classic, attribute_index, key, arena_state.allocator())) return error.InvalidMessageIntegrity;
        }

        agent_context.pushResponseFromRequest(request, source) catch unreachable;

        if (agent_context.binding_request_queue_write_completion.state() != .active) {
            const value = agent_context.popResponse();

            const data = d: {
                var stream = std.io.fixedBufferStream(agent_context.binding_request_queue_write_buffer);
                value.response.write(stream.writer()) catch unreachable;
                break :d stream.getWritten();
            };

            agent_context.binding_request_queue_write_data.from(value.source, data);

            agent_context.binding_request_queue_write_completion = xev.Completion{
                .op = .{
                    .sendmsg = .{
                        .fd = socket_context.socket,
                        .msghdr = &agent_context.binding_request_queue_write_data.message_header,
                        .buffer = null,
                    },
                },
                .userdata = self,
                .callback = connectivityCheckResponseWriteCallback,
            };
            self.loop.add(&agent_context.binding_request_queue_write_completion);
        }
    }

    fn handleConnectivityCheckRequestWrite(
        self: *Context,
        agent_context: *AgentContext,
        socket_context: *SocketContext,
        check_context: *ConnectivityCheckContext,
        result: xev.WriteError!usize,
    ) !void {
        _ = socket_context;
        const pair_index = agent_context.getPairIndexFrom(check_context.pair_foundation).?;
        if (result) |_| {
            check_context.timeout_timer.run(self.loop, &check_context.timeout_completion, 500, Context, self, connectivityCheckTimeoutCallback);
        } else |_| {
            agent_context.checklist.setPairState(pair_index, .failed);
        }
    }

    fn handleConnectivityCheckResponseRead(
        self: *Context,
        response: ztun.Message,
        source: std.net.Address,
        agent_context: *AgentContext,
        socket_context: *SocketContext,
    ) !void {
        _ = socket_context;

        log.debug("Agent {} - Received response from other peer", .{agent_context.id});
        const check_context = agent_context.getConnectivityCheckContextFromTransactionId(response.transaction_id) orelse @panic("TODO");

        check_context.timeout_timer.cancel(self.loop, &check_context.timeout_completion, &check_context.timeout_cancel_completion, Context, self, connectivityCheckTimeoutCancelCallback);

        const pair_index = agent_context.getPairIndexFrom(check_context.pair_foundation) orelse @panic("TODO");
        const pair = &agent_context.checklist.pairs.items[pair_index];

        if (pair.state != .in_progress) {
            log.debug("Agent {} - Pair is not in the in_progress state anymore", .{agent_context.id});
            return;
        }

        const local_candidate = agent_context.local_candidates.items[pair.local_candidate_index].candidate;
        const remote_candidate = agent_context.remote_candidates.items[pair.remote_candidate_index];

        // TODO(Corendos): Discover peer-reflexive candidates.
        const response_address = getMappedAddressFromStunMessage(response) orelse @panic("TODO");

        // NOTE(Corendos): handle https://www.rfc-editor.org/rfc/rfc8445#section-7.2.5.2.1.
        const response_source = source;
        const request_destination = remote_candidate.transport_address;
        const response_destination = response_address;
        const request_source = local_candidate.transport_address;
        // TODO(Corendos): update checklist state
        const new_state: CandidatePairState = if (response_source.eql(request_destination) and response_destination.eql(request_source)) .succeeded else .failed;
        agent_context.checklist.setPairState(pair_index, new_state);

        log.debug("Agent {} - Candidate pair ({}:{}) state: {s}", .{ agent_context.id, pair.local_candidate_index, pair.remote_candidate_index, @tagName(pair.state) });

        if (new_state == .failed) return;

        // NOTE(Corendos): if we are here, we consider the response as a success.

        // Temporarily, we consider that the valid pair corresponds to the pair we selected
        const valid_pair = pair.*;
        agent_context.checklist.valid_list.append(self.allocator, valid_pair) catch unreachable;
        for (agent_context.checklist.pairs.items, 0..) |*p, i| {
            const valid_pair_foundation = agent_context.computePairFoundation(valid_pair);
            const pair_foundation = agent_context.computePairFoundation(p.*);
            if (p.state == .frozen and pair_foundation.eql(valid_pair_foundation)) {
                agent_context.checklist.setPairState(i, .waiting);
            }
        }
    }

    fn handleConnectivityCheckResponseTimeout(
        self: *Context,
        agent_context: *AgentContext,
        check_context: *ConnectivityCheckContext,
    ) !void {
        _ = self;
        log.debug("Agent {} - Response timeout", .{agent_context.id});

        const pair_index = agent_context.getPairIndexFrom(check_context.pair_foundation) orelse @panic("TODO");
        agent_context.checklist.setPairState(pair_index, .failed);

        const pair = &agent_context.checklist.pairs.items[pair_index];

        log.debug("Agent {} - Candidate pair ({}:{}) state: {s}", .{ agent_context.id, pair.local_candidate_index, pair.remote_candidate_index, @tagName(pair.state) });
    }

    fn handleConnectivityCheckMainTimer(self: *Context, agent_context: *AgentContext) !void {
        log.debug("Agent {} - Connectivity check timer fired", .{agent_context.id});

        // TODO(Corendos): handle multiple checklists

        const candidate_pair_index_opt = b: {
            if (!agent_context.checklist.triggered_check_queue.empty()) {}

            const waiting_pair_count = agent_context.getWaitingPairCount();

            if (waiting_pair_count == 0) {
                agent_context.unfreezePair();
            }

            break :b agent_context.getWaitingPairIndex();
        };

        if (candidate_pair_index_opt) |candidate_pair_index| {
            const candidate_pair = &agent_context.checklist.pairs.items[candidate_pair_index];
            const local_candidate = agent_context.local_candidates.items[candidate_pair.local_candidate_index].candidate;
            const remote_candidate = agent_context.remote_candidates.items[candidate_pair.remote_candidate_index];

            var buffer: [4096]u8 = undefined;
            const request = r: {
                var allocator = std.heap.FixedBufferAllocator.init(&buffer);
                break :r makeConnectivityCheckBindingRequest(
                    agent_context.username_fragment,
                    agent_context.remote_username_fragment.?,
                    agent_context.remote_password.?,
                    local_candidate.priority(),
                    agent_context.role.?,
                    agent_context.tiebreaker,
                    allocator.allocator(),
                ) catch unreachable;
            };

            // TODO(Corendos): We should find a way to get to associated socket easily.
            const local_check_context = agent_context.check_context_map.getPtr(agent_context.computePairFoundation(candidate_pair.*)) orelse unreachable;
            const local_socket_context = &agent_context.socket_contexts[local_check_context.socket_index];

            log.debug("Agent {} - Sending Binding request from \"{}\" to \"{}\"", .{ agent_context.id, local_socket_context.address, remote_candidate.transport_address });
            self.sendRequestToRemoteAgent(request, local_check_context, local_socket_context, remote_candidate.transport_address);

            agent_context.checklist.setPairState(candidate_pair_index, .in_progress);

            agent_context.connectivity_checks_timer.run(
                self.loop,
                &agent_context.connectivity_checks_timer_completion,
                Configuration.new_transaction_interval_ms,
                Context,
                self,
                connectivityCheckTimerCallback,
            );
        }
    }
};

test {
    _ = Worker;
    _ = Intrusive;
    _ = platform;
    _ = net;
}
