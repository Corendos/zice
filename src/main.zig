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

const log = std.log.scoped(.zice);

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

/// Represents the type of the Transport Address.
pub const TransportAddressType = enum {
    /// The addresses uses the UDP protocol.
    udp,
    /// The addresses uses the TCP protocol.
    tcp,

    // NOTE(Corendos): TCP is not supported yet.
};

/// Represents what is referred as a Transport Address in the rfc8445.
pub const TransportAddress = struct {
    /// The actual IP and port used.
    address: std.net.Address,
    /// The type of the address.
    type: TransportAddressType,
};

// TODO(Corendos): Implement https://www.rfc-editor.org/rfc/rfc8421#section-4 for local preference computation

/// Represents an ICE candidate.
pub const Candidate = struct {
    /// The type of candidate.
    type: CandidateType,
    /// The candidate transport address.
    transport_address: TransportAddress,
    /// The candidate base address.
    base_address: TransportAddress,
    /// The candidate local preference.
    local_preference: u16 = 0,
    /// The component ID associated to the candidate.
    component_id: u8 = 1,

    // TODO(Corendos): multiple component ID support

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
    };
    const candidate_2 = Candidate{
        .type = .server_reflexive,
        .transport_address = undefined,
        .base_address = undefined,
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

    //const stun_address_ipv4 = std.net.Address.parseIp4("91.134.140.104", 3478) catch unreachable;
    const stun_address_ipv4 = std.net.Address.parseIp4("172.253.120.127", 19302) catch unreachable;
    const stun_address_ipv6 = std.net.Address.parseIp6("2a00:1450:400c:c00::7f", 19302) catch unreachable;

    pub inline fn computeRtoMs(candidate_count: u64) u64 {
        return @max(500, candidate_count * new_transaction_interval_ms);
    }
};

const NetlinkContextState = enum {
    initial_interfaces,
    initial_addresses,
    idle,
};

const NetlinkContext = struct {
    read_completion: xev.Completion = .{},
    write_completion: xev.Completion = .{},

    socket: std.os.fd_t,

    state: NetlinkContextState = .initial_interfaces,
    multipart: bool = false,

    write_buffer: []u8,
    read_buffer: []u8,

    allocator: std.mem.Allocator,

    zice_context: ?*Context = null,

    pub fn init(allocator: std.mem.Allocator) !NetlinkContext {
        var write_buffer = try allocator.alloc(u8, 8192);
        errdefer allocator.free(write_buffer);
        var read_buffer = try allocator.alloc(u8, 8192);
        errdefer allocator.free(read_buffer);

        const socket = try std.os.socket(std.os.linux.AF.NETLINK, std.os.linux.SOCK.RAW, std.os.linux.NETLINK.ROUTE);
        errdefer std.os.close(socket);

        const address = std.os.linux.sockaddr.nl{
            .pid = 0,
            .groups = platform.netlink.RTMGRP.LINK | platform.netlink.RTMGRP.IPV4_IFADDR,
        };
        try std.os.bind(socket, @as(*const std.os.sockaddr, @ptrCast(&address)), @sizeOf(std.os.linux.sockaddr.nl));

        return NetlinkContext{
            .socket = socket,
            .write_buffer = write_buffer,
            .read_buffer = read_buffer,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *NetlinkContext) void {
        std.os.close(self.socket);
        self.allocator.free(self.write_buffer);
        self.allocator.free(self.read_buffer);
    }

    pub fn start(self: *NetlinkContext, loop: *xev.Loop) !void {
        self.read_completion = xev.Completion{
            .op = .{
                .read = .{
                    .fd = self.socket,
                    .buffer = .{ .slice = self.read_buffer },
                },
            },
            .userdata = self,
            .callback = NetlinkContext.readCallback,
        };
        loop.add(&self.read_completion);

        self.requestInterfaces(loop);
    }

    fn requestInterfaces(self: *NetlinkContext, loop: *xev.Loop) void {
        log.debug("Requesting initial Interfaces", .{});
        const request_payload = std.os.linux.ifinfomsg{
            .family = std.os.linux.AF.UNSPEC,
            .type = 0,
            .index = 0,
            .flags = 0,
            .change = 0xFFFFFFFF,
        };

        const request_header = std.os.linux.nlmsghdr{
            .len = platform.netlink.nlmsg_length(@sizeOf(@TypeOf(request_payload))),
            .type = std.os.linux.NetlinkMessageType.RTM_GETLINK,
            .flags = std.os.linux.NLM_F_DUMP | std.os.linux.NLM_F_REQUEST,
            .seq = 0,
            .pid = 0,
        };

        var stream = std.io.fixedBufferStream(self.write_buffer);
        var writer = stream.writer();
        writer.writeStruct(request_header) catch unreachable;
        writer.writeStruct(request_payload) catch unreachable;

        self.write_completion = xev.Completion{
            .op = .{
                .write = .{
                    .fd = self.socket,
                    .buffer = .{ .slice = stream.getWritten() },
                },
            },
            .userdata = self,
            .callback = writeCallback,
        };
        loop.add(&self.write_completion);
        self.multipart = false;
    }

    fn requestAddresses(self: *NetlinkContext, loop: *xev.Loop) void {
        log.debug("Requesting initial Addresses", .{});
        const request_payload = platform.netlink.ifaddrmsg{
            .family = std.os.linux.AF.UNSPEC,
            .prefixlen = 0,
            .flags = 0,
            .scope = 0,
            .index = 0,
        };

        const request_header = std.os.linux.nlmsghdr{
            .len = platform.netlink.nlmsg_length(@sizeOf(@TypeOf(request_payload))),
            .type = std.os.linux.NetlinkMessageType.RTM_GETADDR,
            .flags = std.os.linux.NLM_F_DUMP | std.os.linux.NLM_F_REQUEST,
            .seq = 0,
            .pid = 0,
        };

        var stream = std.io.fixedBufferStream(self.write_buffer);
        var writer = stream.writer();
        writer.writeStruct(request_header) catch unreachable;
        writer.writeStruct(request_payload) catch unreachable;

        self.write_completion = xev.Completion{
            .op = .{
                .write = .{
                    .fd = self.socket,
                    .buffer = .{ .slice = stream.getWritten() },
                },
            },
            .userdata = self,
            .callback = writeCallback,
        };
        loop.add(&self.write_completion);
        self.multipart = false;
    }

    fn writeCallback(
        userdata: ?*anyopaque,
        loop: *xev.Loop,
        completion: *xev.Completion,
        result: xev.Result,
    ) xev.CallbackAction {
        var self = @as(*NetlinkContext, @ptrCast(@alignCast(userdata.?)));
        _ = result.write catch |err| self.writeError(err, loop);
        _ = completion;

        return .disarm;
    }

    fn readCallback(
        userdata: ?*anyopaque,
        loop: *xev.Loop,
        completion: *xev.Completion,
        result: xev.Result,
    ) xev.CallbackAction {
        var self = @as(*NetlinkContext, @ptrCast(@alignCast(userdata.?)));
        if (result.read) |bytes_read| {
            if (self.handleNetlinkMessage(completion.op.read.buffer.slice[0..bytes_read])) |done| {
                if (done) {
                    switch (self.state) {
                        .initial_interfaces => {
                            self.state = .initial_addresses;
                            self.requestAddresses(loop);
                        },
                        .initial_addresses => {
                            self.state = .idle;
                            self.zice_context.?.netlinkContextReady();
                        },
                        else => {},
                    }
                }
            } else |err| self.readError(err, loop);
        } else |err| self.readError(err, loop);

        return .rearm;
    }

    fn writeError(self: *NetlinkContext, err: anyerror, loop: *xev.Loop) void {
        log.err("Got {} while writing in {s} state, retrying...", .{ err, @tagName(self.state) });

        switch (self.state) {
            .initial_interfaces => self.requestInterfaces(loop),
            .initial_addresses => self.requestAddresses(loop),
            else => unreachable,
        }
    }

    fn readError(self: *NetlinkContext, err: anyerror, loop: *xev.Loop) void {
        log.err("Got {} while reading in {s} state, retrying...", .{ err, @tagName(self.state) });

        switch (self.state) {
            .initial_interfaces => self.requestInterfaces(loop),
            .initial_addresses => self.requestAddresses(loop),
            else => {},
        }
    }

    fn handleNetlinkMessage(self: *NetlinkContext, data: []const u8) !bool {
        var it = platform.netlink.MessageIterator.init(@alignCast(data));
        var done = false;
        while (it.next()) |message| {
            self.multipart = self.multipart or (message.flags & std.os.linux.NLM_F_MULTI > 0);
            if (message.type == .ERROR) {
                const error_message = @as(*const platform.netlink.nlmsgerr, @ptrCast(@alignCast(message.data.ptr)));
                log.err("{}", .{error_message.@"error"});
                return error.Unexpected;
            } else if (message.type == .RTM_NEWLINK or message.type == .RTM_DELLINK) {
                const interface_message = @as(*const std.os.linux.ifinfomsg, @ptrCast(@alignCast(message.data)));
                const raw_attributes = @as([]align(@alignOf(std.os.linux.rtattr)) const u8, @alignCast(message.data[@sizeOf(std.os.linux.ifinfomsg)..]));
                self.handleNetlinkInterfaceMessage(interface_message.*, raw_attributes, message.type == .RTM_NEWLINK);
            } else if (message.type == std.os.linux.NetlinkMessageType.RTM_NEWADDR or message.type == std.os.linux.NetlinkMessageType.RTM_DELADDR) {
                const address_message = @as(*const platform.netlink.ifaddrmsg, @ptrCast(@alignCast(message.data)));
                const raw_attributes = @as([]align(@alignOf(std.os.linux.rtattr)) const u8, @alignCast(message.data[@sizeOf(platform.netlink.ifaddrmsg)..]));
                self.handleNetlinkAddressMessage(address_message.*, raw_attributes, message.type == .RTM_NEWADDR);
            } else if (message.type == .DONE) {
                done = true;
            }
        }

        return if (self.multipart) done else true;
    }

    fn handleNetlinkAddressMessage(self: *NetlinkContext, message: platform.netlink.ifaddrmsg, raw_attributes: []align(@alignOf(std.os.linux.rtattr)) const u8, is_new_message: bool) void {
        const index: u32 = @as(u32, @intCast(message.index));

        var attribute_it = platform.netlink.AttributeIterator.init(raw_attributes);
        const address_opt: ?std.net.Address = while (attribute_it.next()) |raw_attribute| {
            const attribute = platform.netlink.IfaAttribute.from(raw_attribute);
            if (attribute == .ADDRESS) {
                break switch (message.family) {
                    std.os.linux.AF.INET => std.net.Address.initPosix(@alignCast(@ptrCast(&std.os.linux.sockaddr.in{
                        .port = 0,
                        .addr = std.mem.bytesToValue(u32, attribute.ADDRESS[0..4]),
                    }))),
                    std.os.linux.AF.INET6 => std.net.Address.initPosix(@alignCast(@ptrCast(&std.os.linux.sockaddr.in6{
                        .port = 0,
                        .flowinfo = 0,
                        .addr = std.mem.bytesToValue([16]u8, attribute.ADDRESS[0..16]),
                        .scope_id = index,
                    }))),
                    else => null,
                };
            }
        } else null;
        if (address_opt) |address| {
            if (is_new_message) {
                self.zice_context.?.addInterfaceAddress(index, address) catch unreachable;
            } else {
                self.zice_context.?.deleteInterfaceAddress(index, address);
            }
        }
    }

    fn handleNetlinkInterfaceMessage(self: *NetlinkContext, message: std.os.linux.ifinfomsg, raw_attributes: []align(@alignOf(std.os.linux.rtattr)) const u8, is_new_message: bool) void {
        const index: u32 = @as(u32, @intCast(message.index));
        if (!is_new_message) {
            self.zice_context.?.deleteNetworkInterface(index);
            return;
        }

        var attribute_it = platform.netlink.AttributeIterator.init(raw_attributes);
        const name_opt: ?[]const u8 = while (attribute_it.next()) |raw_attribute| {
            const attribute = platform.netlink.IflaAttribute.from(raw_attribute);
            if (attribute == .IFNAME) {
                break attribute.IFNAME;
            }
        } else null;

        if (name_opt) |name| {
            self.zice_context.?.addNetworkInterface(index, name, @as(platform.netlink.ARPHRD, @enumFromInt(message.type))) catch {};
        }
    }
};

/// Convenience to build a basic STUN request.
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

/// Convert a MAPPED-ADDRESS STUN attributes to a std.net.Address.
pub fn fromStunAddress(mapped_address: ztun.attr.common.MappedAddress) std.net.Address {
    return switch (mapped_address.family) {
        .ipv4 => |value| std.net.Address.initIp4(value, mapped_address.port),
        .ipv6 => |value| std.net.Address.initIp6(value, mapped_address.port, 0, 0),
    };
}

/// Tries to extract the address from a STUN binding response or return null if that's not possible.
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
    pub fn from(self: *WriteData, address: std.net.Address, data: []u8) void {
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

/// Context for a candidate during the gathering process.
pub const GatheringContext = struct {
    /// The index of associated agent.
    agent_id: u32,
    /// Our index in the Agent Context.
    index: u32,
    /// The status of this candidate.
    status: CandidateGatheringStatus = .new,

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

    /// Counts the number of request sent.
    request_sent_count: u64 = 0,
    /// The current RTO (see RFC).
    rto: u64,

    /// Initialize a Candidate context from the given socket, address and rto.
    pub fn init(agent_id: u32, index: u32, rto: u64) !GatheringContext {
        const timer = try xev.Timer.init();
        errdefer timer.deinit();

        return .{
            .agent_id = agent_id,
            .index = index,
            .timer = timer,
            .rto = rto,
        };
    }

    /// Deinitialize a candidate context.
    pub fn deinit(self: *GatheringContext) void {
        self.timer.deinit();
    }

    /// Returns true if the gathering process seems to be done.
    pub inline fn isDone(self: *const GatheringContext) bool {
        return (self.status == .done or self.status == .failed) and
            self.timer_completion.state() == .dead and
            self.timer_cancel_completion.state() == .dead;
    }
};

// TODO(Corendos): This is a bit misnamed as multiple candidates can share the same CandidateContext.
// TODO(Corendos): Handle socket closing properly.
pub const CandidateContext = struct {
    /// The index of associated agent.
    agent_id: u32,
    /// Our index in the Agent Context.
    index: u32,

    /// The socket associated with the candidate.
    socket: std.os.fd_t,
    /// The candidate local address.
    address: std.net.Address,

    /// The buffer used to send a message.
    write_buffer: []u8 = &.{},
    /// The buffer used to read a message.
    read_buffer: []u8 = &.{},

    /// The data required to send a message.
    write_data: WriteData = undefined,

    /// The associated xev.Completion.
    write_completion: xev.Completion = .{},
    /// The associated xev.Completion.
    read_completion: xev.Completion = .{},

    pub fn init(agent_id: u32, index: u32, socket: std.os.fd_t, address: std.net.Address, read_buffer: []u8, write_buffer: []u8) CandidateContext {
        return CandidateContext{
            .agent_id = agent_id,
            .index = index,
            .socket = socket,
            .address = address,
            .write_buffer = write_buffer,
            .read_buffer = read_buffer,
        };
    }
};

const CandidateEntry = struct {
    candidate: Candidate,
    context_index: u32,
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
const CandidatePairStae = enum {
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
};

/// Represents a candidate pair to check.
const CandidatePair = struct {
    /// The index of the local candidate.
    local_candidate_index: usize,
    /// The index of the remote candidate.
    remote_candidate_index: usize,
    /// The pair priority.
    priority: u64,
};

/// Represents a checklist that will be used to check candidate pairs.
const Checklist = struct {
    /// The state of the checklist.
    state: ChecklistState = .running,
    /// The list of candidate pairs to check.
    pairs: []CandidatePair = &.{},
};

pub const AgentContext = struct {
    /// The id of this agent.
    id: u32,

    /// The allocator used by the AgentContext.
    allocator: std.mem.Allocator,

    /// The timer that fires when a new candidate can be checked.
    gathering_main_timer: xev.Timer,
    /// The associated xev.Completion.
    gathering_main_timer_completion: xev.Completion = .{},
    /// The agent gathering state.
    gathering_state: GatheringState = .idle,
    /// The agent state.
    state: AgentState = .created,

    buffer_arena_state: ?std.heap.ArenaAllocator = null,

    // TODO(Corendos): CandidateContext should be renamed as it's more of a SocketContext since multiple candidates
    //                 share the same socket.

    /// Contexts for each candidate.
    candidate_contexts: []CandidateContext = &.{},
    /// Gathering context for each candidate.
    gathering_contexts: []GatheringContext = &.{},

    local_candidates: std.ArrayListUnmanaged(CandidateEntry) = .{},
    remote_candidates: std.ArrayListUnmanaged(Candidate) = .{},
    has_remote_candidates: bool = false,

    // TODO(Corendos): handle multiple data-stream.
    /// The checklists used to check candidate pairs.
    checklist: Checklist = .{},

    role: ?AgentRole = null,

    /// Userdata that is given back in callbacks.
    userdata: ?*anyopaque,
    /// Callbacks to call when a new candidate is found during gathering (or when there won't be any new candidates).
    on_candidate_callback: OnCandidateCallback,
    /// Callback to call when the gathering state changes.
    on_state_change_callback: OnStateChangeCallback,

    pub fn init(
        id: u32,
        userdata: ?*anyopaque,
        on_candidate_callback: OnCandidateCallback,
        on_state_change_callback: OnStateChangeCallback,
        allocator: std.mem.Allocator,
    ) !AgentContext {
        var timer = try xev.Timer.init();
        return AgentContext{
            .id = id,
            .allocator = allocator,
            .gathering_main_timer = timer,
            .userdata = userdata,
            .on_candidate_callback = on_candidate_callback,
            .on_state_change_callback = on_state_change_callback,
        };
    }

    pub fn deinit(self: *AgentContext) void {
        self.gathering_main_timer.deinit();
        if (self.buffer_arena_state) |*s| s.deinit();
        self.allocator.free(self.candidate_contexts);
        for (self.gathering_contexts) |*ctx| ctx.deinit();
        self.allocator.free(self.gathering_contexts);
        self.local_candidates.deinit(self.allocator);
        self.remote_candidates.deinit(self.allocator);
        self.allocator.free(self.checklist.pairs);
    }

    pub fn initCandidates(self: *AgentContext, sockets: []const std.os.fd_t, addresses: []const std.net.Address) !void {
        std.debug.assert(sockets.len == addresses.len);
        const candidate_count = sockets.len;

        self.buffer_arena_state = std.heap.ArenaAllocator.init(self.allocator);
        errdefer self.buffer_arena_state = null;
        errdefer self.buffer_arena_state.?.deinit();

        const buffer_arena = self.buffer_arena_state.?.allocator();

        var candidate_contexts = try self.allocator.alloc(CandidateContext, candidate_count);
        errdefer self.allocator.free(candidate_contexts);
        for (0..candidate_count) |index| {
            const read_buffer = try buffer_arena.alloc(u8, 4096);
            const writer_buffer = try buffer_arena.alloc(u8, 4096);
            candidate_contexts[index] = CandidateContext.init(self.id, @intCast(index), sockets[index], addresses[index], read_buffer, writer_buffer);
        }

        var gathering_context_list = try std.ArrayList(GatheringContext).initCapacity(self.allocator, candidate_count);
        defer gathering_context_list.deinit();
        errdefer for (&gathering_context_list.items) |*ctx| ctx.deinit();

        for (0..candidate_count) |index| {
            gathering_context_list.appendAssumeCapacity(try GatheringContext.init(self.id, @intCast(index), Configuration.computeRtoMs(candidate_count)));
        }

        self.candidate_contexts = candidate_contexts;
        self.gathering_contexts = gathering_context_list.toOwnedSlice() catch unreachable;
    }

    /// Returns true if the gathering is done and we can call the callback with a valid result.
    fn isGatheringDone(self: *const AgentContext) bool {
        return self.gathering_main_timer_completion.state() == .dead and for (self.gathering_contexts) |*ctx| {
            if (!ctx.isDone()) break false;
        } else true;
    }

    /// Return the index of a candidate that has not been checked yet or null.
    fn getUncheckedCandidate(self: *const AgentContext) ?usize {
        for (self.gathering_contexts, 0..) |ctx, i| {
            if (ctx.status == .new) {
                return i;
            }
        }
        return null;
    }

    fn addLocalCandidate(self: *AgentContext, candidate: Candidate, context_index: u32) !void {
        try self.local_candidates.append(self.allocator, CandidateEntry{ .candidate = candidate, .context_index = context_index });
    }

    fn computePriorities(self: *AgentContext) void {
        // TODO(Corendos): Handle component ID as well.

        var arena_state = std.heap.ArenaAllocator.init(self.allocator);
        defer arena_state.deinit();

        const candidate_type_count = std.meta.tags(CandidateType).len;
        var candidate_lists_per_type: [candidate_type_count * 2]std.ArrayList(usize) = undefined;
        for (&candidate_lists_per_type) |*list| list.* = std.ArrayList(usize).initCapacity(arena_state.allocator(), self.local_candidates.items.len) catch unreachable;

        for (self.local_candidates.items, 0..) |entry, i| {
            const address_family = entry.candidate.transport_address.address.any.family;
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

    fn formCandidatesPairs(self: *AgentContext) void {
        // TODO(Corendos): Better handle checklist size
        var pairs = std.ArrayList(CandidatePair).initCapacity(self.allocator, 100) catch unreachable;

        for (self.local_candidates.items, 0..) |local_entry, i| {
            const local_component_id = local_entry.candidate.component_id;
            const local_address_family = local_entry.candidate.transport_address.address.any.family;
            for (self.remote_candidates.items, 0..) |remote_candidate, j| {
                const remote_component_id = remote_candidate.component_id;
                const remote_address_family = remote_candidate.transport_address.address.any.family;
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

        std.sort.heap(CandidatePair, pairs.items, {}, (struct {
            fn greaterThan(_: void, a: CandidatePair, b: CandidatePair) bool {
                return a.priority > b.priority;
            }
        }).greaterThan);

        self.checklist = Checklist{ .pairs = pairs.toOwnedSlice() catch unreachable };
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

pub const Operation = union(OperationType) {
    gather_candidates: void,
    set_remote_candidates: []Candidate,
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
    read: ztun.Message,
    /// A STUN message was sent and the payload contains the result.
    write: xev.WriteError!usize,
    /// The retry timer fired and the payload contains the result.
    retry_timer: xev.Timer.RunError!void,
    /// The retry timer was cancelled and the payload contains the result.
    cancel_retry_timer: xev.CancelError!void,
    /// The main timer fired and the payload contains the result.
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
        self.netlink_context.zice_context = self;
        try self.netlink_context.start(loop);
        self.async_handle.wait(loop, &self.async_completion, Context, self, Context.asyncCallback);
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

    pub fn setRemoteCandidates(self: *Context, c: *Completion, agent_id: u32, candidates: []Candidate) !void {
        c.* = Completion{
            .agent_id = agent_id,
            .op = .{ .set_remote_candidates = candidates },
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

            const socket = try std.os.socket(address.any.family, std.os.SOCK.DGRAM, 0);
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

        try agent_context.initCandidates(socket_list.items, address_list.items);

        for (agent_context.candidate_contexts, 0..) |ctx, index| {
            const candidate = Candidate{
                .type = .host,
                .base_address = TransportAddress{ .address = ctx.address, .type = .udp },
                .transport_address = TransportAddress{ .address = ctx.address, .type = .udp },
            };
            agent_context.addLocalCandidate(candidate, @intCast(index)) catch unreachable;
            agent_context.on_candidate_callback(agent_context.userdata, agent_context.id, .{ .candidate = candidate });
        }

        agent_context.gathering_main_timer.run(
            loop,
            &agent_context.gathering_main_timer_completion,
            Configuration.new_transaction_interval_ms,
            Context,
            self,
            Context.mainTimerCallback,
        );
    }

    fn processSetRemoteCandidates(self: *Context, agent_context: *AgentContext, candidates: []Candidate, loop: *xev.Loop) !void {
        try agent_context.remote_candidates.appendSlice(agent_context.allocator, candidates);
        agent_context.has_remote_candidates = true;

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
        agent_context.formCandidatesPairs();
        log.debug("Agent {} - Candidate pairs count: {}", .{ agent_context.id, agent_context.checklist.pairs.len });
        _ = self;
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
        candidate_index: ?u32,
        loop: *xev.Loop,
        result: GatheringEventResult,
    ) void {
        if (result == .main_timer) {
            self.handleMainTimer(agent_context, loop, result.main_timer);
        } else {
            const candidate_context = &agent_context.candidate_contexts[candidate_index.?];
            const gathering_context = &agent_context.gathering_contexts[candidate_index.?];

            switch (result) {
                .write => |r| self.handleStunMessageWrite(agent_context, candidate_context, gathering_context, loop, r),
                .read => |message| self.handleStunMessageRead(agent_context, candidate_context, gathering_context, loop, message),
                .retry_timer => |r| self.handleRetryTimer(agent_context, candidate_context, gathering_context, loop, r),
                .cancel_retry_timer => {},
                else => unreachable,
            }
        }

        if (!agent_context.isGatheringDone()) return;

        agent_context.gathering_state = .done;
        agent_context.on_state_change_callback(agent_context.userdata, agent_context.id, agent_context.gathering_state);

        agent_context.on_candidate_callback(agent_context.userdata, agent_context.id, .{ .done = {} });

        agent_context.removeRedundantAndSortCandidates();

        if (agent_context.has_remote_candidates) {
            self.startChecks(agent_context);
        }

        // TODO(Corendos):  start pairs checks.
    }

    fn handleStunMessageWrite(
        self: *Context,
        agent_context: *AgentContext,
        candidate_context: *CandidateContext,
        gathering_context: *GatheringContext,
        loop: *xev.Loop,
        result: xev.WriteError!usize,
    ) void {
        _ = agent_context;
        _ = result catch |err| {
            log.err("Got {} with candidate \"{}\" while writing to socket", .{ err, candidate_context.address });
            gathering_context.status = .failed;
            return;
        };

        gathering_context.request_sent_count += 1;
        log.debug("STUN request sent for candidate \"{}\"", .{candidate_context.address});

        const is_first_request = gathering_context.request_sent_count == 1;
        gathering_context.timer_timeout_ms = if (is_first_request) gathering_context.rto else gathering_context.timer_timeout_ms * 2;

        const is_last_request = gathering_context.request_sent_count == Configuration.request_count;
        if (is_last_request) {
            gathering_context.timer_timeout_ms = gathering_context.rto * Configuration.last_request_factor;
            gathering_context.is_retry_timer = false;
        }

        gathering_context.timer.run(
            loop,
            &gathering_context.timer_completion,
            gathering_context.timer_timeout_ms,
            Context,
            self,
            timerCallback,
        );
    }

    fn handleStunMessageRead(
        self: *Context,
        agent_context: *AgentContext,
        candidate_context: *CandidateContext,
        gathering_context: *GatheringContext,
        loop: *xev.Loop,
        message: ztun.Message,
    ) void {
        if (gathering_context.status != .checking) return;

        gathering_context.status = .done;
        log.debug("Gathering done for candidate \"{}\"", .{candidate_context.address});

        if (getServerReflexiveAddressFromStunMessage(message)) |transport_address| {
            const candidate = Candidate{
                .type = .server_reflexive,
                .transport_address = TransportAddress{ .address = transport_address, .type = .udp },
                .base_address = TransportAddress{ .address = candidate_context.address, .type = .udp },
            };
            agent_context.addLocalCandidate(candidate, candidate_context.index) catch unreachable;
            agent_context.on_candidate_callback(agent_context.userdata, agent_context.id, .{ .candidate = candidate });
        }

        gathering_context.timer.cancel(
            loop,
            &gathering_context.timer_completion,
            &gathering_context.timer_cancel_completion,
            Context,
            self,
            timerCancelCallback,
        );
    }

    fn handleRetryTimer(
        self: *Context,
        agent_context: *AgentContext,
        candidate_context: *CandidateContext,
        gathering_context: *GatheringContext,
        loop: *xev.Loop,
        result: xev.Timer.RunError!void,
    ) void {
        _ = agent_context;
        _ = result catch return;

        if (gathering_context.is_retry_timer) {
            log.debug("STUN request {}/{} from candidate \"{}\" timed out", .{ gathering_context.request_sent_count, Configuration.request_count, candidate_context.address });
            self.sendStunMessage(candidate_context, loop);
        } else {
            log.debug("Gathering timed out for candidate \"{}\"", .{candidate_context.address});
            gathering_context.status = .failed;
        }
    }

    fn handleMainTimer(self: *Context, agent_context: *AgentContext, loop: *xev.Loop, result: xev.Timer.RunError!void) void {
        _ = result catch |err| {
            log.err("{}", .{err});
            @panic("TODO");
        };

        // Get a candidate still in the .new state or disarm the timer.
        const candidate_index = agent_context.getUncheckedCandidate() orelse return;

        const candidate_context = &agent_context.candidate_contexts[candidate_index];
        const gathering_context = &agent_context.gathering_contexts[candidate_index];

        // Set the candidate in the .checking state
        gathering_context.status = .checking;

        // Start to listen for activity on the socket.
        candidate_context.read_completion = xev.Completion{
            .op = .{
                .read = .{
                    .fd = candidate_context.socket,
                    .buffer = xev.ReadBuffer{
                        .slice = candidate_context.read_buffer,
                    },
                },
            },
            .userdata = self,
            .callback = readCallback,
        };
        loop.add(&candidate_context.read_completion);

        log.debug("Sending message for candidate \"{}\"", .{candidate_context.address});
        self.sendStunMessage(candidate_context, loop);

        // NOTE(Corendos): Small improvement could be done here. If we now that there won't be any new candidates the next time we go through this function,
        //                 we could avoid one main timer delay.

        agent_context.gathering_main_timer.run(
            loop,
            &agent_context.gathering_main_timer_completion,
            Configuration.new_transaction_interval_ms,
            Context,
            self,
            mainTimerCallback,
        );
    }

    fn tryDecodeStunMessage(allocator: std.mem.Allocator, data: []const u8) ?ztun.Message {
        var stream = std.io.fixedBufferStream(data);
        return ztun.Message.readAlloc(stream.reader(), allocator) catch return null;
    }

    fn readCallback(
        userdata: ?*anyopaque,
        loop: *xev.Loop,
        c: *xev.Completion,
        result: xev.Result,
    ) xev.CallbackAction {
        const self = @as(*Context, @ptrCast(@alignCast(userdata.?)));
        const candidate_context = @fieldParentPtr(CandidateContext, "read_completion", c);
        const agent_context = self.agent_map.get(candidate_context.agent_id).?;

        const bytes_read = result.read catch |err| {
            log.err("Got {} with candidate \"{}\" while reading from socket", .{ err, candidate_context.address });
            return .rearm;
        };

        const data = candidate_context.read_buffer[0..bytes_read];

        var buffer: [4096]u8 = undefined;
        var allocator_state = std.heap.FixedBufferAllocator.init(&buffer);
        var allocator = allocator_state.allocator();

        if (tryDecodeStunMessage(allocator, data)) |stun_message| {
            defer stun_message.deinit(allocator);

            // TODO(Corendos): STUN messages can be request as well, not only response.
            self.handleGatheringEvent(agent_context, candidate_context.index, loop, .{ .read = stun_message });
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
        const self = @as(*Context, @ptrCast(@alignCast(userdata.?)));
        const candidate_context = @fieldParentPtr(CandidateContext, "write_completion", c);
        const agent_context = self.agent_map.get(candidate_context.agent_id).?;

        self.handleGatheringEvent(agent_context, candidate_context.index, loop, .{ .write = result.sendmsg });

        return .disarm;
    }

    fn timerCallback(
        userdata: ?*Context,
        loop: *xev.Loop,
        c: *xev.Completion,
        result: xev.Timer.RunError!void,
    ) xev.CallbackAction {
        const self = userdata.?;
        const gathering_context = @fieldParentPtr(GatheringContext, "timer_completion", c);
        const agent_context = self.agent_map.get(gathering_context.agent_id).?;

        self.handleGatheringEvent(agent_context, gathering_context.index, loop, .{ .retry_timer = result });

        return .disarm;
    }

    fn timerCancelCallback(
        userdata: ?*Context,
        loop: *xev.Loop,
        c: *xev.Completion,
        result: xev.CancelError!void,
    ) xev.CallbackAction {
        const self = userdata.?;
        const gathering_context = @fieldParentPtr(GatheringContext, "timer_cancel_completion", c);
        const agent_context = self.agent_map.get(gathering_context.agent_id).?;

        self.handleGatheringEvent(agent_context, gathering_context.index, loop, .{ .cancel_retry_timer = result });

        return .disarm;
    }

    fn mainTimerCallback(
        userdata: ?*Context,
        loop: *xev.Loop,
        c: *xev.Completion,
        result: xev.Timer.RunError!void,
    ) xev.CallbackAction {
        const self = userdata.?;
        const agent_context = @fieldParentPtr(AgentContext, "gathering_main_timer_completion", c);

        self.handleGatheringEvent(agent_context, null, loop, .{ .main_timer = result });

        return .disarm;
    }

    fn sendStunMessage(self: *Context, candidate_context: *CandidateContext, loop: *xev.Loop) void {
        const data = blk: {
            var buffer: [4096]u8 = undefined;
            var allocator_state = std.heap.FixedBufferAllocator.init(&buffer);
            var allocator = allocator_state.allocator();
            const request_message = makeRequest(allocator) catch unreachable;
            defer request_message.deinit(allocator);

            var stream = std.io.fixedBufferStream(candidate_context.write_buffer);
            request_message.write(stream.writer()) catch unreachable;
            break :blk stream.getWritten();
        };

        const address = switch (candidate_context.address.any.family) {
            std.os.AF.INET => Configuration.stun_address_ipv4,
            std.os.AF.INET6 => Configuration.stun_address_ipv6,
            else => unreachable,
        };

        candidate_context.write_data.from(address, data);

        candidate_context.write_completion = xev.Completion{
            .op = .{
                .sendmsg = .{
                    .fd = candidate_context.socket,
                    .msghdr = &candidate_context.write_data.message_header,
                    .buffer = null,
                },
            },
            .userdata = self,
            .callback = stunWriteCallback,
        };
        loop.add(&candidate_context.write_completion);
    }
};

test {
    _ = Worker;
    _ = Intrusive;
    _ = platform;
    _ = net;
}
