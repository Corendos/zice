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
        std.log.debug("Requesting initial Interfaces", .{});
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
        std.log.debug("Requesting initial Addresses", .{});
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
                        },
                        else => {},
                    }
                }
            } else |err| self.readError(err, loop);
        } else |err| self.readError(err, loop);

        return .rearm;
    }

    fn writeError(self: *NetlinkContext, err: anyerror, loop: *xev.Loop) void {
        std.log.err("Got {} while writing in {s} state, retrying...", .{ err, @tagName(self.state) });

        switch (self.state) {
            .initial_interfaces => self.requestInterfaces(loop),
            .initial_addresses => self.requestAddresses(loop),
            else => unreachable,
        }
    }

    fn readError(self: *NetlinkContext, err: anyerror, loop: *xev.Loop) void {
        std.log.err("Got {} while reading in {s} state, retrying...", .{ err, @tagName(self.state) });

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
                std.log.err("{}", .{error_message.@"error"});
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
pub const MessageData = struct {
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
            .iov = @as([*]const std.os.iovec_const, @ptrCast(&self.iovec)),
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
pub const OnCandidateCallback = *const fn (userdata: ?*anyopaque, agent_index: u32, result: CandidateResult) void;
fn noopCandidateCallback(_: ?*anyopaque, _: u32, _: CandidateResult) void {}

/// Callback that is called when the ICE state changes.
pub const OnStateChangeCallback = *const fn (userdata: ?*anyopaque, agent_index: u32, state: GatheringState) void;
fn noopStateChangeCallback(_: ?*anyopaque, _: u32, _: GatheringState) void {}

/// Context for a candidate during the gathering process.
pub const GatheringContext = struct {
    /// The status of this candidate.
    status: CandidateGatheringStatus = .new,

    /// The timer that is used for retry and failure.
    timer: xev.Timer,
    /// The current timeout for the retry timer.
    timer_timeout_ms: u64 = 0,
    /// Is the timer used for a retry or for a failure.
    is_retry_timer: bool = true,

    /// Counts the number of request sent.
    request_sent_count: u64 = 0,
    /// The current RTO (see RFC).
    rto: u64,

    /// Initialize a Candidate context from the given socket, address and rto.
    pub fn init(rto: u64) !GatheringContext {
        const timer = try xev.Timer.init();
        errdefer timer.deinit();

        return .{
            .timer = timer,
            .rto = rto,
        };
    }

    /// Deinitialize a candidate context.
    pub fn deinit(self: *GatheringContext) void {
        self.timer.deinit();
    }
};

// TODO(Corendos): Handle socket closing properly.
pub const CandidateContext = struct {
    /// The socket associated with the candidate.
    socket: std.os.fd_t,
    /// The candidate local address.
    address: std.net.Address,

    /// The data required to send a message.
    message_data: MessageData = undefined,
    /// The data required to read a message.
    read_buffer: []u8 = &.{},

    pub fn init(socket: std.os.fd_t, address: std.net.Address, read_buffer: []u8, write_buffer: []u8) CandidateContext {
        return CandidateContext{
            .socket = socket,
            .address = address,
            .message_data = .{ .buffer = write_buffer },
            .read_buffer = read_buffer,
        };
    }
};

/// Stores the completions required for a Candidate, but also some indices for bookkeeping.
pub const CompletionData = struct {
    /// The index of associated agent.
    agent_index: u32,
    /// The index of the associate candidate.
    candidate_index: u32,

    /// The associated xev.Completion.
    write_completion: xev.Completion = .{},
    /// The associated xev.Completion.
    read_completion: xev.Completion = .{},
    /// The xev.Completion used to cancel the read.
    cancel_read_completion: xev.Completion = .{},
    /// The associated xev.Completion.
    timer_completion: xev.Completion = .{},
    /// The associated cancel xev.Completion
    timer_cancel_completion: xev.Completion = .{},

    /// Returns true if the gathering process seems to be done.
    pub inline fn isGatheringDone(self: *const CompletionData) bool {
        return self.timer_completion.state() == .dead and self.timer_cancel_completion.state() == .dead;
    }
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

    /// Completion data for each candidate.
    completion_data: []CompletionData = &.{},

    /// Read buffers of each candidate.
    read_buffers: ?[][4096]u8 = null,
    /// Write buffers of each candidate.
    write_buffers: ?[][4096]u8 = null,
    /// Contexts for each candidate.
    candidate_contexts: []CandidateContext = &.{},
    /// Gathering context for each candidate.
    gathering_contexts: []GatheringContext = &.{},

    /// Userdata that is given back in callbacks.
    userdata: ?*anyopaque,
    /// Callbacks to call when a new candidate is found during gathering (or when there won't be any new candidates).
    on_candidate_callback: OnCandidateCallback,
    /// Callback to call when the gathering state changes.
    on_state_change_callback: OnStateChangeCallback,

    pub fn init(
        index: u32,
        userdata: ?*anyopaque,
        on_candidate_callback: OnCandidateCallback,
        on_state_change_callback: OnStateChangeCallback,
        allocator: std.mem.Allocator,
    ) !AgentContext {
        var timer = try xev.Timer.init();
        return AgentContext{
            .index = index,
            .allocator = allocator,
            .gathering_main_timer = timer,
            .userdata = userdata,
            .on_candidate_callback = on_candidate_callback,
            .on_state_change_callback = on_state_change_callback,
        };
    }

    pub fn deinit(self: *AgentContext) void {
        self.gathering_main_timer.deinit();
        if (self.write_buffers) |write_buffers| self.allocator.free(write_buffers);
        if (self.read_buffers) |read_buffers| self.allocator.free(read_buffers);
        self.allocator.free(self.completion_data);
        self.allocator.free(self.candidate_contexts);
        for (self.gathering_contexts) |*ctx| ctx.deinit();
        self.allocator.free(self.gathering_contexts);
    }

    pub fn initCandidates(self: *AgentContext, sockets: []const std.os.fd_t, addresses: []const std.net.Address) !void {
        std.debug.assert(sockets.len == addresses.len);
        const candidate_count = sockets.len;

        var completion_data = try self.allocator.alloc(CompletionData, candidate_count);
        errdefer self.allocator.free(completion_data);

        for (completion_data, 0..) |*c, i| c.* = CompletionData{ .agent_index = self.index, .candidate_index = @intCast(i) };

        var write_buffers = try self.allocator.alloc([4096]u8, candidate_count);
        errdefer self.allocator.free(write_buffers);

        var read_buffers = try self.allocator.alloc([4096]u8, candidate_count);
        errdefer self.allocator.free(read_buffers);

        var candidate_contexts = try self.allocator.alloc(CandidateContext, candidate_count);
        errdefer self.allocator.free(candidate_contexts);
        for (candidate_contexts, sockets, addresses, write_buffers, read_buffers) |*ctx, socket, address, *write_buffer, *read_buffer| {
            ctx.* = CandidateContext.init(socket, address, read_buffer[0..], write_buffer[0..]);
        }

        var gathering_context_list = try std.ArrayList(GatheringContext).initCapacity(self.allocator, candidate_count);
        defer gathering_context_list.deinit();
        errdefer for (&gathering_context_list.items) |*ctx| ctx.deinit();

        for (0..candidate_count) |_| {
            gathering_context_list.appendAssumeCapacity(try GatheringContext.init(Configuration.computeRtoMs(candidate_count)));
        }

        self.completion_data = completion_data;
        self.candidate_contexts = candidate_contexts;
        self.gathering_contexts = gathering_context_list.toOwnedSlice() catch unreachable;
        self.write_buffers = write_buffers;
        self.read_buffers = read_buffers;
    }

    /// Returns true if the gathering is done and we can call the callback with a valid result.
    fn isGatheringDone(self: *const AgentContext) bool {
        return self.gathering_main_timer_completion.state() == .dead and for (self.completion_data) |*ctx| {
            if (!ctx.isGatheringDone()) break false;
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
};

pub const Operation = union(OperationType) {
    gather_candidates: void,
};

pub const Callback = *const fn (?*anyopaque) void;

pub fn noopCallback(userdata: ?*anyopaque) void {
    _ = userdata;
}

pub const Completion = struct {
    agent_index: u32 = 0,
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
    agent_index: u32 = 1024,

    string_storage: std.heap.ArenaAllocator,

    netlink_context: NetlinkContext,

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

    pub fn addNetworkInterface(self: *Context, index: u32, name: []const u8, interface_type: platform.netlink.ARPHRD) !void {
        const gop = try self.network_interface_map.getOrPut(self.allocator, index);
        if (!gop.found_existing) {
            std.log.debug("New interface: {s}", .{name});
            gop.value_ptr.* = NetworkInterface{
                .name = try self.string_storage.allocator().dupe(u8, name),
                .index = index,
                .type = interface_type,
            };
        }
    }

    pub fn deleteNetworkInterface(self: *Context, index: u32) void {
        std.log.debug("Delete interface {}", .{index});
        _ = self.network_interface_map.swapRemove(index);
    }

    fn searchAddress(self: *Context, interface_index: u32, address: std.net.Address) ?usize {
        return for (self.interface_addresses.items, 0..) |item, i| {
            if (item.interface_index == interface_index and item.address.eql(address)) {
                return i;
            }
        } else null;
    }

    pub fn addInterfaceAddress(self: *Context, interface_index: u32, address: std.net.Address) !void {
        if (self.searchAddress(interface_index, address) != null) return;

        std.log.debug("New Address for interface {}: {}", .{ interface_index, address });
        try self.interface_addresses.append(self.allocator, .{
            .interface_index = interface_index,
            .address = address,
        });
    }

    pub fn deleteInterfaceAddress(self: *Context, interface_index: u32, address: std.net.Address) void {
        std.log.debug("Delete Address for interface {}: {}", .{ interface_index, address });
        const index = self.searchAddress(interface_index, address) orelse return;
        _ = self.interface_addresses.swapRemove(index);
    }

    // TODO(Corendos): Maybe that should be async as well ?
    //                 I struggle with the fact that agent can be deleted on a separate thread and mess
    //                 up the internal state of the zice Context...

    pub fn newAgent(self: *Context, options: CreateAgentOptions) !u32 {
        self.agent_map_mutex.lock();
        defer self.agent_map_mutex.unlock();

        const agent_id = a: {
            defer self.agent_index += 1;
            break :a self.agent_index;
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

    pub fn gatherCandidates(self: *Context, agent_id: u32) !void {
        var barrier = std.Thread.ResetEvent{};
        var completion = Completion{
            .agent_index = agent_id,
            .op = .{ .gather_candidates = {} },
            .userdata = &barrier,
            .callback = (struct {
                fn callback(userdata: ?*anyopaque) void {
                    var inner_barrier: *std.Thread.ResetEvent = @alignCast(@ptrCast(userdata.?));
                    inner_barrier.set();
                }
            }).callback,
        };
        self.async_queue.push(&completion);
        try self.async_handle.notify();

        barrier.wait();
    }

    pub fn processGatherCandidates(self: *Context, completion: *Completion, loop: *xev.Loop) !void {
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
            try socket_list.append(socket);
            try address_list.append(bound_address);
        }

        self.agent_map_mutex.lock();
        defer self.agent_map_mutex.unlock();
        const agent_context: *AgentContext = self.agent_map.get(completion.agent_index) orelse return error.InvalidAgent;

        agent_context.gathering_state = .gathering;
        agent_context.on_state_change_callback(agent_context.userdata, agent_context.index, agent_context.gathering_state);

        try agent_context.initCandidates(socket_list.items, address_list.items);

        for (agent_context.candidate_contexts) |ctx| {
            const candidate = Candidate{
                .type = .host,
                .base_address = ctx.address,
                .transport_address = ctx.address,
            };
            agent_context.on_candidate_callback(agent_context.userdata, agent_context.index, .{ .candidate = candidate });
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

    fn asyncCallback(
        userdata: ?*Context,
        loop: *xev.Loop,
        _: *xev.Completion,
        result: xev.Async.WaitError!void,
    ) xev.CallbackAction {
        const self = userdata orelse unreachable;
        _ = result catch {};

        while (self.async_queue.pop()) |completion| {
            std.log.debug("Received {s} completion for agent {}", .{ @tagName(completion.op), completion.agent_index });
            switch (completion.op) {
                .gather_candidates => self.processGatherCandidates(completion, loop) catch @panic("TODO"),
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
        candidate_context: ?*CandidateContext,
        gathering_context: ?*GatheringContext,
        completion_data: ?*CompletionData,
        loop: *xev.Loop,
        result: GatheringEventResult,
    ) void {
        switch (result) {
            .write => |r| self.handleStunMessageWrite(agent_context, candidate_context.?, gathering_context.?, completion_data.?, loop, r),
            .read => |message| self.handleStunMessageRead(agent_context, candidate_context.?, gathering_context.?, completion_data.?, loop, message),
            .retry_timer => |r| self.handleRetryTimer(agent_context, candidate_context.?, gathering_context.?, completion_data.?, loop, r),
            .cancel_retry_timer => {},
            .main_timer => |r| self.handleMainTimer(agent_context, loop, r),
        }

        if (agent_context.isGatheringDone()) {
            agent_context.gathering_state = .done;
            agent_context.on_state_change_callback(agent_context.userdata, agent_context.index, agent_context.gathering_state);

            agent_context.on_candidate_callback(agent_context.userdata, agent_context.index, .{ .done = {} });
        }
    }

    fn handleStunMessageWrite(
        self: *Context,
        agent_context: *AgentContext,
        candidate_context: *CandidateContext,
        gathering_context: *GatheringContext,
        completion_data: *CompletionData,
        loop: *xev.Loop,
        result: xev.WriteError!usize,
    ) void {
        _ = agent_context;
        _ = result catch |err| {
            std.log.err("Got {} with candidate \"{}\" while writing to socket", .{ err, candidate_context.address });
            gathering_context.status = .failed;
            return;
        };

        gathering_context.request_sent_count += 1;
        std.log.debug("STUN request sent for candidate \"{}\"", .{candidate_context.address});

        const is_first_request = gathering_context.request_sent_count == 1;
        gathering_context.timer_timeout_ms = if (is_first_request) gathering_context.rto else gathering_context.timer_timeout_ms * 2;

        const is_last_request = gathering_context.request_sent_count == Configuration.request_count;
        if (is_last_request) {
            gathering_context.timer_timeout_ms = gathering_context.rto * Configuration.last_request_factor;
            gathering_context.is_retry_timer = false;
        }

        gathering_context.timer.run(
            loop,
            &completion_data.timer_completion,
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
        completion_data: *CompletionData,
        loop: *xev.Loop,
        message: ztun.Message,
    ) void {
        if (gathering_context.status != .checking) return;

        gathering_context.status = .done;
        std.log.debug("Gathering done for candidate \"{}\"", .{candidate_context.address});

        if (getServerReflexiveAddressFromStunMessage(message)) |transport_address| {
            const candidate = Candidate{
                .type = .server_reflexive,
                .transport_address = transport_address,
                .base_address = candidate_context.address,
            };
            agent_context.on_candidate_callback(agent_context.userdata, agent_context.index, .{ .candidate = candidate });
        }

        gathering_context.timer.cancel(
            loop,
            &completion_data.timer_completion,
            &completion_data.timer_cancel_completion,
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
        completion_data: *CompletionData,
        loop: *xev.Loop,
        result: xev.Timer.RunError!void,
    ) void {
        _ = agent_context;
        _ = result catch return;

        if (gathering_context.is_retry_timer) {
            std.log.debug("STUN request {}/{} from candidate \"{}\" timed out", .{ gathering_context.request_sent_count, Configuration.request_count, candidate_context.address });
            self.sendStunMessage(candidate_context, completion_data, loop);
        } else {
            std.log.debug("Gathering timed out for candidate \"{}\"", .{candidate_context.address});
            gathering_context.status = .failed;
        }
    }

    fn handleMainTimer(self: *Context, agent_context: *AgentContext, loop: *xev.Loop, result: xev.Timer.RunError!void) void {
        _ = result catch |err| {
            std.log.err("{}", .{err});
            @panic("TODO");
        };

        // Get a candidate still in the .new state or disarm the timer.
        const candidate_index = agent_context.getUncheckedCandidate() orelse return;

        const candidate_context = &agent_context.candidate_contexts[candidate_index];
        const gathering_context = &agent_context.gathering_contexts[candidate_index];
        const completion_data = &agent_context.completion_data[candidate_index];

        // Set the candidate in the .checking state
        gathering_context.status = .checking;

        // Start to listen for activity on the socket.
        completion_data.read_completion = xev.Completion{
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
        loop.add(&completion_data.read_completion);

        std.log.debug("Sending message for candidate \"{}\"", .{candidate_context.address});
        self.sendStunMessage(candidate_context, completion_data, loop);

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
        const completion_data = @fieldParentPtr(CompletionData, "read_completion", c);
        const agent_context = self.agent_map.get(completion_data.agent_index).?;
        const candidate_context = &agent_context.candidate_contexts[completion_data.candidate_index];
        const gathering_context = &agent_context.gathering_contexts[completion_data.candidate_index];

        const bytes_read = result.read catch |err| {
            std.log.err("Got {} with candidate \"{}\" while reading from socket", .{ err, candidate_context.address });
            return .rearm;
        };

        const data = candidate_context.read_buffer[0..bytes_read];

        var buffer: [4096]u8 = undefined;
        var allocator_state = std.heap.FixedBufferAllocator.init(&buffer);
        var allocator = allocator_state.allocator();

        if (tryDecodeStunMessage(allocator, data)) |stun_message| {
            defer stun_message.deinit(allocator);

            // TODO(Corendos): STUN messages can be request as well, not only response.
            self.handleGatheringEvent(agent_context, candidate_context, gathering_context, completion_data, loop, .{ .read = stun_message });
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
        const completion_data = @fieldParentPtr(CompletionData, "write_completion", c);
        const agent_context = self.agent_map.get(completion_data.agent_index).?;
        const candidate_context = &agent_context.candidate_contexts[completion_data.candidate_index];
        const gathering_context = &agent_context.gathering_contexts[completion_data.candidate_index];

        self.handleGatheringEvent(agent_context, candidate_context, gathering_context, completion_data, loop, .{ .write = result.sendmsg });

        return .disarm;
    }

    fn timerCallback(
        userdata: ?*Context,
        loop: *xev.Loop,
        c: *xev.Completion,
        result: xev.Timer.RunError!void,
    ) xev.CallbackAction {
        const self = userdata.?;
        const completion_data = @fieldParentPtr(CompletionData, "timer_completion", c);
        const agent_context = self.agent_map.get(completion_data.agent_index).?;
        const candidate_context = &agent_context.candidate_contexts[completion_data.candidate_index];
        const gathering_context = &agent_context.gathering_contexts[completion_data.candidate_index];

        self.handleGatheringEvent(agent_context, candidate_context, gathering_context, completion_data, loop, .{ .retry_timer = result });

        return .disarm;
    }

    fn timerCancelCallback(
        userdata: ?*Context,
        loop: *xev.Loop,
        c: *xev.Completion,
        result: xev.CancelError!void,
    ) xev.CallbackAction {
        const self = userdata.?;
        const completion_data = @fieldParentPtr(CompletionData, "timer_cancel_completion", c);
        const agent_context = self.agent_map.get(completion_data.agent_index).?;
        const candidate_context = &agent_context.candidate_contexts[completion_data.candidate_index];
        const gathering_context = &agent_context.gathering_contexts[completion_data.candidate_index];

        self.handleGatheringEvent(agent_context, candidate_context, gathering_context, completion_data, loop, .{ .cancel_retry_timer = result });

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

        self.handleGatheringEvent(agent_context, null, null, null, loop, .{ .main_timer = result });

        return .disarm;
    }

    fn sendStunMessage(self: *Context, candidate_context: *CandidateContext, completion_data: *CompletionData, loop: *xev.Loop) void {
        const message_size = blk: {
            var buffer: [4096]u8 = undefined;
            var allocator_state = std.heap.FixedBufferAllocator.init(&buffer);
            var allocator = allocator_state.allocator();
            const request_message = makeRequest(allocator) catch unreachable;
            defer request_message.deinit(allocator);

            var stream = std.io.fixedBufferStream(candidate_context.message_data.buffer);
            request_message.write(stream.writer()) catch unreachable;
            break :blk stream.getWritten().len;
        };

        const address = switch (candidate_context.address.any.family) {
            std.os.AF.INET => Configuration.stun_address_ipv4,
            std.os.AF.INET6 => Configuration.stun_address_ipv6,
            else => unreachable,
        };

        // TODO(Corendos): Maybe the size can be set elsewhere ?
        candidate_context.message_data.setFrom(address, message_size);

        completion_data.write_completion = xev.Completion{
            .op = .{
                .sendmsg = .{
                    .fd = candidate_context.socket,
                    .msghdr = &candidate_context.message_data.message_header,
                    .buffer = null,
                },
            },
            .userdata = self,
            .callback = stunWriteCallback,
        };
        loop.add(&completion_data.write_completion);
    }
};

test {
    _ = Worker;
    _ = Intrusive;
    _ = platform;
    _ = net;
}
