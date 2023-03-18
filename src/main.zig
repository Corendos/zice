// Copyright 2023 - Corentin Godeau and the zice contributors
// SPDX-License-Identifier: MIT

const std = @import("std");
const builtin = @import("builtin");
const ztun = @import("ztun");
const xev = @import("xev");

pub const Intrusive = @import("queue.zig").Intrusive;

const platform = switch (builtin.os.tag) {
    .linux => @import("zice/linux.zig"),
    else => @compileError("\"" ++ @tagName(builtin.os.tag) ++ "\" platform is not supported yet."),
};

pub const net = @import("net.zig");
pub usingnamespace platform;

pub const CandidateType = enum {
    host,
    server_reflexive,
    peer_reflexive,
    relay,
};

pub const Candidate = struct {
    type: CandidateType,
    transport_address: std.net.Address,
    base_address: std.net.Address,
};

pub const Configuration = struct {
    /// Represents the value of Ta in the RFC 8489.
    pub const new_transaction_interval_ms: u64 = 50;
    /// Represents the value of Rc in the RFC 8489.
    pub const request_count: u64 = 7; // TODO(Corentin): revert to 7
    /// Represents the value of Rm in the RFC 8489.
    pub const last_request_factor: u64 = 16; // TODO(Corentin): revert to 16

    //const stun_address_ipv4 = std.net.Address.parseIp4("91.134.140.104", 3478) catch unreachable;
    const stun_address_ipv4 = std.net.Address.parseIp4("172.253.120.127", 19302) catch unreachable;
    const stun_address_ipv6 = std.net.Address.parseIp6("2a00:1450:400c:c00::7f", 19302) catch unreachable;

    pub inline fn computeRtoMs(candidate_count: u64) u64 {
        return std.math.max(500, candidate_count * new_transaction_interval_ms);
    }
};

pub const MessageData = struct {
    completion: xev.Completion = .{},
    buffer: []u8,
    iovec: std.os.iovec_const = undefined,
    message_header: std.os.msghdr_const = undefined,

    pub fn setFrom(self: *MessageData, address: *const std.net.Address, size: usize) void {
        self.iovec = .{
            .iov_base = self.buffer.ptr,
            .iov_len = size,
        };

        self.message_header = .{
            .name = &address.any,
            .namelen = address.getOsSockLen(),
            .control = null,
            .controllen = 0,
            .iov = @ptrCast([*]const std.os.iovec_const, &self.iovec),
            .iovlen = 1,
            .flags = 0,
        };
    }
};

pub const CandidateGatheringContext = struct {
    candidate: Candidate,
    socket: net.Socket,
    status: GatheringStatus = .new,

    message_data: MessageData,

    read_data: struct {
        completion: xev.Completion = .{},
        cancel_completion: xev.Completion = .{},
        buffer: []u8,
    },

    retry_timer_context: RetryTimerContext,
    failed_timer_completion: xev.Completion = .{},
    failed_timer: xev.Timer,
    rto: u64,
    candidate_list: *std.ArrayList(Candidate),

    pub fn init(candidate: Candidate, socket: net.Socket, rto: u64, candidate_list: *std.ArrayList(Candidate), allocator: std.mem.Allocator) !CandidateGatheringContext {
        var retry_timer = try xev.Timer.init();
        errdefer retry_timer.deinit();

        var failed_timer = try xev.Timer.init();
        errdefer failed_timer.deinit();

        var read_buffer = try allocator.alloc(u8, 4096);
        errdefer allocator.free(read_buffer);

        var write_buffer = try allocator.alloc(u8, 4096);
        errdefer allocator.free(write_buffer);

        return CandidateGatheringContext{
            .candidate = candidate,
            .socket = socket,
            .message_data = .{
                .buffer = write_buffer,
            },
            .read_data = .{
                .buffer = read_buffer,
            },
            .retry_timer_context = .{ .timer = retry_timer },
            .failed_timer = failed_timer,
            .rto = rto,
            .candidate_list = candidate_list,
        };
    }

    pub fn deinit(self: CandidateGatheringContext, allocator: std.mem.Allocator) void {
        self.retry_timer_context.timer.deinit();
        self.failed_timer.deinit();
        allocator.free(self.read_data.buffer);
        allocator.free(self.message_data.buffer);
    }
};

pub const GatheringStatus = enum {
    new,
    checking,
    failed,
    done,
};

const RetryTimerContext = struct {
    timer: xev.Timer,
    completion: xev.Completion = undefined,
    timeout_ms: u64 = 0,
    request_sent_count: usize = 0,
};

const GatheringContext = struct {
    const Self = GatheringContext;

    candidate_contexts: []CandidateGatheringContext,
    candidate_list: *std.ArrayList(Candidate),

    main_timer: xev.Timer,

    pub fn init(allocator: std.mem.Allocator, sockets: []net.Socket, candidates: []const Candidate, candidate_list: *std.ArrayList(Candidate)) !Self {
        const count = candidates.len;

        var candidate_gathering_contexts = try allocator.alloc(CandidateGatheringContext, count);
        errdefer allocator.free(candidate_gathering_contexts);

        const initial_timeout = Configuration.computeRtoMs(candidates.len);
        for (candidate_gathering_contexts, 0..) |*ctx, i| {
            ctx.* = try CandidateGatheringContext.init(candidates[i], sockets[i], initial_timeout, candidate_list, allocator);
        }
        errdefer for (candidate_gathering_contexts) |*ctx| {
            ctx.deinit(allocator);
        };

        const main_timer = try xev.Timer.init();
        errdefer main_timer.deinit();

        return Self{
            .candidate_contexts = candidate_gathering_contexts,
            .candidate_list = candidate_list,
            .main_timer = main_timer,
        };
    }

    pub fn deinit(self: GatheringContext, allocator: std.mem.Allocator) void {
        self.main_timer.deinit();

        for (self.candidate_contexts) |*ctx| ctx.deinit(allocator);
        allocator.free(self.candidate_contexts);
    }

    pub fn findCandidateToCheck(self: Self) ?usize {
        for (self.candidate_contexts, 0..) |ctx, i| {
            if (ctx.status == .new) {
                return i;
            }
        }
        return null;
    }

    pub inline fn done(self: Self) bool {
        for (self.candidate_contexts) |ctx| {
            if (ctx.status == .new or ctx.status == .checking) return false;
        }
        return true;
    }
};

pub fn makeRequest(allocator: std.mem.Allocator) !ztun.Message {
    var message_builder = ztun.MessageBuilder.init(allocator);
    defer message_builder.deinit();

    // Binding request with random transaction ID.
    message_builder.setClass(ztun.Class.request);
    message_builder.setMethod(ztun.Method.binding);
    message_builder.randomTransactionId();

    // Authentication attributes.
    // const username_attribute = ztun.attr.common.Username{ .value = "anon" };
    // const attribute = try username_attribute.toAttribute(allocator);
    // errdefer allocator.free(attribute.data);
    // try message_builder.addAttribute(attribute);

    // const authentication = ztun.auth.Authentication{ .short_term = ztun.auth.ShortTermAuthentication{ .password = "password" } };

    // message_builder.addMessageIntegrity(authentication);
    // message_builder.addMessageIntegritySha256(authentication);

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

fn failedTimerCallback(userdata: ?*CandidateGatheringContext, loop: *xev.Loop, c: *xev.Completion, result: xev.Timer.RunError!void) xev.CallbackAction {
    const candidate_context_ptr = userdata.?;
    if (candidate_context_ptr.status == .done) return .disarm;
    std.debug.assert(candidate_context_ptr.status == .checking);
    _ = result catch unreachable;
    _ = c;

    std.log.debug("Gathering timed out for candidate \"{}\"", .{candidate_context_ptr.candidate.base_address});

    candidate_context_ptr.status = .failed;

    candidate_context_ptr.read_data.cancel_completion = xev.Completion{
        .op = .{
            .cancel = .{ .c = &candidate_context_ptr.read_data.completion },
        },
    };
    loop.add(&candidate_context_ptr.read_data.cancel_completion);

    return .disarm;
}

fn retryTimerCallback(userdata: ?*CandidateGatheringContext, loop: *xev.Loop, c: *xev.Completion, result: xev.Timer.RunError!void) xev.CallbackAction {
    _ = result catch unreachable;
    _ = c;
    const candidate_context_ptr = userdata.?;
    if (candidate_context_ptr.status == .done or candidate_context_ptr.status == .failed) return .disarm;

    std.debug.assert(candidate_context_ptr.status == .checking);

    const retry_timer_context = &candidate_context_ptr.retry_timer_context;
    std.log.debug("STUN request {}/{} from candidate \"{}\" timed out", .{ retry_timer_context.request_sent_count, Configuration.request_count, candidate_context_ptr.candidate.base_address });

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

    const address = switch (candidate_context_ptr.candidate.base_address.any.family) {
        std.os.AF.INET => Configuration.stun_address_ipv4,
        std.os.AF.INET6 => Configuration.stun_address_ipv6,
        else => unreachable,
    };
    candidate_context_ptr.message_data.setFrom(&address, message_size);

    candidate_context_ptr.message_data.completion = xev.Completion{
        .op = .{
            .sendmsg = .{
                .fd = candidate_context_ptr.socket.fd,
                .msghdr = &candidate_context_ptr.message_data.message_header,
                .buffer = null,
            },
        },
        .userdata = candidate_context_ptr,
        .callback = sendMsgCallback,
    };
    loop.add(&candidate_context_ptr.message_data.completion);

    return .disarm;
}

fn readCallback(userdata: ?*anyopaque, loop: *xev.Loop, c: *xev.Completion, result: xev.Result) xev.CallbackAction {
    const candidate_context_ptr = @ptrCast(*CandidateGatheringContext, @alignCast(8, userdata.?));
    const bytes_read = result.read catch |err| {
        std.log.err("Got {} with candidate \"{}\" while reading from socket", .{ err, candidate_context_ptr.candidate.base_address });
        candidate_context_ptr.status = .failed;
        return .disarm;
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

    candidate_context_ptr.status = .done;
    std.log.debug("Gathering done for candidate \"{}\"", .{candidate_context_ptr.candidate.base_address});

    if (getServerReflexiveAddressFromStunMessage(message)) |transport_address| {
        candidate_context_ptr.candidate_list.append(Candidate{
            .type = .server_reflexive,
            .transport_address = transport_address,
            .base_address = candidate_context_ptr.candidate.base_address,
        }) catch unreachable;
    }

    return .disarm;
}

fn sendMsgCallback(userdata: ?*anyopaque, loop: *xev.Loop, c: *xev.Completion, result: xev.Result) xev.CallbackAction {
    const candidate_context_ptr = @ptrCast(*CandidateGatheringContext, @alignCast(8, userdata.?));
    _ = result.sendmsg catch |err| {
        std.log.err("Got {} with candidate \"{}\" while writing to socket", .{ err, candidate_context_ptr.candidate.base_address });
        candidate_context_ptr.status = .failed;
        return .disarm;
    };
    _ = c;

    candidate_context_ptr.retry_timer_context.request_sent_count += 1;
    std.log.debug("STUN request sent for candidate \"{}\"", .{candidate_context_ptr.candidate.base_address});

    if (candidate_context_ptr.retry_timer_context.request_sent_count == 1) {
        candidate_context_ptr.read_data.completion = xev.Completion{
            .op = .{ .read = .{
                .fd = candidate_context_ptr.socket.fd,
                .buffer = xev.ReadBuffer{
                    .slice = candidate_context_ptr.read_data.buffer,
                },
            } },
            .userdata = candidate_context_ptr,
            .callback = readCallback,
        };
        loop.add(&candidate_context_ptr.read_data.completion);
        candidate_context_ptr.retry_timer_context.timeout_ms = candidate_context_ptr.rto;
    } else if (candidate_context_ptr.retry_timer_context.request_sent_count == Configuration.request_count) {
        candidate_context_ptr.failed_timer.run(
            loop,
            &candidate_context_ptr.failed_timer_completion,
            candidate_context_ptr.rto * Configuration.last_request_factor,
            CandidateGatheringContext,
            candidate_context_ptr,
            failedTimerCallback,
        );
        return .disarm;
    } else {
        candidate_context_ptr.retry_timer_context.timeout_ms = candidate_context_ptr.retry_timer_context.timeout_ms * 2;
    }

    candidate_context_ptr.retry_timer_context.timer.run(
        loop,
        &candidate_context_ptr.retry_timer_context.completion,
        candidate_context_ptr.retry_timer_context.timeout_ms,
        CandidateGatheringContext,
        candidate_context_ptr,
        retryTimerCallback,
    );

    return .disarm;
}

fn mainTimerCallback(userdata: ?*GatheringContext, loop: *xev.Loop, c: *xev.Completion, result: xev.Timer.RunError!void) xev.CallbackAction {
    var context = userdata.?;
    _ = result catch unreachable;

    std.log.debug("Looking for new candidates to check", .{});
    const candidate_index = context.findCandidateToCheck() orelse {
        std.log.debug("No candidate found, disabling timer", .{});
        return .disarm;
    };
    const candidate_context_ptr = &context.candidate_contexts[candidate_index];

    context.main_timer.run(loop, c, 50, GatheringContext, userdata.?, mainTimerCallback);

    const candidate_address = candidate_context_ptr.candidate.base_address;
    std.log.debug("Connecting socket of candidate \"{}\"", .{candidate_address});

    candidate_context_ptr.status = .checking;

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

    const address = switch (candidate_address.any.family) {
        std.os.AF.INET => Configuration.stun_address_ipv4,
        std.os.AF.INET6 => Configuration.stun_address_ipv6,
        else => unreachable,
    };
    candidate_context_ptr.message_data.setFrom(&address, message_size);

    candidate_context_ptr.message_data.completion = xev.Completion{
        .op = .{
            .sendmsg = .{
                .fd = candidate_context_ptr.socket.fd,
                .msghdr = &candidate_context_ptr.message_data.message_header,
                .buffer = null,
            },
        },
        .userdata = candidate_context_ptr,
        .callback = sendMsgCallback,
    };
    loop.add(&candidate_context_ptr.message_data.completion);

    return .disarm;
}

pub fn makeServerReflexiveCandidates(candidates: []Candidate, sockets: []net.Socket, allocator: std.mem.Allocator) ![]Candidate {
    var server_reflexive_candidate_list = try std.ArrayList(Candidate).initCapacity(allocator, candidates.len);
    defer server_reflexive_candidate_list.deinit();

    var gathering_context = try GatheringContext.init(allocator, sockets, candidates, &server_reflexive_candidate_list);
    defer gathering_context.deinit(allocator);

    var event_loop = try xev.Loop.init(.{});
    defer event_loop.deinit();

    var main_timer_completion: xev.Completion = undefined;

    gathering_context.main_timer.run(&event_loop, &main_timer_completion, 50, GatheringContext, &gathering_context, mainTimerCallback);

    while (!gathering_context.done()) {
        try event_loop.run(.once);
    }

    return try server_reflexive_candidate_list.toOwnedSlice();
}

test {
    _ = net;
    _ = platform;
}
