// Copyright 2023 - Corentin Godeau and the zice contributors
// SPDX-License-Identifier: MIT

const std = @import("std");
const builtin = @import("builtin");
const ztun = @import("ztun");
const xev = @import("xev");

pub const Intrusive = @import("queue.zig").Intrusive;
pub const Worker = @import("zice/Worker.zig");

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

pub const MessageData = struct {
    completion: xev.Completion = .{},
    buffer: []u8 = &.{},
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

pub const ReadData = struct {
    completion: xev.Completion = .{},
    cancel_completion: xev.Completion = .{},
    buffer: []u8 = &.{},
};

pub const CandidateGatheringError = error{OutOfMemory};

pub const CandidateGatheringResult = struct {
    candidates: []Candidate,
};

pub const CandidateContext = struct {
    socket: std.os.fd_t,
    address: std.net.Address,
    status: GatheringStatus = .new,

    message_data: MessageData = undefined,
    read_data: ReadData = undefined,

    retry_timer: xev.Timer,
    retry_timer_completion: xev.Completion = .{},
    retry_timer_timeout_ms: u64 = 0,

    failed_timer: xev.Timer,
    failed_timer_completion: xev.Completion = .{},

    request_sent_count: u64 = 0,
    rto: u64,

    parent_context: ?*CandidateGatheringContext = null,

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

    pub fn deinit(self: *CandidateContext, allocator: std.mem.Allocator) void {
        allocator.free(self.message_data.buffer);
        allocator.free(self.read_data.buffer);
        self.failed_timer.deinit();
        self.retry_timer.deinit();
    }
};

pub const CandidateGatheringContext = struct {
    allocator: std.mem.Allocator,
    userdata: ?*anyopaque,
    callback: *const fn (userdata: ?*anyopaque, result: CandidateGatheringError!CandidateGatheringResult) void,

    main_timer: xev.Timer,
    main_timer_completion: xev.Completion = .{},

    completion: Worker.Completion = .{},

    candidate_contexts: []CandidateContext = &.{},
    result_candidates: std.ArrayListUnmanaged(Candidate) = .{},

    pub fn init(
        sockets: []const std.os.fd_t,
        addresses: []const std.net.Address,
        allocator: std.mem.Allocator,
        userdata: ?*anyopaque,
        callback: *const fn (userdata: ?*anyopaque, result: CandidateGatheringError!CandidateGatheringResult) void,
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

    pub fn cleanup(self: *CandidateGatheringContext) void {
        for (self.candidate_contexts) |*ctx| ctx.deinit(self.allocator);
        self.allocator.free(self.candidate_contexts);
        self.main_timer.deinit();
        self.result_candidates.deinit(self.allocator);
    }

    fn getUncheckedCandidate(self: *const CandidateGatheringContext) ?usize {
        for (self.candidate_contexts, 0..) |ctx, i| {
            if (ctx.status == .new) {
                return i;
            }
        }
        return null;
    }

    inline fn isDone(self: *const CandidateGatheringContext) bool {
        for (self.candidate_contexts) |ctx| {
            if (ctx.status == .new or ctx.status == .checking) return false;
        }
        return true;
    }
};

//const GatheringContext = struct {
//    const Self = GatheringContext;
//
//    candidate_contexts: []CandidateGatheringContext,
//    candidate_list: *std.ArrayList(Candidate),
//
//    main_timer: xev.Timer,
//
//    pub fn init(allocator: std.mem.Allocator, sockets: []net.Socket, candidates: []const Candidate, candidate_list: *std.ArrayList(Candidate)) !Self {
//        const count = candidates.len;
//
//        var candidate_gathering_contexts = try allocator.alloc(CandidateGatheringContext, count);
//        errdefer allocator.free(candidate_gathering_contexts);
//
//        const initial_timeout = Configuration.computeRtoMs(candidates.len);
//        for (candidate_gathering_contexts, 0..) |*ctx, i| {
//            ctx.* = try CandidateGatheringContext.init(candidates[i], sockets[i], initial_timeout, candidate_list, allocator);
//        }
//        errdefer for (candidate_gathering_contexts) |*ctx| {
//            ctx.deinit(allocator);
//        };
//
//        const main_timer = try xev.Timer.init();
//        errdefer main_timer.deinit();
//
//        return Self{
//            .candidate_contexts = candidate_gathering_contexts,
//            .candidate_list = candidate_list,
//            .main_timer = main_timer,
//        };
//    }
//
//    pub fn deinit(self: GatheringContext, allocator: std.mem.Allocator) void {
//        self.main_timer.deinit();
//
//        for (self.candidate_contexts) |*ctx| ctx.deinit(allocator);
//        allocator.free(self.candidate_contexts);
//    }
//
//    pub fn findCandidateToCheck(self: Self) ?usize {
//        for (self.candidate_contexts, 0..) |ctx, i| {
//            if (ctx.status == .new) {
//                return i;
//            }
//        }
//        return null;
//    }
//
//    pub inline fn done(self: Self) bool {
//        for (self.candidate_contexts) |ctx| {
//            if (ctx.status == .new or ctx.status == .checking) return false;
//        }
//        return true;
//    }
//};

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

fn failedTimerCallback(userdata: ?*CandidateContext, loop: *xev.Loop, c: *xev.Completion, result: xev.Timer.RunError!void) xev.CallbackAction {
    const candidate_context_ptr = userdata.?;
    if (candidate_context_ptr.status == .done) return .disarm;
    std.debug.assert(candidate_context_ptr.status == .checking);
    _ = result catch unreachable;
    _ = c;

    std.log.debug("Gathering timed out for candidate \"{}\"", .{candidate_context_ptr.address});

    candidate_context_ptr.status = .failed;

    candidate_context_ptr.read_data.cancel_completion = xev.Completion{
        .op = .{
            .cancel = .{ .c = &candidate_context_ptr.read_data.completion },
        },
    };
    loop.add(&candidate_context_ptr.read_data.cancel_completion);

    const candidate_gathering_context = candidate_context_ptr.parent_context.?;
    if (candidate_gathering_context.isDone()) {
        var candidates = candidate_gathering_context.result_candidates.toOwnedSlice(candidate_gathering_context.allocator) catch |e| {
            candidate_gathering_context.cleanup();
            candidate_gathering_context.callback(candidate_gathering_context.userdata, e);
            return .disarm;
        };

        candidate_gathering_context.callback(candidate_gathering_context.userdata, .{ .candidates = candidates });
    }

    return .disarm;
}

fn retryTimerCallback(userdata: ?*CandidateContext, loop: *xev.Loop, c: *xev.Completion, result: xev.Timer.RunError!void) xev.CallbackAction {
    _ = result catch unreachable;
    _ = c;
    const candidate_context_ptr = userdata.?;
    if (candidate_context_ptr.status == .done or candidate_context_ptr.status == .failed) return .disarm;

    std.debug.assert(candidate_context_ptr.status == .checking);

    std.log.debug("STUN request {}/{} from candidate \"{}\" timed out", .{ candidate_context_ptr.request_sent_count, Configuration.request_count, candidate_context_ptr.address });

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
    candidate_context_ptr.message_data.setFrom(&address, message_size);

    candidate_context_ptr.message_data.completion = xev.Completion{
        .op = .{
            .sendmsg = .{
                .fd = candidate_context_ptr.socket,
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
    const candidate_context_ptr = @ptrCast(*CandidateContext, @alignCast(8, userdata.?));

    const bytes_read = result.read catch |err| {
        std.log.err("Got {} with candidate \"{}\" while reading from socket", .{ err, candidate_context_ptr.address });
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
    std.log.debug("Gathering done for candidate \"{}\"", .{candidate_context_ptr.address});

    const candidate_gathering_context = candidate_context_ptr.parent_context.?;
    if (getServerReflexiveAddressFromStunMessage(message)) |transport_address| {
        candidate_gathering_context.result_candidates.append(candidate_gathering_context.allocator, Candidate{
            .type = .server_reflexive,
            .transport_address = transport_address,
            .base_address = candidate_context_ptr.address,
        }) catch unreachable;
    }

    if (candidate_gathering_context.isDone()) {
        var candidates = candidate_gathering_context.result_candidates.toOwnedSlice(candidate_gathering_context.allocator) catch |e| {
            candidate_gathering_context.cleanup();
            candidate_gathering_context.callback(candidate_gathering_context.userdata, e);
            return .disarm;
        };

        candidate_gathering_context.callback(candidate_gathering_context.userdata, .{ .candidates = candidates });
    }

    return .disarm;
}

fn sendMsgCallback(userdata: ?*anyopaque, loop: *xev.Loop, c: *xev.Completion, result: xev.Result) xev.CallbackAction {
    const candidate_context_ptr = @ptrCast(*CandidateContext, @alignCast(8, userdata.?));

    _ = result.sendmsg catch |err| {
        std.log.err("Got {} with candidate \"{}\" while writing to socket", .{ err, candidate_context_ptr.address });
        candidate_context_ptr.status = .failed;
        return .disarm;
    };
    _ = c;

    candidate_context_ptr.request_sent_count += 1;
    std.log.debug("STUN request sent for candidate \"{}\"", .{candidate_context_ptr.address});

    if (candidate_context_ptr.request_sent_count == 1) {
        candidate_context_ptr.read_data.completion = xev.Completion{
            .op = .{ .read = .{
                .fd = candidate_context_ptr.socket,
                .buffer = xev.ReadBuffer{
                    .slice = candidate_context_ptr.read_data.buffer,
                },
            } },
            .userdata = candidate_context_ptr,
            .callback = readCallback,
        };
        loop.add(&candidate_context_ptr.read_data.completion);
        candidate_context_ptr.retry_timer_timeout_ms = candidate_context_ptr.rto;
    } else if (candidate_context_ptr.request_sent_count == Configuration.request_count) {
        candidate_context_ptr.failed_timer.run(
            loop,
            &candidate_context_ptr.failed_timer_completion,
            candidate_context_ptr.rto * Configuration.last_request_factor,
            CandidateContext,
            candidate_context_ptr,
            failedTimerCallback,
        );
        return .disarm;
    } else {
        candidate_context_ptr.retry_timer_timeout_ms = candidate_context_ptr.retry_timer_timeout_ms * 2;
    }

    candidate_context_ptr.retry_timer.run(
        loop,
        &candidate_context_ptr.retry_timer_completion,
        candidate_context_ptr.retry_timer_timeout_ms,
        CandidateContext,
        candidate_context_ptr,
        retryTimerCallback,
    );

    return .disarm;
}

fn mainTimerCallback(userdata: ?*CandidateGatheringContext, loop: *xev.Loop, c: *xev.Completion, result: xev.Timer.RunError!void) xev.CallbackAction {
    var context = userdata.?;
    _ = result catch unreachable;

    std.debug.assert(context.candidate_contexts.len != 0);

    const candidate_index = context.getUncheckedCandidate() orelse {
        return .disarm;
    };
    const candidate_context_ptr = &context.candidate_contexts[candidate_index];

    context.main_timer.run(loop, c, Configuration.new_transaction_interval_ms, CandidateGatheringContext, context, mainTimerCallback);

    const candidate_address = candidate_context_ptr.address;
    std.log.debug("Sending message from candidate \"{}\"", .{candidate_address});

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
                .fd = candidate_context_ptr.socket,
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

pub fn makeCandidates(context: *CandidateGatheringContext, worker: *Worker) void {
    for (context.candidate_contexts) |ctx| {
        context.result_candidates.append(context.allocator, Candidate{
            .type = .host,
            .base_address = ctx.address,
            .transport_address = ctx.address,
        }) catch |e| {
            context.cleanup();
            context.callback(context.userdata, e);
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
    _ = net;
    _ = platform;
    _ = Worker;
}
