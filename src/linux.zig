// Copyright 2023 - Corentin Godeau and the zice contributors
// SPDX-License-Identifier: MIT

const std = @import("std");
const net = @import("net.zig");
const nl = @import("linux/netlink.zig");
const zice = @import("main.zig");
const ztun = @import("ztun");

const os = @import("os.zig");

/// Gather IP address for all interfaces.
pub fn getAddressesFromInterfaces(allocator: std.mem.Allocator) ![]net.Address {
    var temp_arena_state = std.heap.ArenaAllocator.init(allocator);
    defer temp_arena_state.deinit();

    var temp_arena = temp_arena_state.allocator();

    const socket = try nl.createSocket();
    defer nl.closeSocket(socket);

    try nl.bindSocket(socket, 0, 0);

    var netlink_cache = nl.Cache.init(temp_arena);

    try netlink_cache.update(socket);
    var address_list = std.ArrayList(net.Address).init(allocator);
    defer address_list.deinit();

    for (netlink_cache.links) |link| {
        if (link.type == nl.ARPHRD.LOOPBACK) continue;
        const addresses = try netlink_cache.getAddressesByInterfaceIndexAlloc(link.interface_index, temp_arena);

        for (addresses) |address| {
            try address_list.append(address);
        }
    }

    return address_list.toOwnedSlice();
}

pub fn bind(socket: i32, address: net.Address, port: ?u16) os.linux.BindError!void {
    return switch (address) {
        .ipv4 => |ipv4_address| r: {
            var linux_address = os.linux.c.sockaddr.in{
                .port = port orelse 0,
                .addr = @bitCast(u32, ipv4_address.value),
            };
            break :r os.linux.bind(socket, @ptrCast(*const os.linux.c.sockaddr, &linux_address), @sizeOf(os.linux.c.sockaddr.in));
        },
        .ipv6 => |ipv6_address| r: {
            var linux_address = os.linux.c.sockaddr.in6{
                .port = port orelse 0,
                .flowinfo = 0,
                .addr = undefined,
                .scope_id = ipv6_address.scope_id,
            };
            std.mem.copyBackwards(u8, &linux_address.addr, &ipv6_address.value);
            break :r os.linux.bind(socket, @ptrCast(*const os.linux.c.sockaddr, &linux_address), @sizeOf(os.linux.c.sockaddr.in6));
        },
    };
}

//pub fn bindAndGetPort(address: net.Address) error{BindError}!struct { socket: i32, port: u16 } {
//    const protocol_family = switch (address) {
//        .ipv4 => os.linux.ProtocolFamily.inet,
//        .ipv6 => os.linux.ProtocolFamily.inet6,
//    };
//    const socket = os.linux.socket(protocol_family, os.linux.SocketType.datagram) catch return error.BindError;
//    errdefer os.linux.close(socket) catch {};
//
//    bind(socket, address, null) catch return error.BindError;
//
//    var address_storage: os.linux.c.sockaddr.storage = undefined;
//    var address_size: u32 = @sizeOf(os.linux.c.sockaddr.storage);
//
//    os.linux.getSocketName(socket, &address_storage, &address_size) catch return error.BindError;
//    const port = switch (address_storage.family) {
//        os.linux.c.AF.INET => @ptrCast(*os.linux.c.sockaddr.in, &address_storage).port,
//        os.linux.c.AF.INET6 => @ptrCast(*os.linux.c.sockaddr.in6, &address_storage).port,
//        else => return error.BindError,
//    };
//
//    return .{ .socket = socket, .port = port };
//}

pub fn getSocketPort(socket: i32) !u16 {
    var address_storage: os.linux.c.sockaddr.storage = undefined;
    var address_size: u32 = @sizeOf(os.linux.c.sockaddr.storage);

    os.linux.getSocketName(socket, &address_storage, &address_size) catch return error.BindError;
    return switch (address_storage.family) {
        os.linux.c.AF.INET => @ptrCast(*os.linux.c.sockaddr.in, &address_storage).port,
        os.linux.c.AF.INET6 => @ptrCast(*os.linux.c.sockaddr.in6, &address_storage).port,
        else => error.UnsupportedFamily,
    };
}

pub fn makeHostCandidates(addresses: []net.Address, socket_fds: []i32, allocator: std.mem.Allocator) ![]zice.Candidate {
    var candidate_list = try std.ArrayList(zice.Candidate).initCapacity(allocator, addresses.len);
    defer candidate_list.deinit();

    for (addresses) |address, i| {
        const port = try getSocketPort(socket_fds[i]);
        try candidate_list.append(zice.Candidate{
            .type = .host,
            .transport_address = .{ .address = address, .port = port },
            .base_address = .{ .address = address, .port = port },
        });
    }

    return try candidate_list.toOwnedSlice();
}

pub const GatheringStatus = enum {
    new,
    checking,
    failed,
    done,
};

const RetryTimerContext = struct {
    timeout_ms: u64 = 0,
    request_sent_count: usize = 0,
};

const GatheringDataType = enum(u32) {
    socket,
    retry_timer,
    failed_timer,
    main_timer,
};

const GatheringEpollData = extern union {
    raw: u64,
    payload: extern struct {
        type: GatheringDataType,
        candidate_index: u32 = 0,
    },
};

const GatheringContext = struct {
    const Self = GatheringContext;

    candidate_status: []GatheringStatus,
    candidate_epoll_data: []GatheringEpollData,

    retry_timer_context: []RetryTimerContext,
    retry_timer_fds: []i32,
    retry_timer_epoll_data: []GatheringEpollData,

    failed_timer_fds: []i32,
    failed_timer_epoll_data: []GatheringEpollData,

    main_timer_fd: i32,
    main_timer_epoll_data: GatheringEpollData = .{ .payload = .{ .type = .main_timer } },

    read_buffer: []u8,

    pub fn initCount(allocator: std.mem.Allocator, count: usize) !Self {
        var candidate_status = try allocator.alloc(GatheringStatus, count);
        errdefer allocator.free(candidate_status);
        std.mem.set(GatheringStatus, candidate_status, .new);

        var candidate_epoll_data = try allocator.alloc(GatheringEpollData, count);
        errdefer allocator.free(candidate_epoll_data);
        for (candidate_epoll_data) |*data, i| {
            data.payload.type = .socket;
            data.payload.candidate_index = @intCast(u32, i);
        }

        var retry_timer_context = try allocator.alloc(RetryTimerContext, count);
        errdefer allocator.free(retry_timer_context);
        std.mem.set(RetryTimerContext, retry_timer_context, .{});

        var retry_timer_fds = try allocator.alloc(i32, count);
        errdefer allocator.free(retry_timer_fds);
        std.mem.set(i32, retry_timer_fds, 0);

        var retry_timer_epoll_data = try allocator.alloc(GatheringEpollData, count);
        errdefer allocator.free(retry_timer_epoll_data);
        for (retry_timer_epoll_data) |*data, i| {
            data.payload.type = .retry_timer;
            data.payload.candidate_index = @intCast(u32, i);
        }

        var failed_timer_fds = try allocator.alloc(i32, count);
        errdefer allocator.free(failed_timer_fds);
        std.mem.set(i32, failed_timer_fds, 0);

        var failed_timer_epoll_data = try allocator.alloc(GatheringEpollData, count);
        errdefer allocator.free(failed_timer_epoll_data);
        for (failed_timer_epoll_data) |*data, i| {
            data.payload.type = .failed_timer;
            data.payload.candidate_index = @intCast(u32, i);
        }

        const main_timer_fd = try os.linux.timerFdCreate(.monotonic, 0);
        errdefer os.linux.close(main_timer_fd) catch {};

        var read_buffer = try allocator.alloc(u8, 4096);
        errdefer allocator.free(read_buffer);

        return Self{
            .candidate_status = candidate_status,
            .candidate_epoll_data = candidate_epoll_data,
            .retry_timer_context = retry_timer_context,
            .retry_timer_fds = retry_timer_fds,
            .retry_timer_epoll_data = retry_timer_epoll_data,
            .failed_timer_fds = failed_timer_fds,
            .failed_timer_epoll_data = failed_timer_epoll_data,
            .main_timer_fd = main_timer_fd,
            .read_buffer = read_buffer,
        };
    }

    pub fn deinit(self: GatheringContext, allocator: std.mem.Allocator) void {
        allocator.free(self.read_buffer);

        os.linux.close(self.main_timer_fd) catch {};

        allocator.free(self.failed_timer_epoll_data);
        allocator.free(self.failed_timer_fds);

        allocator.free(self.retry_timer_epoll_data);
        allocator.free(self.retry_timer_fds);
        allocator.free(self.retry_timer_context);

        allocator.free(self.candidate_epoll_data);
        allocator.free(self.candidate_status);
    }

    pub fn findCandidateToCheck(self: Self) ?usize {
        for (self.candidate_status) |status, i| {
            if (status == .new) {
                return i;
            }
        }
        return null;
    }

    pub inline fn done(self: Self) bool {
        for (self.candidate_status) |status| {
            if (status == .new or status == .checking) return false;
        }
        return true;
    }
};

//const stun_address = std.net.Address.parseIp4("91.134.140.104", 3478) catch unreachable;
const stun_address = std.net.Address.parseIp4("172.253.120.127", 19302) catch unreachable;
const stun_address_ipv6 = std.net.Address.parseIp6("2a00:1450:400c:c00::7f", 19302) catch unreachable;

pub fn makeRequest(allocator: std.mem.Allocator) !ztun.Message {
    var message_builder = ztun.MessageBuilder.init(allocator);
    defer message_builder.deinit();

    // Binding request with random transaction ID.
    message_builder.setClass(ztun.Class.request);
    message_builder.setMethod(ztun.Method.binding);
    message_builder.randomTransactionId();

    // Authentication attributes.
    const username_attribute = ztun.attr.common.Username{ .value = "anon" };
    const attribute = try username_attribute.toAttribute(allocator);
    errdefer allocator.free(attribute.data);
    try message_builder.addAttribute(attribute);

    const authentication = ztun.auth.Authentication{ .short_term = ztun.auth.ShortTermAuthentication{ .password = "password" } };

    message_builder.addMessageIntegrity(authentication);
    message_builder.addMessageIntegritySha256(authentication);

    // Add a fingerprint for validity check.
    message_builder.addFingerprint();
    return try message_builder.build();
}

pub fn sendStunRequest(socket: i32, family: net.AddressFamily, allocator: std.mem.Allocator) !void {
    var buffer = try allocator.alloc(u8, 4096);
    defer allocator.free(buffer);

    const request_message = try makeRequest(allocator);
    defer request_message.deinit(allocator);

    const raw_request_message = blk: {
        var stream = std.io.fixedBufferStream(buffer);
        try request_message.write(stream.writer());
        break :blk stream.getWritten();
    };

    const bytes_sent = switch (family) {
        .ipv4 => try os.linux.sendto(socket, raw_request_message, 0, &stun_address.any, stun_address.getOsSockLen()),
        .ipv6 => try os.linux.sendto(socket, raw_request_message, 0, &stun_address_ipv6.any, stun_address_ipv6.getOsSockLen()),
    };

    std.debug.assert(bytes_sent == raw_request_message.len);
}

fn durationNsTotimeSpec(duration_ns: u64) os.linux.c.timespec {
    return os.linux.c.timespec{
        .tv_sec = @intCast(isize, duration_ns / std.time.ns_per_s),
        .tv_nsec = @intCast(isize, duration_ns % std.time.ns_per_s),
    };
}

pub fn stunAddressFamilyToAddress(address_family: ztun.attr.common.AddressFamily) net.Address {
    return switch (address_family) {
        .ipv4 => |value| blk: {
            const endian_corrected_value = std.mem.nativeToBig(u32, value);
            var bytes = std.mem.asBytes(&endian_corrected_value);
            break :blk .{ .ipv4 = .{ .value = bytes[0..4].* } };
        },
        .ipv6 => |value| blk: {
            const endian_corrected_value = std.mem.nativeToBig(u128, value);
            var bytes = std.mem.asBytes(&endian_corrected_value);

            break :blk .{ .ipv6 = .{ .value = bytes[0..16].* } };
        },
    };
}

pub fn getServerReflexiveAddressFromStunMessage(message: ztun.Message) ?zice.TransportAddress {
    for (message.attributes) |attribute| {
        if (attribute.type == ztun.attr.Type.mapped_address) {
            const mapped_address_attribute = ztun.attr.common.MappedAddress.fromAttribute(attribute) catch return null;
            return .{ .address = stunAddressFamilyToAddress(mapped_address_attribute.family), .port = mapped_address_attribute.port };
        } else if (attribute.type == ztun.attr.Type.xor_mapped_address) {
            const xor_mapped_address_attribute = ztun.attr.common.XorMappedAddress.fromAttribute(attribute) catch return null;
            const mapped_address_attribute = ztun.attr.common.decode(xor_mapped_address_attribute, message.transaction_id);
            return .{ .address = stunAddressFamilyToAddress(mapped_address_attribute.family), .port = mapped_address_attribute.port };
        }
    }

    return null;
}

fn handleMainTimer(context: *GatheringContext, candidates: []zice.Candidate, socket_fds: []i32, epoll_fd: i32, allocator: std.mem.Allocator) !void {
    // Discard timer value
    _ = try os.linux.read(context.main_timer_fd, context.read_buffer);

    std.log.debug("Looking for new candidates to check", .{});
    const candidate_index = context.findCandidateToCheck() orelse {
        std.log.debug("No candidate found, disabling timer", .{});
        try os.linux.epollControl(epoll_fd, os.linux.EpollControlOp.delete, context.main_timer_fd, null);
        return;
    };

    const candidate_address = candidates[candidate_index].base_address;
    std.log.debug("Sending STUN request from candidate \"{}\"", .{candidate_address});

    context.candidate_status[candidate_index] = .checking;

    const retry_timer_context = &context.retry_timer_context[candidate_index];

    const retry_timer_fd = try os.linux.timerFdCreate(.monotonic, 0);
    context.retry_timer_fds[candidate_index] = retry_timer_fd;

    const initial_timeout = zice.Configuration.computeRtoMs(candidates.len);
    retry_timer_context.timeout_ms = initial_timeout;

    const rto_timer_spec = os.linux.c.itimerspec{
        .it_interval = durationNsTotimeSpec(0),
        .it_value = durationNsTotimeSpec(initial_timeout * std.time.ns_per_ms),
    };
    _ = try os.linux.timerFdSetTime(retry_timer_fd, 0, rto_timer_spec);

    var event = os.linux.c.epoll_event{
        .events = os.linux.c.EPOLL.IN,
        .data = .{ .u64 = context.retry_timer_epoll_data[candidate_index].raw },
    };
    try os.linux.epollControl(epoll_fd, os.linux.EpollControlOp.add, retry_timer_fd, &event);

    sendStunRequest(socket_fds[candidate_index], candidate_address.address, allocator) catch {
        std.log.debug("Gathering failed for candidate \"{}\"", .{candidate_address});
        context.candidate_status[candidate_index] = .failed;
        try os.linux.epollControl(epoll_fd, os.linux.EpollControlOp.delete, retry_timer_fd, null);
    };
    retry_timer_context.request_sent_count += 1;
}

fn handleRetryTimer(context: *GatheringContext, index: u32, candidates: []zice.Candidate, socket_fds: []i32, epoll_fd: i32, allocator: std.mem.Allocator) !void {
    const candidate_address = candidates[index].base_address;
    std.debug.assert(context.candidate_status[index] == .checking);

    const retry_timer_context = &context.retry_timer_context[index];
    const retry_timer_fd = context.retry_timer_fds[index];
    std.log.debug("STUN request {}/{} from candidate \"{}\" timed out", .{ retry_timer_context.request_sent_count, zice.Configuration.request_count, candidate_address });

    // Discard timer value
    _ = try os.linux.read(retry_timer_fd, context.read_buffer);

    retry_timer_context.request_sent_count += 1;
    sendStunRequest(socket_fds[index], candidate_address.address, allocator) catch {
        std.log.debug("Gathering failed for candidate \"{}\"", .{candidate_address});
        context.candidate_status[index] = .failed;
        try os.linux.epollControl(epoll_fd, os.linux.EpollControlOp.delete, retry_timer_fd, null);
        return;
    };

    if (retry_timer_context.request_sent_count == zice.Configuration.request_count) {
        try os.linux.epollControl(epoll_fd, os.linux.EpollControlOp.delete, retry_timer_fd, null);

        const failed_timer_fd = try os.linux.timerFdCreate(.monotonic, 0);
        context.failed_timer_fds[index] = failed_timer_fd;

        const failed_timer_spec = os.linux.c.itimerspec{
            .it_interval = durationNsTotimeSpec(0),
            .it_value = durationNsTotimeSpec(zice.Configuration.last_request_factor * zice.Configuration.computeRtoMs(candidates.len) * std.time.ns_per_ms),
        };
        _ = try os.linux.timerFdSetTime(failed_timer_fd, 0, failed_timer_spec);

        var event = os.linux.c.epoll_event{
            .events = os.linux.c.EPOLL.IN,
            .data = .{ .u64 = context.failed_timer_epoll_data[index].raw },
        };
        try os.linux.epollControl(epoll_fd, os.linux.EpollControlOp.add, failed_timer_fd, &event);
    } else {
        retry_timer_context.timeout_ms = retry_timer_context.timeout_ms * 2;

        const rto_timer_spec = os.linux.c.itimerspec{
            .it_interval = durationNsTotimeSpec(0),
            .it_value = durationNsTotimeSpec(retry_timer_context.timeout_ms * std.time.ns_per_ms),
        };
        _ = try os.linux.timerFdSetTime(retry_timer_fd, 0, rto_timer_spec);
    }
}

fn handleSocket(context: *GatheringContext, index: u32, candidates: []zice.Candidate, socket_fds: []i32, epoll_fd: i32, allocator: std.mem.Allocator) !?zice.Candidate {
    std.debug.assert(context.candidate_status[index] == .checking);

    const data_read = try os.linux.read(socket_fds[index], context.read_buffer);
    const message: ztun.Message = blk: {
        var stream = std.io.fixedBufferStream(data_read);
        break :blk try ztun.Message.readAlloc(stream.reader(), allocator);
    };
    defer message.deinit(allocator);

    context.candidate_status[index] = .done;
    std.log.debug("Gathering done for candidate \"{}\"", .{candidates[index].base_address});

    try os.linux.epollControl(epoll_fd, os.linux.EpollControlOp.delete, context.retry_timer_fds[index], null);

    const transport_address = getServerReflexiveAddressFromStunMessage(message) orelse return null;

    return zice.Candidate{
        .type = .server_reflexive,
        .transport_address = transport_address,
        .base_address = candidates[index].base_address,
    };
}

fn handleFailedTimer(context: *GatheringContext, index: u32, candidates: []zice.Candidate, epoll_fd: i32) !void {
    const candidate_address = candidates[index].base_address;
    std.debug.assert(context.candidate_status[index] == .checking);
    std.log.debug("Gathering timed out for candidate \"{}\"", .{candidate_address});

    // Discard timer value
    _ = try os.linux.read(context.failed_timer_fds[index], context.read_buffer);
    try os.linux.epollControl(epoll_fd, os.linux.EpollControlOp.delete, context.failed_timer_fds[index], null);
    context.candidate_status[index] = .failed;
}

pub fn makeServerReflexiveCandidates(candidates: []zice.Candidate, socket_fds: []i32, allocator: std.mem.Allocator) ![]zice.Candidate {
    var server_reflexive_candidate_list = try std.ArrayList(zice.Candidate).initCapacity(allocator, candidates.len);
    defer server_reflexive_candidate_list.deinit();

    var gathering_context = try GatheringContext.initCount(allocator, candidates.len);
    defer gathering_context.deinit(allocator);
    defer for (gathering_context.retry_timer_fds) |fd| {
        if (fd != 0) {
            os.linux.close(fd) catch {};
        }
    };

    const epoll_fd = try os.linux.epollCreate();
    defer os.linux.close(epoll_fd) catch {};

    for (candidates) |_, i| {
        var event = os.linux.c.epoll_event{ .events = os.linux.c.EPOLL.IN, .data = .{ .u64 = gathering_context.candidate_epoll_data[i].raw } };
        try os.linux.epollControl(epoll_fd, os.linux.EpollControlOp.add, socket_fds[i], &event);
    }

    const main_timer_spec = os.linux.c.itimerspec{
        .it_interval = durationNsTotimeSpec(50 * std.time.ns_per_ms),
        .it_value = durationNsTotimeSpec(1),
    };
    _ = try os.linux.timerFdSetTime(gathering_context.main_timer_fd, 0, main_timer_spec);

    var main_timer_event = os.linux.c.epoll_event{
        .events = os.linux.c.EPOLL.IN,
        .data = .{ .u64 = gathering_context.main_timer_epoll_data.raw },
    };
    try os.linux.epollControl(epoll_fd, os.linux.EpollControlOp.add, gathering_context.main_timer_fd, &main_timer_event);

    var read_buffer = try allocator.alloc(u8, 4096);
    defer allocator.free(read_buffer);

    var epoll_events_storage: [16]os.linux.c.epoll_event = undefined;

    const rto_base_ms = zice.Configuration.computeRtoMs(candidates.len);
    _ = rto_base_ms;

    while (!gathering_context.done()) {
        const epoll_events = try os.linux.epollWait(epoll_fd, &epoll_events_storage, null);

        for (epoll_events) |epoll_event| {
            const gathering_epoll_data = GatheringEpollData{ .raw = epoll_event.data.u64 };
            switch (gathering_epoll_data.payload.type) {
                .main_timer => try handleMainTimer(&gathering_context, candidates, socket_fds, epoll_fd, allocator),
                .socket => {
                    const candidate = try handleSocket(&gathering_context, gathering_epoll_data.payload.candidate_index, candidates, socket_fds, epoll_fd, allocator) orelse continue;
                    try server_reflexive_candidate_list.append(candidate);
                },
                .retry_timer => try handleRetryTimer(&gathering_context, gathering_epoll_data.payload.candidate_index, candidates, socket_fds, epoll_fd, allocator),
                .failed_timer => try handleFailedTimer(&gathering_context, gathering_epoll_data.payload.candidate_index, candidates, epoll_fd),
            }
        }
    }

    return try server_reflexive_candidate_list.toOwnedSlice();
}
