// Copyright 2023 - Corentin Godeau and the zice contributors
// SPDX-License-Identifier: MIT

const std = @import("std");

const xev = @import("xev");
const zice = @import("zice");

const StopHandler = struct {
    storage: [@sizeOf(std.os.linux.signalfd_siginfo)]u8,
    fd: std.os.fd_t,
    mask: std.os.sigset_t,
    completion: xev.Completion = .{},

    pub fn init() !StopHandler {
        var self: StopHandler = undefined;
        self.mask = m: {
            var mask = std.os.empty_sigset;
            std.os.linux.sigaddset(&mask, std.os.SIG.INT);
            break :m mask;
        };
        self.fd = try std.os.signalfd(-1, &self.mask, 0);
        errdefer std.os.close(self);

        return self;
    }

    pub fn deinit(self: StopHandler) void {
        std.os.close(self.fd);
    }

    pub fn register(self: *StopHandler, loop: *xev.Loop) void {
        self.completion = xev.Completion{
            .op = .{
                .read = .{
                    .fd = self.fd,
                    .buffer = .{ .slice = &self.storage },
                },
            },
            .callback = (struct {
                fn callback(
                    _: ?*anyopaque,
                    l: *xev.Loop,
                    _: *xev.Completion,
                    _: xev.Result,
                ) xev.CallbackAction {
                    std.log.info("Received SIGINT", .{});
                    l.stop();
                    return .disarm;
                }
            }).callback,
            .userdata = null,
        };
        loop.add(&self.completion);
        std.os.sigprocmask(std.os.SIG.BLOCK, &self.mask, null);
    }
};

const Context = struct {
    socket: std.os.fd_t,
    write_c: xev.Completion = undefined,
    read_c: xev.Completion = undefined,
    zice_context: *zice.Context,

    read_buffer: []u8,
    arena: std.mem.Allocator,
};

pub fn writeInterfaceCallback(
    userdata: ?*anyopaque,
    loop: *xev.Loop,
    completion: *xev.Completion,
    result: xev.Result,
) xev.CallbackAction {
    var context = @ptrCast(*Context, @alignCast(@alignOf(Context), userdata.?));
    _ = result.write catch unreachable;
    _ = completion;

    context.read_c = xev.Completion{
        .op = .{
            .read = .{
                .fd = context.socket,
                .buffer = .{ .slice = context.read_buffer },
            },
        },
        .userdata = context,
        .callback = readInterfaceCallback,
    };
    loop.add(&context.read_c);

    return .disarm;
}

pub fn writeAddressCallback(
    userdata: ?*anyopaque,
    loop: *xev.Loop,
    completion: *xev.Completion,
    result: xev.Result,
) xev.CallbackAction {
    var context = @ptrCast(*Context, @alignCast(@alignOf(Context), userdata.?));
    _ = result.write catch unreachable;
    _ = completion;

    context.read_c = xev.Completion{
        .op = .{
            .read = .{
                .fd = context.socket,
                .buffer = .{ .slice = context.read_buffer },
            },
        },
        .userdata = context,
        .callback = readAddressCallback,
    };
    loop.add(&context.read_c);

    return .disarm;
}

pub fn readInterfaceCallback(
    userdata: ?*anyopaque,
    loop: *xev.Loop,
    completion: *xev.Completion,
    result: xev.Result,
) xev.CallbackAction {
    var context = @ptrCast(*Context, @alignCast(@alignOf(Context), userdata.?));
    const bytes_read = result.read catch return .rearm;

    const done = handleNetlinkMessage(context, completion.op.read.buffer.slice[0..bytes_read]);

    if (done) {
        var network_interface_iterator = context.zice_context.network_interface_map.iterator();
        std.log.debug("Current entries:", .{});
        while (network_interface_iterator.next()) |network_interface| {
            std.log.debug("Index {}: {s}", .{ network_interface.value_ptr.index, network_interface.value_ptr.name });
        }

        context.write_c = xev.Completion{
            .op = .{
                .write = .{
                    .fd = context.socket,
                    .buffer = .{ .slice = makeAddressRequest(context.arena) catch unreachable },
                },
            },
            .userdata = context,
            .callback = writeAddressCallback,
        };
        loop.add(&context.write_c);
    }

    return if (done) .disarm else .rearm;
}

pub fn readAddressCallback(
    userdata: ?*anyopaque,
    loop: *xev.Loop,
    completion: *xev.Completion,
    result: xev.Result,
) xev.CallbackAction {
    var context = @ptrCast(*Context, @alignCast(@alignOf(Context), userdata.?));
    const bytes_read = result.read catch return .rearm;

    const done = handleNetlinkMessage(context, completion.op.read.buffer.slice[0..bytes_read]);

    if (done) {
        std.log.debug("Current entries:", .{});
        for (context.zice_context.interface_addresses.items) |address| {
            std.log.debug("Index {}: {}", .{ address.interface_index, address.address });
        }
        context.read_c = xev.Completion{
            .op = .{
                .read = .{
                    .fd = context.socket,
                    .buffer = .{ .slice = context.read_buffer },
                },
            },
            .userdata = context,
            .callback = readCallback,
        };
        loop.add(&context.read_c);
    }

    return if (done) .disarm else .rearm;
}

pub fn readCallback(
    userdata: ?*anyopaque,
    loop: *xev.Loop,
    completion: *xev.Completion,
    result: xev.Result,
) xev.CallbackAction {
    var context = @ptrCast(*Context, @alignCast(@alignOf(Context), userdata.?));
    _ = loop;
    const bytes_read = result.read catch return .rearm;

    const done = handleNetlinkMessage(context, completion.op.read.buffer.slice[0..bytes_read]);
    if (done) {
        for (context.zice_context.interface_addresses.items) |address| {
            std.log.debug("Address {}: {}", .{ address.interface_index, address.address });
        }
        var network_interface_iterator = context.zice_context.network_interface_map.iterator();
        while (network_interface_iterator.next()) |network_interface| {
            std.log.debug("Interface {}: {s}", .{ network_interface.value_ptr.index, network_interface.value_ptr.name });
        }
    }

    return .rearm;
}

fn handleNetlinkMessage(context: *Context, data: []const u8) bool {
    var multipart: bool = false;
    var done: bool = true;

    var it = zice.netlink.MessageIterator.init(@alignCast(4, data));
    while (it.next()) |message| {
        if (!multipart and message.flags & std.os.linux.NLM_F_MULTI > 0) {
            multipart = true;
            done = false;
        }

        if (multipart and message.type == .DONE) {
            done = true;
        }
        std.log.debug("Received {} message", .{message.type});
        if (message.type == .ERROR) {
            const error_message = @ptrCast(*const zice.netlink.nlmsgerr, @alignCast(@alignOf(zice.netlink.nlmsgerr), message.data.ptr));

            std.log.debug("Error: {}", .{error_message.@"error"});
        } else if (message.type == .RTM_NEWLINK or message.type == .RTM_DELLINK) {
            const is_newlink_message = message.type == .RTM_NEWLINK;

            const interface_info_msg = @ptrCast(*const std.os.linux.ifinfomsg, @alignCast(@alignOf(std.os.linux.ifinfomsg), message.data.ptr));

            const index: u32 = @intCast(u32, interface_info_msg.index);

            const raw_attributes = @alignCast(@alignOf(std.os.linux.rtattr), message.data[@sizeOf(std.os.linux.ifinfomsg)..]);

            var attribute_it = zice.netlink.AttributeIterator.init(raw_attributes);
            const name_opt: ?[]const u8 = while (attribute_it.next()) |raw_attribute| {
                const attribute = zice.netlink.IflaAttribute.from(raw_attribute);
                if (attribute == .IFNAME) {
                    break attribute.IFNAME;
                }
            } else null;

            if (name_opt) |name| {
                if (is_newlink_message) {
                    context.zice_context.addNetworkInterface(index, name) catch {};
                } else {
                    context.zice_context.deleteNetworkInterface(index);
                }
            }
        } else if (message.type == std.os.linux.NetlinkMessageType.RTM_NEWADDR or message.type == std.os.linux.NetlinkMessageType.RTM_DELADDR) {
            const is_newaddr_message = message.type == .RTM_NEWADDR;

            const interface_address_msg = @ptrCast(*const zice.netlink.ifaddrmsg, @alignCast(@alignOf(zice.netlink.ifaddrmsg), message.data.ptr));

            const index: u32 = @intCast(u32, interface_address_msg.index);

            const raw_attributes = @alignCast(@alignOf(std.os.linux.rtattr), message.data[@sizeOf(zice.netlink.ifaddrmsg)..]);

            var attribute_it = zice.netlink.AttributeIterator.init(raw_attributes);
            const address_opt: ?std.net.Address = while (attribute_it.next()) |raw_attribute| {
                const attribute = zice.netlink.IfaAttribute.from(raw_attribute);
                if (attribute == .ADDRESS) {
                    break switch (interface_address_msg.family) {
                        std.os.linux.AF.INET => std.net.Address.initPosix(@ptrCast(*const std.os.linux.sockaddr, &std.os.linux.sockaddr.in{
                            .port = 0,
                            .addr = std.mem.bytesToValue(u32, attribute.ADDRESS[0..4]),
                        })),
                        std.os.linux.AF.INET6 => std.net.Address.initPosix(@ptrCast(*const std.os.linux.sockaddr, &std.os.linux.sockaddr.in6{
                            .port = 0,
                            .flowinfo = 0,
                            .addr = std.mem.bytesToValue([16]u8, attribute.ADDRESS[0..16]),
                            .scope_id = index,
                        })),
                        else => null,
                    };
                }
            } else null;
            if (address_opt) |address| {
                if (is_newaddr_message) {
                    context.zice_context.addInterfaceAddress(index, address) catch unreachable;
                } else {
                    context.zice_context.deleteInterfaceAddress(index, address);
                }
            }
        }
    }

    return done;
}

fn makeInterfaceRequest(allocator: std.mem.Allocator) ![]const u8 {
    const request_payload = std.os.linux.ifinfomsg{
        .family = std.os.linux.AF.UNSPEC,
        .type = 0,
        .index = 0,
        .flags = 0,
        .change = 0xFFFFFFFF,
    };

    const request_header = std.os.linux.nlmsghdr{
        .len = zice.netlink.nlmsg_length(@sizeOf(@TypeOf(request_payload))),
        .type = std.os.linux.NetlinkMessageType.RTM_GETLINK,
        .flags = std.os.linux.NLM_F_DUMP | std.os.linux.NLM_F_REQUEST,
        .seq = 1,
        .pid = 0,
    };

    var buffer = try allocator.alloc(u8, zice.netlink.nlmsg_space(@sizeOf(@TypeOf(request_payload))));

    var stream = std.io.fixedBufferStream(buffer);
    var writer = stream.writer();
    try writer.writeStruct(request_header);
    try writer.writeStruct(request_payload);

    return buffer;
}

fn makeAddressRequest(allocator: std.mem.Allocator) ![]const u8 {
    const request_payload = zice.netlink.ifaddrmsg{
        .family = std.os.linux.AF.UNSPEC,
        .prefixlen = 0,
        .flags = 0,
        .scope = 0,
        .index = 0,
    };

    const request_header = std.os.linux.nlmsghdr{
        .len = zice.netlink.nlmsg_length(@sizeOf(@TypeOf(request_payload))),
        .type = std.os.linux.NetlinkMessageType.RTM_GETADDR,
        .flags = std.os.linux.NLM_F_DUMP | std.os.linux.NLM_F_REQUEST,
        .seq = 1,
        .pid = 0,
    };

    var buffer = try allocator.alloc(u8, zice.netlink.nlmsg_space(@sizeOf(@TypeOf(request_payload))));

    var stream = std.io.fixedBufferStream(buffer);
    var writer = stream.writer();
    try writer.writeStruct(request_header);
    try writer.writeStruct(request_payload);

    return buffer;
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();

    var event_loop = try xev.Loop.init(.{});
    defer event_loop.deinit();

    var stop_handler = try StopHandler.init();
    defer stop_handler.deinit();

    stop_handler.register(&event_loop);

    const nl_socket = try std.os.socket(std.os.linux.AF.NETLINK, std.os.linux.SOCK.RAW, std.os.linux.NETLINK.ROUTE);
    defer std.os.close(nl_socket);

    const address = std.os.linux.sockaddr.nl{
        .pid = 0,
        .groups = zice.netlink.RTMGRP.LINK | zice.netlink.RTMGRP.IPV4_IFADDR,
    };
    try std.os.bind(nl_socket, @ptrCast(*const std.os.sockaddr, &address), @sizeOf(std.os.linux.sockaddr.nl));

    var arena_state = std.heap.ArenaAllocator.init(gpa.allocator());
    defer arena_state.deinit();

    var arena = arena_state.allocator();

    var zice_context = try zice.Context.init(gpa.allocator());
    defer zice_context.deinit();

    var context = Context{
        .socket = nl_socket,
        .zice_context = &zice_context,
        .read_buffer = try arena.alloc(u8, 2048),
        .arena = arena,
    };

    // Request about interfaces
    context.write_c = xev.Completion{
        .op = .{
            .write = .{
                .fd = nl_socket,
                .buffer = .{ .slice = try makeInterfaceRequest(arena) },
            },
        },
        .userdata = &context,
        .callback = writeInterfaceCallback,
    };
    event_loop.add(&context.write_c);

    try event_loop.run(.until_done);
}
