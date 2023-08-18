// Copyright 2023 - Corentin Godeau and the zice contributors
// SPDX-License-Identifier: MIT

const std = @import("std");
const xev = @import("xev");

const zice = @import("main.zig");
const netlink = @import("zice/linux.zig").netlink;

const NetlinkContextState = enum(u2) {
    initial_interfaces,
    initial_addresses,
    idle,
};

pub const NetlinkContext = struct {
    pub const EventType = enum {
        add,
        delete,
    };

    pub const InterfaceEvent = union(EventType) {
        add: struct { index: u32, name: []const u8, type: netlink.ARPHRD },
        delete: u32,
    };

    read_completion: xev.Completion = .{},
    read_cancel_completion: xev.Completion = .{},
    write_completion: xev.Completion = .{},
    write_cancel_completion: xev.Completion = .{},

    socket: std.os.fd_t,

    flags: packed struct {
        state: NetlinkContextState = .initial_interfaces,
        multipart: bool = false,
        stopped: bool = false,
    } = .{},

    write_buffer: []u8,
    read_buffer: []u8,

    userdata: ?*anyopaque = null,
    on_interface_callback: ?*const fn (userdata: ?*anyopaque, event: InterfaceEvent) void = null,
    on_address_callback: ?*const fn (userdata: ?*anyopaque, event_type: EventType, interface_index: u32, address: std.net.Address) void = null,
    on_idle_callback: ?*const fn (userdata: ?*anyopaque) void = null,

    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) !NetlinkContext {
        var write_buffer = try allocator.alloc(u8, 8192);
        errdefer allocator.free(write_buffer);
        var read_buffer = try allocator.alloc(u8, 8192);
        errdefer allocator.free(read_buffer);

        const socket = try std.os.socket(std.os.linux.AF.NETLINK, std.os.linux.SOCK.RAW, std.os.linux.NETLINK.ROUTE);
        errdefer std.os.close(socket);

        const address = std.os.linux.sockaddr.nl{
            .pid = 0,
            .groups = netlink.RTMGRP.LINK | netlink.RTMGRP.IPV4_IFADDR,
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

    pub fn stop(self: *NetlinkContext, loop: *xev.Loop) void {
        if (self.flags.stopped) return;
        self.write_cancel_completion = xev.Completion{
            .op = .{ .cancel = .{ .c = &self.write_completion } },
            .userdata = self,
            .callback = writeCancelCallback,
        };
        loop.add(&self.write_cancel_completion);

        self.read_cancel_completion = xev.Completion{
            .op = .{ .cancel = .{ .c = &self.read_completion } },
            .userdata = self,
            .callback = readCancelCallback,
        };
        loop.add(&self.read_cancel_completion);
        self.flags.stopped = true;
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
            .len = netlink.nlmsg_length(@sizeOf(@TypeOf(request_payload))),
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
        self.flags.multipart = false;
    }

    fn requestAddresses(self: *NetlinkContext, loop: *xev.Loop) void {
        std.log.debug("Requesting initial Addresses", .{});
        const request_payload = netlink.ifaddrmsg{
            .family = std.os.linux.AF.UNSPEC,
            .prefixlen = 0,
            .flags = 0,
            .scope = 0,
            .index = 0,
        };

        const request_header = std.os.linux.nlmsghdr{
            .len = netlink.nlmsg_length(@sizeOf(@TypeOf(request_payload))),
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
        self.flags.multipart = false;
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

    fn writeCancelCallback(
        userdata: ?*anyopaque,
        loop: *xev.Loop,
        completion: *xev.Completion,
        result: xev.Result,
    ) xev.CallbackAction {
        _ = result;
        _ = loop;
        _ = completion;
        var self = @as(*NetlinkContext, @ptrCast(@alignCast(userdata.?)));
        _ = self;

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
                    switch (self.flags.state) {
                        .initial_interfaces => {
                            self.flags.state = .initial_addresses;
                            self.requestAddresses(loop);
                        },
                        .initial_addresses => {
                            self.flags.state = .idle;
                            if (self.on_idle_callback) |callback| {
                                callback(self.userdata);
                            }
                        },
                        else => {},
                    }
                }
            } else |err| self.readError(err, loop);
        } else |err| self.readError(err, loop);

        return if (self.flags.stopped) .disarm else .rearm;
    }

    fn readCancelCallback(
        userdata: ?*anyopaque,
        loop: *xev.Loop,
        completion: *xev.Completion,
        result: xev.Result,
    ) xev.CallbackAction {
        _ = result;
        _ = loop;
        _ = completion;
        var self = @as(*NetlinkContext, @ptrCast(@alignCast(userdata.?)));
        _ = self;

        return .disarm;
    }

    fn writeError(self: *NetlinkContext, err: anyerror, loop: *xev.Loop) void {
        if (err == error.Canceled and self.flags.stopped) return;
        std.log.err("Got {} while writing in {s} state, retrying...", .{ err, @tagName(self.flags.state) });

        switch (self.flags.state) {
            .initial_interfaces => self.requestInterfaces(loop),
            .initial_addresses => self.requestAddresses(loop),
            else => unreachable,
        }
    }

    fn readError(self: *NetlinkContext, err: anyerror, loop: *xev.Loop) void {
        if (err == error.Canceled and self.flags.stopped) return;
        std.log.err("Got {} while reading in {s} state, retrying...", .{ err, @tagName(self.flags.state) });

        switch (self.flags.state) {
            .initial_interfaces => self.requestInterfaces(loop),
            .initial_addresses => self.requestAddresses(loop),
            else => {},
        }
    }

    fn handleNetlinkMessage(self: *NetlinkContext, data: []const u8) !bool {
        var it = netlink.MessageIterator.init(@alignCast(data));
        var done = false;
        while (it.next()) |message| {
            self.flags.multipart = self.flags.multipart or (message.flags & std.os.linux.NLM_F_MULTI > 0);
            if (message.type == .ERROR) {
                const error_message = @as(*const netlink.nlmsgerr, @ptrCast(@alignCast(message.data.ptr)));
                std.log.err("{}", .{error_message.@"error"});
                return error.Unexpected;
            } else if (message.type == .RTM_NEWLINK or message.type == .RTM_DELLINK) {
                const interface_message = @as(*const std.os.linux.ifinfomsg, @ptrCast(@alignCast(message.data)));
                const raw_attributes = @as([]align(@alignOf(std.os.linux.rtattr)) const u8, @alignCast(message.data[@sizeOf(std.os.linux.ifinfomsg)..]));
                self.handleNetlinkInterfaceMessage(interface_message.*, raw_attributes, message.type == .RTM_NEWLINK);
            } else if (message.type == std.os.linux.NetlinkMessageType.RTM_NEWADDR or message.type == std.os.linux.NetlinkMessageType.RTM_DELADDR) {
                const address_message = @as(*const netlink.ifaddrmsg, @ptrCast(@alignCast(message.data)));
                const raw_attributes = @as([]align(@alignOf(std.os.linux.rtattr)) const u8, @alignCast(message.data[@sizeOf(netlink.ifaddrmsg)..]));
                self.handleNetlinkAddressMessage(address_message.*, raw_attributes, message.type == .RTM_NEWADDR);
            } else if (message.type == .DONE) {
                done = true;
            }
        }

        return if (self.flags.multipart) done else true;
    }

    fn handleNetlinkAddressMessage(self: *NetlinkContext, message: netlink.ifaddrmsg, raw_attributes: []align(@alignOf(std.os.linux.rtattr)) const u8, is_new_message: bool) void {
        const interface_index: u32 = @as(u32, @intCast(message.index));

        var attribute_it = netlink.AttributeIterator.init(raw_attributes);
        const address_opt: ?std.net.Address = while (attribute_it.next()) |raw_attribute| {
            const attribute = netlink.IfaAttribute.from(raw_attribute);
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
                        .scope_id = interface_index,
                    }))),
                    else => null,
                };
            }
        } else null;
        if (address_opt) |address| {
            if (self.on_address_callback) |callback| {
                const event_type: EventType = if (is_new_message) .add else .delete;
                callback(self.userdata, event_type, interface_index, address);
            }
        }
    }

    fn handleNetlinkInterfaceMessage(self: *NetlinkContext, message: std.os.linux.ifinfomsg, raw_attributes: []align(@alignOf(std.os.linux.rtattr)) const u8, is_new_message: bool) void {
        const index: u32 = @as(u32, @intCast(message.index));
        if (!is_new_message) {
            if (self.on_interface_callback) |callback| {
                callback(self.userdata, .{ .delete = index });
            }
            return;
        }

        var attribute_it = netlink.AttributeIterator.init(raw_attributes);
        const name_opt: ?[]const u8 = while (attribute_it.next()) |raw_attribute| {
            const attribute = netlink.IflaAttribute.from(raw_attribute);
            if (attribute == .IFNAME) {
                break attribute.IFNAME;
            }
        } else null;

        if (name_opt) |name| {
            if (self.on_interface_callback) |callback| {
                callback(self.userdata, .{ .add = .{ .index = index, .name = name, .type = @enumFromInt(message.type) } });
            }
        }
    }
};
