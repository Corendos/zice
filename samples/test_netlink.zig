// Copyright 2023 - Corentin Godeau and the zice contributors
// SPDX-License-Identifier: MIT

const std = @import("std");

const xev = @import("xev");
const zice = @import("zice");

const Context = struct {
    socket: std.os.fd_t,
    write_c: xev.Completion = undefined,
    read_c: xev.Completion = undefined,

    read_buffer: []u8,
};

pub fn writeCallback(
    userdata: ?*anyopaque,
    loop: *xev.Loop,
    completion: *xev.Completion,
    result: xev.Result,
) xev.CallbackAction {
    var context = @ptrCast(*Context, @alignCast(@alignOf(Context), userdata.?));
    _ = result;
    _ = completion;

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

    return .disarm;
}

pub fn readCallback(
    userdata: ?*anyopaque,
    loop: *xev.Loop,
    completion: *xev.Completion,
    result: xev.Result,
) xev.CallbackAction {
    var context = @ptrCast(*Context, @alignCast(@alignOf(Context), userdata.?));
    _ = completion;
    _ = loop;
    const bytes_read = result.read catch unreachable;
    std.log.debug("{any}", .{context.read_buffer[0..bytes_read]});
    return .disarm;
}

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

pub fn main() !void {
    var event_loop = try xev.Loop.init(.{});
    defer event_loop.deinit();

    var stop_handler = try StopHandler.init();
    defer stop_handler.deinit();

    stop_handler.register(&event_loop);

    const nl_socket = try std.os.socket(std.os.linux.AF.NETLINK, std.os.linux.SOCK.RAW, std.os.linux.NETLINK.ROUTE);
    defer std.os.close(nl_socket);

    const address = std.os.linux.sockaddr.nl{
        .pid = 0,
        .groups = 1,
    };
    try std.os.bind(nl_socket, @ptrCast(*const std.os.sockaddr, &address), @sizeOf(std.os.linux.sockaddr.nl));

    var buffer: [4096]u8 align(4) = undefined;
    var completion = xev.Completion{
        .op = .{
            .read = .{
                .fd = nl_socket,
                .buffer = .{ .slice = &buffer },
            },
        },
        .callback = (struct {
            fn callback(
                _: ?*anyopaque,
                _: *xev.Loop,
                c: *xev.Completion,
                result: xev.Result,
            ) xev.CallbackAction {
                const bytes_read = result.read catch return .rearm;
                const data = @alignCast(4, c.op.read.buffer.slice[0..bytes_read]);
                var it = zice.netlink.MessageIterator.init(data);
                while (it.next()) |message| {
                    if (message.type == .RTM_NEWLINK or message.type == .RTM_DELLINK) {
                        const link_message = zice.netlink.LinkMessage.from(message.data);
                        std.log.debug("Received: {any}", .{link_message});

                        var attribute_it = zice.netlink.AttributeIterator.init(link_message.raw_attributes);
                        while (attribute_it.next()) |attribute| {
                            std.log.debug("    Attribute: {any}", .{attribute});
                        }
                    }
                }
                return .rearm;
            }
        }).callback,
        .userdata = null,
    };
    event_loop.add(&completion);

    //var arena_state = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    //defer arena_state.deinit();

    //var arena = arena_state.allocator();

    //const socket = try std.os.socket(std.os.linux.AF.NETLINK, std.os.SOCK.RAW, std.os.linux.NETLINK.ROUTE);
    //defer std.os.close(socket);

    //const address = std.os.linux.sockaddr.nl{ .pid = 0, .groups = 0 };

    //try std.os.bind(socket, @ptrCast(*const std.os.linux.sockaddr, &address), @sizeOf(std.os.linux.sockaddr.nl));

    //var context = Context{
    //    .socket = socket,
    //    .read_buffer = try arena.alloc(u8, 4096),
    //};

    //const request_header = std.os.linux.nlmsghdr{
    //    .len = zice.nl.nlmsg_length(@sizeOf(std.os.linux.ifinfomsg)),
    //    .type = std.os.linux.NetlinkMessageType.RTM_GETLINK,
    //    .flags = std.os.linux.NLM_F_DUMP | std.os.linux.NLM_F_REQUEST,
    //    .seq = 1,
    //    .pid = 0,
    //};

    //const request_payload = std.os.linux.ifinfomsg{
    //    .family = std.os.linux.AF.UNSPEC,
    //    .type = 0,
    //    .index = 0,
    //    .flags = 0,
    //    .change = 0xFFFFFFFF,
    //};

    //const request_buffer = blk: {
    //    var buffer = try arena.alloc(u8, zice.nl.nlmsg_space(@sizeOf(std.os.linux.ifinfomsg)));

    //    var stream = std.io.fixedBufferStream(buffer);
    //    var writer = stream.writer();
    //    try writer.writeStruct(request_header);
    //    try writer.writeStruct(request_payload);

    //    break :blk buffer;
    //};

    //context.write_c = xev.Completion{
    //    .op = .{
    //        .write = .{
    //            .fd = socket,
    //            .buffer = .{ .slice = request_buffer },
    //        },
    //    },
    //    .userdata = &context,
    //    .callback = writeCallback,
    //};
    //event_loop.add(&context.write_c);

    try event_loop.run(.until_done);
}