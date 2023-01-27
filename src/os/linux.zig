// Copyright 2023 - Corentin Godeau and the zice contributors
// SPDX-License-Identifier: MIT

const std = @import("std");

pub const c = std.os.linux;

const linux = std.os.linux;

pub const UnexpectedError = error{
    Unexpected,
};

pub const CloseError = error{
    BadFileNumber,
    InterruptedSystemCall,
    IOError,
    NoSpaceLeftOnDevice,
    QuotaExceeded,
} || UnexpectedError;

pub fn close(fd: i32) CloseError!void {
    const result = linux.close(fd);
    const err = linux.getErrno(result);
    return switch (err) {
        linux.E.SUCCESS => {},
        linux.E.BADF => error.BadFileNumber,
        linux.E.INTR => error.InterruptedSystemCall,
        linux.E.IO => error.IOError,
        linux.E.NOSPC => error.NoSpaceLeftOnDevice,
        linux.E.DQUOT => error.QuotaExceeded,
        else => error.Unexpected,
    };
}

pub const SocketError = error{
    PermissionDenied,
    AddressFamilyNotSupported,
    InvalidArgument,
    TooManyOpenFiles,
    FileTableOverflow,
    NoBufferSpaceAvailable,
    ProtocolNotSupported,
} || UnexpectedError;

pub const ProtocolFamily = enum {
    unix,
    local,
    inet,
    inet6,
    ipx,
    netlink,
    x25,
    ax25,
    atmpvc,
    appletalk,
    packet,

    pub inline fn toLinuxDomain(self: ProtocolFamily) u32 {
        return switch (self) {
            .unix => linux.PF.UNIX,
            .local => linux.PF.LOCAL,
            .inet => linux.PF.INET,
            .inet6 => linux.PF.INET6,
            .ipx => linux.PF.IPX,
            .netlink => linux.PF.NETLINK,
            .x25 => linux.PF.X25,
            .ax25 => linux.PF.AX25,
            .atmpvc => linux.PF.ATMPVC,
            .appletalk => linux.PF.APPLETALK,
            .packet => linux.PF.PACKET,
        };
    }
};

pub const SocketType = enum {
    stream,
    datagram,
    seq_packet,
    raw,
    rdm,
    packet,

    pub inline fn toLinuxSocketType(self: SocketType) u32 {
        return switch (self) {
            .stream => linux.SOCK.STREAM,
            .datagram => linux.SOCK.DGRAM,
            .seq_packet => linux.SOCK.SEQPACKET,
            .raw => linux.SOCK.RAW,
            .rdm => linux.SOCK.RDM,
            .packet => linux.SOCK.PACKET,
        };
    }
};

pub fn socket(family: ProtocolFamily, socket_type: SocketType) SocketError!i32 {
    const result = linux.socket(family.toLinuxDomain(), socket_type.toLinuxSocketType(), 0);
    const err = linux.getErrno(result);
    return switch (err) {
        linux.E.SUCCESS => @intCast(i32, result),
        linux.E.ACCES => error.PermissionDenied,
        linux.E.AFNOSUPPORT => error.AddressFamilyNotSupported,
        linux.E.INVAL => error.InvalidArgument,
        linux.E.MFILE => error.TooManyOpenFiles,
        linux.E.NFILE => error.FileTableOverflow,
        linux.E.NOBUFS, linux.E.NOMEM => error.NoBufferSpaceAvailable,
        linux.E.PROTONOSUPPORT => error.ProtocolNotSupported,
        else => error.Unexpected,
    };
}

pub const BindError = error{
    PermissionDenied,
    AddressAlreadyInUse,
    BadFileNumber,
    InvalidArgument,
    NotASocket,
    AddressNotAvailable,
    BadAddress,
    TooManySymbolicLinks,
    FileNameTooLong,
    NoSuchFileOrDirectory,
    OutOfMemory,
    NotADirectory,
    ReadOnlyFileSystem,
} || UnexpectedError;

pub fn bind(socket_: i32, address: *const linux.sockaddr, address_len: u32) BindError!void {
    const result = linux.bind(socket_, address, address_len);
    const err = linux.getErrno(result);
    return switch (err) {
        linux.E.SUCCESS => {},
        linux.E.ACCES => error.PermissionDenied,
        linux.E.ADDRINUSE => error.AddressAlreadyInUse,
        linux.E.BADF => error.BadFileNumber,
        linux.E.INVAL => error.InvalidArgument,
        linux.E.NOTSOCK => error.NotASocket,
        linux.E.ADDRNOTAVAIL => error.AddressNotAvailable,
        linux.E.FAULT => error.BadAddress,
        linux.E.LOOP => error.TooManySymbolicLinks,
        linux.E.NAMETOOLONG => error.FileNameTooLong,
        linux.E.NOENT => error.NoSuchFileOrDirectory,
        linux.E.NOMEM => error.OutOfMemory,
        linux.E.NOTDIR => error.NotADirectory,
        linux.E.ROFS => error.ReadOnlyFileSystem,
        else => error.Unexpected,
    };
}

pub const GetSocketNameError = error{
    BadFileNumber,
    NotASocket,
    OperationNotSupported,
    InvalidArgument,
    NoBufferSpaceAvailable,
} || UnexpectedError;

pub fn getSocketName(socket_: i32, address: *linux.sockaddr.storage, address_size: *u32) GetSocketNameError!void {
    const result = linux.getsockname(socket_, @ptrCast(*linux.sockaddr, address), address_size);
    const err = linux.getErrno(result);

    return switch (err) {
        linux.E.SUCCESS => {},
        linux.E.BADF => error.BadFileNumber,
        linux.E.NOTSOCK => error.NotASocket,
        linux.E.OPNOTSUPP => error.OperationNotSupported,
        linux.E.INVAL => error.InvalidArgument,
        linux.E.NOBUFS => error.NoBufferSpaceAvailable,
        else => error.Unexpected,
    };
}

pub const EpollEventFlags = struct {
    pub const input: u32 = linux.EPOLL.IN;
    pub const output: u32 = linux.EPOLL.OUT;
    pub const read_hangup: u32 = linux.EPOLL.RDHUP;
    pub const pri: u32 = linux.EPOLL.PRI;
    pub const err: u32 = linux.EPOLL.ERR;
    pub const hangup: u32 = linux.EPOLL.HUP;
    pub const edge_triggered: u32 = linux.EPOLL.ET;
    pub const oneshot: u32 = linux.EPOLL.ONESHOT;
    pub const wake_up: u32 = linux.EPOLL.WAKEUP;
    pub const exclusive: u32 = linux.EPOLL.EXCLUSIVE;
};

pub const EpollCreateError = error{
    InvalidArgument,
    TooManyOpenFiles,
    FileTableOverflow,
    OutOfMemory,
} || UnexpectedError;

pub const EpollCreateFlags = struct {
    pub const CLOEXEC: u32 = linux.EPOLL.CLOEXEC;
};

pub fn epollCreate() EpollCreateError!i32 {
    const result = linux.epoll_create();
    const err = linux.getErrno(result);
    return switch (err) {
        linux.E.SUCCESS => @intCast(i32, result),
        linux.E.INVAL => error.InvalidArgument,
        linux.E.MFILE => error.TooManyOpenFiles,
        linux.E.NFILE => error.FileTableOverflow,
        linux.E.NOMEM => error.OutOfMemory,
        else => error.Unexpected,
    };
}

pub fn epollCreate1(flags: u32) EpollCreateError!i32 {
    const result = linux.epoll_create1(flags);
    const err = linux.getErrno(result);
    return switch (err) {
        linux.E.SUCCESS => @intCast(i32, result),
        linux.E.INVAL => error.InvalidArgument,
        linux.E.MFILE => error.TooManyOpenFiles,
        linux.E.NFILE => error.FileTableOverflow,
        linux.E.NOMEM => error.OutOfMemory,
        else => error.Unexpected,
    };
}

pub const EpollControlError = error{
    BadFileNumber,
    FileExists,
    InvalidArgument,
    TooManySymbolicLinks,
    NoSuchFileOrDirectory,
    OutOfMemory,
    NoSpaceLeftOnDevice,
    OperationNotPermitted,
} || UnexpectedError;

pub const EpollControlOp = enum(u32) {
    add = linux.EPOLL.CTL_ADD,
    modify = linux.EPOLL.CTL_MOD,
    delete = linux.EPOLL.CTL_DEL,
};

pub fn epollControl(epoll_fd: i32, op: EpollControlOp, fd: i32, epoll_event: ?*linux.epoll_event) EpollControlError!void {
    const result = linux.epoll_ctl(epoll_fd, @enumToInt(op), fd, epoll_event);
    const err = linux.getErrno(result);
    return switch (err) {
        linux.E.SUCCESS => {},
        linux.E.BADF => error.BadFileNumber,
        linux.E.EXIST => error.FileExists,
        linux.E.INVAL => error.InvalidArgument,
        linux.E.LOOP => error.TooManySymbolicLinks,
        linux.E.NOENT => error.NoSuchFileOrDirectory,
        linux.E.NOMEM => error.OutOfMemory,
        linux.E.NOSPC => error.NoSpaceLeftOnDevice,
        linux.E.PERM => error.OperationNotPermitted,
        else => error.Unexpected,
    };
}

pub const EpollWaitError = error{
    BadFileNumber,
    BadAddress,
    InterruptedSystemCall,
    InvalidArgument,
} || UnexpectedError;

pub fn epollWait(epoll_fd: i32, events: []linux.epoll_event, timeout: ?i32) EpollWaitError![]linux.epoll_event {
    const result = linux.epoll_wait(epoll_fd, events.ptr, @intCast(u32, events.len), timeout orelse -1);
    const err = linux.getErrno(result);
    return switch (err) {
        linux.E.SUCCESS => events[0..result],
        linux.E.BADF => error.BadFileNumber,
        linux.E.FAULT => error.BadAddress,
        linux.E.INTR => error.InterruptedSystemCall,
        linux.E.INVAL => error.InvalidArgument,
        else => error.Unexpected,
    };
}

pub fn epollPWait(epoll_fd: i32, events: []linux.epoll_event, timeout: ?u32, sigmask: ?*const linux.sigset_t) EpollWaitError![]linux.epoll_event {
    const result = linux.epoll_pwait(epoll_fd, events.ptr, events.len, timeout orelse -1, sigmask);
    const err = linux.getErrno(result);
    return switch (err) {
        linux.E.SUCCESS => events[0..result],
        linux.E.BADF => error.BadFileNumber,
        linux.E.FAULT => error.BadAddress,
        linux.E.INTR => error.InterruptedSystemCall,
        linux.E.INVAL => error.InvalidArgument,
        else => error.Unexpected,
    };
}

// TODO(Corentin): Implement
//pub fn epollPWait2(epoll_fd: i32, events: []linux.epoll_event, timeout: ?*const linux.timespec, sigmask: ?*const linux.sigset_t) EpollWaitError![]linux.epoll_event {
//    const result = linux.epoll_pwait2(epoll_fd, events.ptr, events.len, timeout orelse -1, sigmask);
//    const err = linux.getErrno(result);
//    return switch (err) {
//        linux.E.SUCCESS => {},
//        linux.E.BADF => error.BadFileNumber,
//        linux.E.FAULT => error.BadAddress,
//        linux.E.INTR => error.InterruptedSystemCall,
//        linux.E.INVAL => error.InvalidArgument,
//        else => error.Unexpected,
//    };
//}

pub const TimerFdCreateError = error{
    InvalidArgument,
    TooManyOpenFiles,
    FileTableOverflow,
    NoSuchDevice,
    OutOfMemory,
    OperationNotPermitted,
} || UnexpectedError;

pub const TimerFdCreateClock = enum(i32) {
    realtime = linux.CLOCK.REALTIME,
    monotonic = linux.CLOCK.MONOTONIC,
    boot_time = linux.CLOCK.BOOTTIME,
    realtime_alarm = linux.CLOCK.REALTIME_ALARM,
    boot_time_alarm = linux.CLOCK.BOOTTIME_ALARM,
};

pub const TimerFdCreateFlags = struct {
    pub const NONBLOCK: u32 = linux.TFD.NONBLOCK;
    pub const CLOEXEC: u32 = linux.TFD.CLOEXEC;
};

pub fn timerFdCreate(clock: TimerFdCreateClock, flags: u32) TimerFdCreateError!i32 {
    const result = linux.timerfd_create(@enumToInt(clock), flags);
    const err = linux.getErrno(result);
    return switch (err) {
        linux.E.SUCCESS => @intCast(i32, result),
        linux.E.INVAL => error.InvalidArgument,
        linux.E.MFILE => error.TooManyOpenFiles,
        linux.E.NFILE => error.FileTableOverflow,
        linux.E.NODEV => error.NoSuchDevice,
        linux.E.NOMEM => error.OutOfMemory,
        linux.E.PERM => error.OperationNotPermitted,
        else => error.Unexpected,
    };
}

pub const TimerFdSetTimeError = error{
    BadFileNumber,
    BadAddress,
    InvalidArgument,
    OperationCanceled,
} || UnexpectedError;

pub const TimerFdSetTimeFlags = struct {
    pub const ABSTIME: u32 = linux.TFD.TIMER_ABSTIME;
    pub const CANCEL_ON_SET: u32 = linux.TFD.TIMER_CANCEL_ON_SET;
};

pub fn timerFdSetTime(timer_fd: i32, flags: u32, value: linux.itimerspec) TimerFdSetTimeError!linux.itimerspec {
    var old_value: linux.itimerspec = undefined;
    const result = linux.timerfd_settime(timer_fd, flags, &value, &old_value);
    const err = linux.getErrno(result);
    return switch (err) {
        linux.E.SUCCESS => old_value,
        linux.E.BADF => error.BadFileNumber,
        linux.E.FAULT => error.BadAddress,
        linux.E.INVAL => error.InvalidArgument,
        linux.E.CANCELED => error.OperationCanceled,
        else => error.Unexpected,
    };
}

pub const TimerFdGetTimeError = error{
    BadFileNumber,
    BadAddress,
    InvalidArgument,
} || UnexpectedError;

pub fn timerFdGetTime(timer_fd: i32) TimerFdGetTimeError!linux.itimerspec {
    var value: linux.itimerspec = undefined;
    const result = linux.timerfd_gettime(timer_fd, &value);
    const err = linux.getErrno(result);
    return switch (err) {
        linux.E.SUCCESS => value,
        linux.E.BADF => error.BadFileNumber,
        linux.E.FAULT => error.BadAddress,
        linux.E.INVAL => error.InvalidArgument,
        else => error.Unexpected,
    };
}

pub const ReadError = error{
    WouldBlock,
    BadFileNumber,
    BadAddress,
    InterruptedSystemCall,
    InvalidArgument,
    IOError,
    IsADirectory,
} || UnexpectedError;

pub fn read(fd: i32, buffer: []u8) ReadError![]u8 {
    const result = linux.read(fd, buffer.ptr, buffer.len);
    const err = linux.getErrno(result);
    return switch (err) {
        linux.E.SUCCESS => buffer[0..result],
        linux.E.AGAIN => error.WouldBlock,
        linux.E.BADF => error.BadFileNumber,
        linux.E.FAULT => error.BadAddress,
        linux.E.INTR => error.InterruptedSystemCall,
        linux.E.INVAL => error.InvalidArgument,
        linux.E.IO => error.IOError,
        linux.E.ISDIR => error.IsADirectory,
        else => error.Unexpected,
    };
}

pub const WriteError = error{
    WouldBlock,
    BadFileNumber,
    DestinationAddressRequired,
    QuotaExceeded,
    BadAddress,
    FileTooLarge,
    InterruptedSystemCall,
    InvalidArgument,
    IOError,
    NoSpaceLeftOnDevice,
    OperationNotPermitted,
    BrokenPipe,
} || UnexpectedError;

pub fn write(fd: i32, buffer: []const u8) WriteError!usize {
    const result = linux.write(fd, buffer.ptr, buffer.len);
    const err = linux.getErrno(result);
    return switch (err) {
        linux.E.SUCCESS => result,
        linux.E.AGAIN => error.WouldBlock,
        linux.E.BADF => error.BadFileNumber,
        linux.E.DESTADDRREQ => error.DestinationAddressRequired,
        linux.E.DQUOT => error.QuotaExceeded,
        linux.E.FAULT => error.BadAddress,
        linux.E.FBIG => error.FileTooLarge,
        linux.E.INTR => error.InterruptedSystemCall,
        linux.E.INVAL => error.InvalidArgument,
        linux.E.IO => error.IOError,
        linux.E.NOSPC => error.NoSpaceLeftOnDevice,
        linux.E.PERM => error.OperationNotPermitted,
        linux.E.PIPE => error.BrokenPipe,
        else => error.Unexpected,
    };
}

pub const PipeError = error{
    BadAddress,
    InvalidArgument,
    TooManyOpenFiles,
    FileTableOverflow,
} || UnexpectedError;

pub fn pipe() PipeError![2]i32 {
    var pipe_fds: [2]i32 = undefined;
    const result = linux.pipe(&pipe_fds);
    const err = linux.getErrno(result);
    return switch (err) {
        linux.E.SUCCESS => pipe_fds,
        linux.E.FAULT => error.BadAddress,
        linux.E.INVAL => error.InvalidArgument,
        linux.E.MFILE => error.TooManyOpenFiles,
        linux.E.NFILE => error.FileTableOverflow,
        else => error.Unexpected,
    };
}

pub const SendToError = error{
    AddressFamilyNotSupported,
    WouldBlock,
    BadFileNumber,
    ConnectionResetByPeer,
    InterruptedSystemCall,
    MessageTooLong,
    TransportEndpointIsNotConnected,
    NotASocket,
    OperationNotSupported,
    BrokenPipe,
    IOError,
    TooManySymbolicLinks,
    FileNameTooLong,
    NoSuchFileOrDirectory,
    NotADirectory,
    PermissionDenied,
    DesinationAddressRequired,
    NoRouteToHost,
    InvalidArgument,
    AlreadyConnected,
    NetworkIsDone,
    NetworkIsUnreachable,
    NoBufferSpaceAvailable,
    OutOfMemory,
} || UnexpectedError;

pub fn sendto(socket_: i32, message: []const u8, flags: u32, dest_address: *const linux.sockaddr, dest_address_len: u32) SendToError!usize {
    const result = linux.sendto(socket_, message.ptr, message.len, flags, dest_address, dest_address_len);
    const err = linux.getErrno(result);
    return switch (err) {
        linux.E.SUCCESS => result,
        linux.E.AFNOSUPPORT => error.AddressFamilyNotSupported,
        linux.E.AGAIN => error.WouldBlock,
        linux.E.BADF => error.BadFileNumber,
        linux.E.CONNRESET => error.ConnectionResetByPeer,
        linux.E.INTR => error.InterruptedSystemCall,
        linux.E.MSGSIZE => error.MessageTooLong,
        linux.E.NOTCONN => error.TransportEndpointIsNotConnected,
        linux.E.NOTSOCK => error.NotASocket,
        linux.E.OPNOTSUPP => error.OperationNotSupported,
        linux.E.PIPE => error.BrokenPipe,
        linux.E.IO => error.IOError,
        linux.E.LOOP => error.TooManySymbolicLinks,
        linux.E.NAMETOOLONG => error.FileNameTooLong,
        linux.E.NOENT => error.NoSuchFileOrDirectory,
        linux.E.NOTDIR => error.NotADirectory,
        linux.E.ACCES => error.PermissionDenied,
        linux.E.DESTADDRREQ => error.DesinationAddressRequired,
        linux.E.HOSTUNREACH => error.NoRouteToHost,
        linux.E.INVAL => error.InvalidArgument,
        linux.E.ISCONN => error.AlreadyConnected,
        linux.E.NETDOWN => error.NetworkIsDone,
        linux.E.NETUNREACH => error.NetworkIsUnreachable,
        linux.E.NOBUFS => error.NoBufferSpaceAvailable,
        linux.E.NOMEM => error.OutOfMemory,
        else => error.Unexpected,
    };
}
