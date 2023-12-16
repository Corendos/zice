// Copyright 2023 - Corentin Godeau and the zice contributors
// SPDX-License-Identifier: MIT

const std = @import("std");
const zice = @import("main.zig");
const Reader = @import("io.zig").Reader;

pub const MediaAttribute = struct {
    media: []const u8,
    port: []const u8,
    proto: []const u8,
    fmt: []const u8,
};

pub const CandidateAttribute = struct {
    foundation: []const u8,
    component_id: []const u8,
    transport: []const u8,
    priority: []const u8,
    address: []const u8,
    port: []const u8,
    type: []const u8,
    related_address: ?[]const u8,
    related_port: ?[]const u8,
    extensions: []const u8,
};

pub const IceUfragAttribute = struct {
    value: []const u8,
};

pub const IcePwdAttribute = struct {
    value: []const u8,
};

pub const IceOptionsAttribute = struct {
    options: []const u8,
};

pub const AttributeType = enum {
    media,
    candidate,
    ice_ufrag,
    ice_pwd,
    ice_options,
};

pub const Attribute = union(AttributeType) {
    media: MediaAttribute,
    candidate: CandidateAttribute,
    ice_ufrag: IceUfragAttribute,
    ice_pwd: IcePwdAttribute,
    ice_options: IceOptionsAttribute,
};

pub const Parser = struct {
    line_reader: Reader,

    pub fn init(sdp: []const u8) Parser {
        return Parser{ .line_reader = Reader.init(sdp) };
    }

    fn readLine(self: *Parser) ?[]const u8 {
        if (self.line_reader.done()) return null;
        const line = self.line_reader.readUntilAnyOrEof("\r\n");
        self.line_reader.skipAny("\r\n");

        return line;
    }

    pub fn next(self: *Parser) ?Attribute {
        while (self.readLine()) |line| {
            var line_reader = Reader.init(line);
            if (line_reader.done()) continue;

            switch (line_reader.peek().?) {
                'm' => {
                    return .{ .media = tryParseMediaAttribute(line_reader) orelse continue };
                },
                'a' => {
                    return tryParseAttribute(line_reader) orelse continue;
                },
                else => {},
            }
        }

        return null;
    }

    fn tryParseMediaAttribute(reader: Reader) ?MediaAttribute {
        var local_reader = reader;
        if (!local_reader.expect("m=")) return null;

        const media = local_reader.readUntil(' ') orelse return null;
        local_reader.skip(' ');

        const port = local_reader.readUntil(' ') orelse return null;
        local_reader.skip(' ');

        const proto = local_reader.readUntil(' ') orelse return null;
        local_reader.skip(' ');

        const fmt = local_reader.readRemaining();

        return MediaAttribute{
            .media = media,
            .port = port,
            .proto = proto,
            .fmt = fmt,
        };
    }

    fn tryParseIceOptions(reader: Reader) ?IceOptionsAttribute {
        var local_reader = reader;
        const result = local_reader.readRemaining();
        return if (result.len != 0) IceOptionsAttribute{ .options = result } else null;
    }

    fn tryParseIceUfrag(reader: Reader) ?IceUfragAttribute {
        var local_reader = reader;
        const result = local_reader.readRemaining();
        return if (result.len != 0) IceUfragAttribute{ .value = result } else null;
    }

    fn tryParseIcePwd(reader: Reader) ?IcePwdAttribute {
        var local_reader = reader;
        const result = local_reader.readRemaining();
        return if (result.len != 0) IcePwdAttribute{ .value = result } else null;
    }

    fn tryReadRelatedAddress(reader: *Reader) ?[]const u8 {
        var local_reader = reader.*;

        if (!local_reader.expect("raddr")) return null;
        local_reader.skip(' ');

        const address = local_reader.readUntilOrEof(' ');
        local_reader.skip(' ');

        reader.* = local_reader;
        return address;
    }

    fn tryReadRelatedPort(reader: *Reader) ?[]const u8 {
        var local_reader = reader.*;

        if (!local_reader.expect("rport")) return null;
        local_reader.skip(' ');

        const port = local_reader.readUntilOrEof(' ');
        local_reader.skip(' ');

        reader.* = local_reader;
        return port;
    }

    fn tryParseCandidate(reader: Reader) ?CandidateAttribute {
        var local_reader = reader;

        const foundation = local_reader.readUntil(' ') orelse return null;
        local_reader.skip(' ');

        const component_id = local_reader.readUntil(' ') orelse return null;
        local_reader.skip(' ');

        const transport = local_reader.readUntil(' ') orelse return null;
        local_reader.skip(' ');

        const priority = local_reader.readUntil(' ') orelse return null;
        local_reader.skip(' ');

        const address = a: {
            const address = local_reader.readUntil(' ') orelse return null;
            local_reader.skip(' ');
            break :a std.mem.trim(u8, address, "[]");
        };

        const port = local_reader.readUntil(' ') orelse return null;
        local_reader.skip(' ');

        if (!local_reader.expect("typ")) return null;
        local_reader.skip(' ');
        const candidate_type = local_reader.readUntilOrEof(' ');
        local_reader.skip(' ');

        const related_address = tryReadRelatedAddress(&local_reader);

        const related_port = tryReadRelatedPort(&local_reader);

        const extensions = local_reader.readRemaining();

        return CandidateAttribute{
            .foundation = foundation,
            .component_id = component_id,
            .transport = transport,
            .priority = priority,
            .address = address,
            .port = port,
            .type = candidate_type,
            .related_address = related_address,
            .related_port = related_port,
            .extensions = extensions,
        };
    }

    fn tryParseAttribute(reader: Reader) ?Attribute {
        var local_reader = reader;
        if (!local_reader.expect("a=")) return null;

        const attribute_name = local_reader.readUntilOrEof(':');
        local_reader.skip(':');

        if (std.mem.eql(u8, attribute_name, "ice-options")) {
            const ice_options = tryParseIceOptions(local_reader) orelse return null;
            return Attribute{ .ice_options = ice_options };
        } else if (std.mem.eql(u8, attribute_name, "ice-ufrag")) {
            const ice_ufrag = tryParseIceUfrag(local_reader) orelse return null;
            return Attribute{ .ice_ufrag = ice_ufrag };
        } else if (std.mem.eql(u8, attribute_name, "ice-pwd")) {
            const ice_pwd = tryParseIcePwd(local_reader) orelse return null;
            return Attribute{ .ice_pwd = ice_pwd };
        } else if (std.mem.eql(u8, attribute_name, "candidate")) {
            const candidate = tryParseCandidate(local_reader) orelse return null;
            return Attribute{ .candidate = candidate };
        } else return null;
    }
};

pub fn makeSdp(pwd: []const u8, username: []const u8, candidates: []const zice.Candidate, is_controlling: bool, allocator: std.mem.Allocator) ![]const u8 {
    var buffer = std.ArrayList(u8).init(allocator);
    defer buffer.deinit();

    var writer = buffer.writer();

    const sdp_template_1 =
        \\v=0
        \\o=jdoe 2890844526 2890842807 IN IP4 0.0.0.0
        \\s=-
        \\t=0 0
        \\a=sendrecv
        \\a=fingerprint:sha-256 49:66:12:17:0D:1C:91:AE:57:4C:C6:36:DD:D5:97:D2:7D:62:C9:9A:7F:B9:A3:F4:70:03:E7:43:91:73:23:5E
        \\a=group:BUNDLE 0
        \\a=ice-options:ice2
        \\a=msid-semantic:WMS *
        \\m=application 9 UDP/DTLS/SCTP webrtc-datachannel
        \\c=IN IP4 0.0.0.0
    ;
    try writer.writeAll(sdp_template_1);

    for (candidates) |*c| {
        try writer.print("\na=candidate:{} {} UDP {} {a} {p} typ {s}", .{
            c.foundation.asNumber(),
            c.component_id,
            c.priority,
            zice.fmt.addressFormatter(c.transport_address),
            zice.fmt.addressFormatter(c.transport_address),
            c.type.toString(),
        });
        if (c.type == .server_reflexive) {
            try writer.print(" raddr {a} rport {p}", .{
                zice.fmt.addressFormatter(c.base_address),
                zice.fmt.addressFormatter(c.base_address),
            });
        }
    }

    const sdp_template_2 =
        \\
        \\a=sendrecv
        \\a=ice-pwd:{s}
        \\a=ice-ufrag:{s}
        \\a=mid:0{s}
        \\a=sctp-port:5000
        \\a=max-message-size:1073741823
    ;

    try writer.print(sdp_template_2, .{ pwd, username, if (is_controlling) "\na=setup:actpass" else "" });

    return buffer.toOwnedSlice();
}

test "smoke test" {
    const sdp =
        \\v=0
        \\o=jdoe 2890844526 2890842807 IN IP4 0.0.0.0
        \\s=-
        \\t=0 0
        \\a=sendrecv
        \\a=fingerprint:sha-256 49:66:12:17:0D:1C:91:AE:57:4C:C6:36:DD:D5:97:D2:7D:62:C9:9A:7F:B9:A3:F4:70:03:E7:43:91:73:23:5E
        \\a=group:BUNDLE 0
        \\a=ice-options:ice2
        \\a=msid-semantic:WMS *
        \\m=application 9 UDP/DTLS/SCTP webrtc-datachannel
        \\c=IN IP4 0.0.0.0
        \\a=candidate:1 1 UDP 2130706431 203.0.113.141 8998 typ host
        \\a=candidate:2 1 UDP 1694498815 192.0.2.3 45664 typ srflx raddr 203.0.113.141 rport 8998
        \\a=sendrecv
        \\a=ice-pwd:asd88fgpdd777uzjYhagZg
        \\a=ice-ufrag:8hhY
        \\a=mid:0
        \\a=sctp-port:5000
        \\a=max-message-size:1073741823
    ;
    var parser = Parser.init(sdp);

    const options = parser.next();
    try std.testing.expect(options != null);
    try std.testing.expectEqual(AttributeType.ice_options, options.?);
    try std.testing.expectEqualStrings("ice2", options.?.ice_options.options);

    const pwd = parser.next();
    try std.testing.expect(pwd != null);
    try std.testing.expectEqual(AttributeType.ice_pwd, pwd.?);
    try std.testing.expectEqualStrings("asd88fgpdd777uzjYhagZg", pwd.?.ice_pwd.value);

    const ufrag = parser.next();
    try std.testing.expect(ufrag != null);
    try std.testing.expectEqual(AttributeType.ice_ufrag, ufrag.?);
    try std.testing.expectEqualStrings("8hhY", ufrag.?.ice_ufrag.value);

    const media = parser.next();
    try std.testing.expect(media != null);
    try std.testing.expectEqual(AttributeType.media, media.?);

    const candidate1 = parser.next();
    try std.testing.expect(candidate1 != null);
    try std.testing.expectEqual(AttributeType.candidate, candidate1.?);

    const candidate2 = parser.next();
    try std.testing.expect(candidate2 != null);
    try std.testing.expectEqual(AttributeType.candidate, candidate2.?);
}
