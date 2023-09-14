// Copyright 2023 - Corentin Godeau and the zice contributors
// SPDX-License-Identifier: MIT

const std = @import("std");

pub const tm = extern struct {
    tm_sec: c_int, // Seconds. [0-60] 1 leap second
    tm_min: c_int, // Minutes. [0-59]
    tm_hour: c_int, // Hours.   [0-23]
    tm_mday: c_int, // Day.     [1-31]
    tm_mon: c_int, // Month.   [0-11]
    tm_year: c_int, // Year - 1900.
    tm_wday: c_int, // Day of week. [0-6]
    tm_yday: c_int, // Days in year.[0-365]
    tm_isdst: c_int, // DST.     [-1/0/1]
    __tm_gmtoff: c_long, // Seconds east of UTC.
    __tm_zone: [*:0]const u8, // Timezone abbreviation.

    pub fn format(self: tm, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
        _ = options;
        _ = fmt;
        try writer.print("{:0>2}-{:0>2}-{:0>4} {:0>2}:{:0>2}:{:0>2}", .{
            @as(u64, @intCast(self.tm_mday)),
            @as(u64, @intCast(self.tm_mon)),
            @as(u64, @intCast(1900 + self.tm_year)),
            @as(u64, @intCast(self.tm_hour)),
            @as(u64, @intCast(self.tm_min)),
            @as(u64, @intCast(self.tm_sec)),
        });
    }
};

pub fn localTime(time: std.os.linux.time_t) !tm {
    const t: i64 = @intCast(time);

    var days: i64 = undefined;
    var secs: i64 = undefined;
    var remdays: c_int = undefined;
    var remsecs: c_int = undefined;
    var remyears: c_int = undefined;
    var qc_cycles: c_int = undefined;
    var c_cycles: c_int = undefined;
    var q_cycles: c_int = undefined;
    var years: c_int = undefined;
    var months: c_int = 0;
    var wday: c_int = undefined;
    var yday: c_int = undefined;
    var leap: c_int = undefined;
    const days_in_month = [12]u8{ 31, 30, 31, 30, 31, 31, 30, 31, 30, 31, 31, 29 };

    const LEAPOCH = 946684800 + 86400 * (31 + 29);
    const DAYS_PER_400Y = 365 * 400 + 97;
    const DAYS_PER_100Y = 365 * 100 + 24;
    const DAYS_PER_4Y = 365 * 4 + 1;

    // Reject time_t values whose year would overflow int */
    if (t < std.math.minInt(c_int) * 31622400 or t > std.math.maxInt(c_int) * 31622400) {
        return error.Overflow;
    }

    secs = t - LEAPOCH;
    days = @divTrunc(secs, 86400);
    remsecs = @intCast(@rem(secs, 86400));
    if (remsecs < 0) {
        remsecs += 86400;
        days -= 1;
    }

    wday = @intCast(@rem((3 + days), 7));
    if (wday < 0) wday += 7;

    qc_cycles = @intCast(@divTrunc(days, DAYS_PER_400Y));
    remdays = @intCast(@rem(days, DAYS_PER_400Y));
    if (remdays < 0) {
        remdays += DAYS_PER_400Y;
        qc_cycles -= 1;
    }

    c_cycles = @intCast(@divTrunc(remdays, DAYS_PER_100Y));
    if (c_cycles == 4) c_cycles -= 1;
    remdays -= c_cycles * DAYS_PER_100Y;

    q_cycles = @intCast(@divTrunc(remdays, DAYS_PER_4Y));
    if (q_cycles == 25) q_cycles -= 1;
    remdays -= q_cycles * DAYS_PER_4Y;

    remyears = @intCast(@divTrunc(remdays, 365));
    if (remyears == 4) remyears -= 1;
    remdays -= remyears * 365;

    leap = if ((remyears == 0) and (q_cycles != 0 or c_cycles == 0)) 1 else 0;
    yday = remdays + 31 + 28 + leap;
    if (yday >= 365 + leap) yday -= 365 + leap;

    years = remyears + 4 * q_cycles + 100 * c_cycles + 400 * qc_cycles;

    while (days_in_month[@intCast(months)] <= remdays) : (months += 1) {
        remdays -= days_in_month[@intCast(months)];
    }

    if (years + 100 > std.math.maxInt(c_int) or years + 100 < std.math.minInt(c_int)) {
        return error.Overflow;
    }

    var result: tm = undefined;
    result.__tm_gmtoff = 0;
    result.__tm_zone = "";

    result.tm_year = years + 100;
    result.tm_mon = months + 2;
    if (result.tm_mon >= 12) {
        result.tm_mon -= 12;
        result.tm_year += 1;
    }
    result.tm_mday = remdays + 1;
    result.tm_wday = wday;
    result.tm_yday = yday;

    result.tm_hour = @divTrunc(remsecs, 3600);
    result.tm_min = @rem(@divTrunc(remsecs, 60), 60);
    result.tm_sec = @rem(remsecs, 60);

    return result;
}
