// Copyright 2023 - Corentin Godeau and the zice contributors
// SPDX-License-Identifier: MIT

const std = @import("std");

pub fn buildSamples(b: *std.build.Builder, optimize: std.builtin.Mode, target: std.zig.CrossTarget) !void {
    var arena_state = std.heap.ArenaAllocator.init(b.allocator);
    defer arena_state.deinit();

    const sample_directory_path = try b.build_root.join(arena_state.allocator(), &[_][]const u8{"samples"});

    var iterable_dir = try std.fs.openIterableDirAbsolute(sample_directory_path, .{});
    var sample_iterator = iterable_dir.iterate();
    while (try sample_iterator.next()) |entry| {
        if (entry.kind != .file) continue;
        const extension = std.fs.path.extension(entry.name);
        if (!std.mem.eql(u8, extension, ".zig")) continue;

        const executable_name = std.fs.path.stem(entry.name);

        const executable_source = std.Build.FileSource{ .path = try std.fs.path.join(arena_state.allocator(), &[_][]const u8{ sample_directory_path, entry.name }) };

        const sample_executable = b.addExecutable(.{
            .name = executable_name,
            .root_source_file = executable_source,
            .target = target,
            .optimize = optimize,
        });
        sample_executable.addModule("zice", b.modules.get("zice").?);
        sample_executable.addModule("xev", b.dependency("libxev", .{}).module("xev"));

        b.installArtifact(sample_executable);

        const sample_run_command = b.addRunArtifact(sample_executable);

        const sample_run_step = b.step(executable_name, "Run the sample");
        sample_run_step.dependOn(&sample_run_command.step);
    }
}

pub fn build(b: *std.build.Builder) void {
    // Standard release options allow the person running `zig build` to select
    // between Debug, ReleaseSafe, ReleaseFast, and ReleaseSmall.
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const ztun_module = b.dependency("ztun", .{
        .target = target,
        .optimize = optimize,
    }).module("ztun");
    const xev_module = b.dependency("libxev", .{
        .target = target,
        .optimize = optimize,
    }).module("xev");

    _ = b.addModule("zice", std.Build.CreateModuleOptions{
        .source_file = .{ .path = thisDir() ++ "/src/main.zig" },
        .dependencies = &.{
            .{ .name = "ztun", .module = ztun_module },
            .{ .name = "xev", .module = xev_module },
        },
    });

    const main_tests = b.addTest(.{
        .name = "zice_test",
        .root_source_file = std.Build.FileSource.relative("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    main_tests.addModule("ztun", ztun_module);
    main_tests.addModule("xev", xev_module);

    const run_main_tests = b.addRunArtifact(main_tests);

    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&run_main_tests.step);

    buildSamples(b, optimize, target) catch unreachable;
}

inline fn thisDir() []const u8 {
    return comptime std.fs.path.dirname(@src().file) orelse ".";
}
