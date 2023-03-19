// Copyright 2023 - Corentin Godeau and the zice contributors
// SPDX-License-Identifier: MIT

const std = @import("std");

pub fn buildSamples(b: *std.build.Builder, mode: std.builtin.Mode, target: std.zig.CrossTarget) !void {
    var arena_state = std.heap.ArenaAllocator.init(b.allocator);
    defer arena_state.deinit();

    const sample_directory_path = try b.build_root.join(arena_state.allocator(), &[_][]const u8{"samples"});

    var iterable_dir = try std.fs.openIterableDirAbsolute(sample_directory_path, .{});
    var sample_iterator = iterable_dir.iterate();
    while (try sample_iterator.next()) |entry| {
        if (entry.kind != .File) continue;
        const extension = std.fs.path.extension(entry.name);
        if (!std.mem.eql(u8, extension, ".zig")) continue;

        const executable_name = std.fs.path.stem(entry.name);

        const executable_source = std.Build.FileSource{ .path = try std.fs.path.join(arena_state.allocator(), &[_][]const u8{ sample_directory_path, entry.name }) };

        const sample_executable = b.addExecutable(.{
            .name = executable_name,
            .root_source_file = executable_source,
            .target = target,
            .optimize = mode,
        });

        const zice_module = b.modules.get("zice").?;
        const xev_module = b.modules.get("xev").?;

        sample_executable.addModule("zice", zice_module);
        sample_executable.addModule("xev", xev_module);
        sample_executable.install();

        const sample_run_command = b.addRunArtifact(sample_executable);
        sample_run_command.step.dependOn(&sample_executable.install_step.?.step);

        const sample_run_step = b.step(executable_name, "Run the sample");
        sample_run_step.dependOn(&sample_run_command.step);
    }
}

pub fn build(b: *std.build.Builder) void {
    // Standard release options allow the person running `zig build` to select
    // between Debug, ReleaseSafe, ReleaseFast, and ReleaseSmall.
    const target = b.standardTargetOptions(.{});
    const mode = b.standardOptimizeOption(.{});

    const ztun_module = b.addModule("ztun", .{
        .source_file = std.Build.FileSource.relative("deps/ztun/src/ztun.zig"),
    });
    const xev_module = b.addModule("xev", .{
        .source_file = std.Build.FileSource.relative("deps/libxev/src/main.zig"),
    });
    const zice_module = b.addModule("zice", .{
        .source_file = std.Build.FileSource.relative("src/main.zig"),
        .dependencies = &.{
            .{ .name = "ztun", .module = ztun_module },
            .{ .name = "xev", .module = xev_module },
        },
    });
    _ = zice_module;

    const lib = b.addStaticLibrary(.{
        .name = "zice",
        .root_source_file = std.Build.FileSource.relative("src/main.zig"),
        .target = target,
        .optimize = mode,
    });
    lib.install();

    const main_tests = b.addTest(.{
        .name = "zice_test",
        .root_source_file = std.Build.FileSource.relative("src/main.zig"),
        .target = target,
        .optimize = mode,
    });
    main_tests.addModule("ztun", ztun_module);
    main_tests.addModule("xev", xev_module);

    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&main_tests.step);

    buildSamples(b, mode, target) catch unreachable;
}
