// Copyright 2023 - Corentin Godeau and the zice contributors
// SPDX-License-Identifier: MIT

const std = @import("std");

const zice_pkg = std.build.Pkg{
    .name = "zice",
    .source = std.build.FileSource.relative("src/main.zig"),
};

pub fn buildSamples(b: *std.build.Builder, mode: std.builtin.Mode, target: std.zig.CrossTarget) !void {
    var arena_state = std.heap.ArenaAllocator.init(b.allocator);
    defer arena_state.deinit();

    const sample_directory_path = try std.fs.path.join(arena_state.allocator(), &[_][]const u8{ b.build_root, "samples" });
    const sample_output_directory = try std.fs.path.join(arena_state.allocator(), &[_][]const u8{ b.install_path, "samples" });
    _ = sample_output_directory;

    var iterable_dir = try std.fs.openIterableDirAbsolute(sample_directory_path, .{});
    var sample_iterator = iterable_dir.iterate();
    while (try sample_iterator.next()) |entry| {
        if (entry.kind != .File) continue;
        const extension = std.fs.path.extension(entry.name);
        if (!std.mem.eql(u8, extension, ".zig")) continue;

        const executable_name = std.fs.path.stem(entry.name);

        const executable_source = try std.fs.path.join(arena_state.allocator(), &[_][]const u8{ sample_directory_path, entry.name });

        const sample_executable = b.addExecutable(executable_name, executable_source);
        sample_executable.addPackage(zice_pkg);
        sample_executable.setBuildMode(mode);
        sample_executable.setTarget(target);
        sample_executable.install();
    }
}

pub fn build(b: *std.build.Builder) void {
    // Standard release options allow the person running `zig build` to select
    // between Debug, ReleaseSafe, ReleaseFast, and ReleaseSmall.
    const mode = b.standardReleaseOptions();
    const target = b.standardTargetOptions(.{});

    const lib = b.addStaticLibrary("zice", "src/main.zig");
    lib.setBuildMode(mode);
    lib.setTarget(target);
    lib.install();

    const main_tests = b.addTest("src/main.zig");
    main_tests.setBuildMode(mode);

    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&main_tests.step);

    buildSamples(b, mode, target) catch unreachable;
}
