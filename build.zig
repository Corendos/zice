// Copyright 2023 - Corentin Godeau and the zice contributors
// SPDX-License-Identifier: MIT

const std = @import("std");
const ztun_build = @import("deps/ztun/build.zig");
const xev_build = @import("deps/libxev/build.zig");

pub fn module(b: *std.Build) *std.Build.Module {
    const ztun_module = ztun_build.module(b);
    const xev_module = xev_build.module(b);

    return b.createModule(std.Build.CreateModuleOptions{
        .source_file = .{ .path = thisDir() ++ "/src/main.zig" },
        .dependencies = &.{
            .{ .name = "ztun", .module = ztun_module },
            .{ .name = "xev", .module = xev_module },
        },
    });
}

pub fn buildSamples(b: *std.build.Builder, zice_module: *std.Build.Module, mode: std.builtin.Mode, target: std.zig.CrossTarget) !void {
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
        sample_executable.addModule("zice", zice_module);
        sample_executable.addModule("xev", zice_module.dependencies.get("xev").?);

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
    const mode = b.standardOptimizeOption(.{});

    const zice_module = module(b);

    const main_tests = b.addTest(.{
        .name = "zice_test",
        .root_source_file = std.Build.FileSource.relative("src/main.zig"),
        .target = target,
        .optimize = mode,
    });
    main_tests.addModule("ztun", zice_module.dependencies.get("ztun").?);
    main_tests.addModule("xev", zice_module.dependencies.get("xev").?);

    const run_main_tests = b.addRunArtifact(main_tests);

    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&run_main_tests.step);

    buildSamples(b, zice_module, mode, target) catch unreachable;
}

inline fn thisDir() []const u8 {
    return comptime std.fs.path.dirname(@src().file) orelse ".";
}
