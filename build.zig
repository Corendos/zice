// Copyright 2023 - Corentin Godeau and the zice contributors
// SPDX-License-Identifier: MIT

const std = @import("std");

pub fn buildSamples(b: *std.build.Builder, sample_utils_module: *std.Build.Module, optimize: std.builtin.Mode, target: std.zig.CrossTarget) !void {
    var arena_state = std.heap.ArenaAllocator.init(b.allocator);
    defer arena_state.deinit();

    const directory_path = try b.build_root.join(arena_state.allocator(), &[_][]const u8{"samples"});

    var iterable_dir = try std.fs.openIterableDirAbsolute(directory_path, .{});
    var iterator = iterable_dir.iterate();
    while (try iterator.next()) |entry| {
        if (entry.kind != .file) continue;
        const extension = std.fs.path.extension(entry.name);
        if (!std.mem.eql(u8, extension, ".zig")) continue;

        const executable_name = std.fs.path.stem(entry.name);

        const executable_source = std.Build.FileSource{ .path = try std.fs.path.join(arena_state.allocator(), &[_][]const u8{ directory_path, entry.name }) };

        const executable = b.addExecutable(.{
            .name = executable_name,
            .root_source_file = executable_source,
            .target = target,
            .optimize = optimize,
        });
        executable.addModule("zice", b.modules.get("zice").?);
        executable.addModule("xev", b.dependency("libxev", .{}).module("xev"));
        executable.addModule("utils", sample_utils_module);
        const install_executable = b.addInstallArtifact(executable, .{});

        const build_step_description = std.fmt.allocPrint(b.allocator, "Build the \"{s}\" executable", .{executable_name}) catch unreachable;
        const build_step = b.step(executable_name, build_step_description);
        build_step.dependOn(&install_executable.step);

        const run_command = b.addRunArtifact(executable);

        const run_step_description = std.fmt.allocPrint(b.allocator, "Run the \"{s}\" executable", .{executable_name}) catch unreachable;
        const run_step_name = std.fmt.allocPrint(b.allocator, "run_{s}", .{executable_name}) catch unreachable;
        const run_step = b.step(run_step_name, run_step_description);
        run_step.dependOn(&run_command.step);
        run_step.dependOn(&install_executable.step);

        b.installArtifact(executable);
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

    const install_tests = b.addInstallArtifact(main_tests, .{});

    const run_main_tests = b.addRunArtifact(main_tests);

    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&run_main_tests.step);
    test_step.dependOn(&install_tests.step);

    const sample_utils_module = b.createModule(.{
        .source_file = .{ .path = thisDir() ++ "/samples/utils/main.zig" },
        .dependencies = &.{
            .{ .name = "xev", .module = xev_module },
        },
    });
    buildSamples(b, sample_utils_module, optimize, target) catch unreachable;
}

inline fn thisDir() []const u8 {
    return comptime std.fs.path.dirname(@src().file) orelse ".";
}
