const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const root_source_file = b.path("src/root.zig");
    const install_step = b.getInstallStep();

    const lib_mod = b.createModule(.{
        .root_source_file = root_source_file,
        .target = target,
        .optimize = optimize,
    });

    const lib = b.addLibrary(.{
        .linkage = .static,
        .name = "kipu",
        .root_module = lib_mod,
    });

    b.installArtifact(lib);

    const tests = b.addTest(.{.root_module = lib_mod});
    const tests_run = b.addRunArtifact(lib_unit_tests);
    const tests_step = b.step("test", "Run tests");
    tests_step.dependOn(&tests_run.step);
    install_step.dependOn(tests_step);
}
