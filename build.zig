const std = @import("std");

pub fn build(b: *std.Build) void {
    const targets = [_]std.Target.Query{
        .{ .cpu_arch = .aarch64, .os_tag = .linux, .abi = .musl },
        .{ .cpu_arch = .x86_64, .os_tag = .linux, .abi = .musl },
    };

    const optimize = b.standardOptimizeOption(.{});

    for (targets) |target_query| {
        const target = b.resolveTargetQuery(target_query);
        const arch_name = @tagName(target_query.cpu_arch.?);

        const exe = b.addExecutable(.{
            .name = "ksuinit",
            .root_module = b.createModule(.{
                .root_source_file = b.path("src/main.zig"),
                .target = target,
                .optimize = if (optimize == .Debug) .ReleaseSmall else optimize,
                .strip = true,
                .single_threaded = true,
            }),
        });

        // Disable PIE - init process doesn't need it
        exe.pie = false;

        // Install to zig-out/<arch>/ksuinit
        const install = b.addInstallArtifact(exe, .{
            .dest_sub_path = b.fmt("{s}/ksuinit", .{arch_name}),
        });

        b.getInstallStep().dependOn(&install.step);
    }

    // Test step (native target)
    const test_step = b.step("test", "Run unit tests");
    const unit_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = b.graph.host,
        }),
    });
    const run_tests = b.addRunArtifact(unit_tests);
    test_step.dependOn(&run_tests.step);
}
