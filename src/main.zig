const std = @import("std");
const linux = std.os.linux;
const init = @import("init.zig");

pub fn main() void {
    // Use fixed buffer allocator to avoid heap allocation
    var buffer: [128 * 1024]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&buffer);
    const allocator = fba.allocator();

    // Run initialization
    init.run(allocator) catch {};

    // Transfer control to real init
    // Pass empty argv and envp since init typically doesn't need them
    const argv = [_:null]?[*:0]const u8{"/init"};
    const envp = [_:null]?[*:0]const u8{};
    _ = linux.execve("/init", &argv, &envp);
}

test "kmsg module" {
    _ = @import("kmsg.zig");
}

test "syscalls module" {
    _ = @import("syscalls.zig");
}

test "elf_writer module" {
    _ = @import("elf_writer.zig");
}

test "loader module" {
    _ = @import("loader.zig");
}

test "init module" {
    _ = @import("init.zig");
}
