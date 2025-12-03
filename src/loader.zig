const std = @import("std");
const linux = std.os.linux;
const elf_writer = @import("elf_writer.zig");
const syscalls = @import("syscalls.zig");
const kmsg = @import("kmsg.zig");

const KptrGuard = struct {
    original_value: [32]u8,
    len: usize,

    const Self = @This();

    pub fn init() ?Self {
        const fd_result = linux.open("/proc/sys/kernel/kptr_restrict", .{ .ACCMODE = .RDWR }, 0);
        const fd: isize = @bitCast(fd_result);
        if (fd < 0) return null;
        defer _ = linux.close(@intCast(fd));

        var guard = Self{ .original_value = undefined, .len = 0 };
        const n_result = linux.read(@intCast(fd), &guard.original_value, guard.original_value.len);
        const n: isize = @bitCast(n_result);
        if (n <= 0) return null;
        guard.len = @intCast(n);

        // Set to "1" to allow reading addresses
        _ = linux.write(@intCast(fd), "1", 1);
        return guard;
    }

    pub fn deinit(self: *Self) void {
        const fd_result = linux.open("/proc/sys/kernel/kptr_restrict", .{ .ACCMODE = .WRONLY }, 0);
        const fd: isize = @bitCast(fd_result);
        if (fd >= 0) {
            _ = linux.write(@intCast(fd), &self.original_value, self.len);
            _ = linux.close(@intCast(fd));
        }
    }
};

pub fn parseKallsyms(allocator: std.mem.Allocator) !std.StringHashMap(u64) {
    var guard = KptrGuard.init();
    defer if (guard) |*g| g.deinit();

    // Read /proc/kallsyms
    const fd_result = linux.open("/proc/kallsyms", .{ .ACCMODE = .RDONLY }, 0);
    const fd: isize = @bitCast(fd_result);
    if (fd < 0) return error.CannotOpenKallsyms;
    defer _ = linux.close(@intCast(fd));

    var symbols = std.StringHashMap(u64).init(allocator);
    errdefer {
        var it = symbols.iterator();
        while (it.next()) |entry| {
            allocator.free(entry.key_ptr.*);
        }
        symbols.deinit();
    }

    // Read file in chunks and parse
    var file_buf: [4096]u8 = undefined;
    var line_buf: [256]u8 = undefined;
    var line_len: usize = 0;

    while (true) {
        const read_result = linux.read(@intCast(fd), &file_buf, file_buf.len);
        const bytes_read: isize = @bitCast(read_result);
        if (bytes_read <= 0) break;

        var i: usize = 0;
        while (i < @as(usize, @intCast(bytes_read))) : (i += 1) {
            const c = file_buf[i];
            if (c == '\n') {
                // Parse line
                if (line_len > 0) {
                    const line = line_buf[0..line_len];
                    if (parseLine(line)) |entry| {
                        const name_copy = try allocator.dupe(u8, entry.name);
                        try symbols.put(name_copy, entry.addr);
                    }
                }
                line_len = 0;
            } else if (line_len < line_buf.len) {
                line_buf[line_len] = c;
                line_len += 1;
            }
        }
    }

    // Handle last line if no newline at end
    if (line_len > 0) {
        const line = line_buf[0..line_len];
        if (parseLine(line)) |entry| {
            const name_copy = try allocator.dupe(u8, entry.name);
            try symbols.put(name_copy, entry.addr);
        }
    }

    return symbols;
}

const ParsedEntry = struct {
    addr: u64,
    name: []const u8,
};

fn parseLine(line: []const u8) ?ParsedEntry {
    // Format: "ffffffff81000000 T symbol_name"
    var iter = std.mem.splitScalar(u8, line, ' ');

    const addr_str = iter.next() orelse return null;
    _ = iter.next(); // Skip type

    const name_raw = iter.next() orelse return null;

    // Remove $ or .llvm. suffix
    var name = name_raw;
    if (std.mem.indexOf(u8, name_raw, "$")) |pos| {
        name = name_raw[0..pos];
    } else if (std.mem.indexOf(u8, name_raw, ".llvm.")) |pos| {
        name = name_raw[0..pos];
    }

    if (name.len == 0) return null;

    const addr = std.fmt.parseInt(u64, addr_str, 16) catch return null;

    return .{ .addr = addr, .name = name };
}

pub fn loadModule(path: [*:0]const u8, allocator: std.mem.Allocator) !void {
    // Check if we are init process (pid == 1)
    const pid = linux.getpid();
    if (pid != 1) {
        return error.NotInitProcess;
    }

    // Read module file
    const fd_result = linux.open(path, .{ .ACCMODE = .RDONLY }, 0);
    const fd: isize = @bitCast(fd_result);
    if (fd < 0) {
        return error.CannotOpenModule;
    }
    defer _ = linux.close(@intCast(fd));

    // Get file size using lseek
    const size_result = linux.lseek(@intCast(fd), 0, linux.SEEK.END);
    const size: isize = @bitCast(size_result);
    if (size <= 0) {
        return error.CannotGetFileSize;
    }
    _ = linux.lseek(@intCast(fd), 0, linux.SEEK.SET);

    // Allocate buffer
    const buffer = try allocator.alloc(u8, @intCast(size));
    defer allocator.free(buffer);

    // Read file
    var total_read: usize = 0;
    while (total_read < buffer.len) {
        const read_result = linux.read(@intCast(fd), buffer[total_read..].ptr, buffer.len - total_read);
        const bytes_read: isize = @bitCast(read_result);
        if (bytes_read <= 0) break;
        total_read += @intCast(bytes_read);
    }

    if (total_read != buffer.len) {
        return error.IncompleteRead;
    }

    // Parse kernel symbols
    var kernel_symbols = try parseKallsyms(allocator);
    defer {
        var it = kernel_symbols.iterator();
        while (it.next()) |entry| {
            allocator.free(entry.key_ptr.*);
        }
        kernel_symbols.deinit();
    }

    // Initialize ELF modifier
    var modifier = try elf_writer.ElfModifier.init(buffer);

    // Find undefined symbols
    var undefined_syms = try modifier.findUndefinedSymbols(allocator);
    defer undefined_syms.deinit(allocator);

    // Resolve and modify symbols
    for (undefined_syms.items) |sym| {
        if (kernel_symbols.get(sym.name)) |addr| {
            modifier.modifySymbol(sym.file_offset, addr);
        } else {
            kmsg.warn("Cannot find symbol: {s}", .{sym.name});
        }
    }

    // Load module
    try syscalls.initModule(buffer, "");
}
