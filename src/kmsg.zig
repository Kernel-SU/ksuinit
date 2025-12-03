const std = @import("std");
const linux = std.os.linux;

// makedev implementation for creating device numbers (simplified for small numbers)
fn makedev(major: u32, minor: u32) u32 {
    // For small major/minor numbers (like 1, 11), this simplified version works
    return (major << 8) | minor;
}

pub const KmsgWriter = struct {
    fd: linux.fd_t,

    const Self = @This();

    pub fn init() ?Self {
        // Try to open /dev/kmsg
        const result = linux.open("/dev/kmsg", .{ .ACCMODE = .WRONLY }, 0);
        const fd: isize = @bitCast(result);

        if (fd >= 0) {
            return .{ .fd = @intCast(fd) };
        }

        // Try to create /kmsg device node (major=1, minor=11)
        const mknod_result = linux.mknod("/kmsg", linux.S.IFCHR | 0o666, makedev(1, 11));
        const mknod_rc: isize = @bitCast(mknod_result);
        // EEXIST = 17 on Linux
        if (mknod_rc != 0 and mknod_rc != -17) {
            return null;
        }

        const result2 = linux.open("/kmsg", .{ .ACCMODE = .WRONLY }, 0);
        const fd2: isize = @bitCast(result2);
        if (fd2 >= 0) {
            return .{ .fd = @intCast(fd2) };
        }

        return null;
    }

    pub fn write(self: Self, comptime level: u8, comptime fmt: []const u8, args: anytype) void {
        var buf: [512]u8 = undefined;
        var fbs = std.io.fixedBufferStream(&buf);
        const writer = fbs.writer();

        // Format: <level>ksuinit: message\n
        writer.print("<{d}>ksuinit: " ++ fmt ++ "\n", .{level} ++ args) catch return;

        const written = fbs.getWritten();
        _ = linux.write(self.fd, written.ptr, written.len);
    }

    pub fn info(self: Self, comptime fmt: []const u8, args: anytype) void {
        self.write(6, fmt, args); // LOG_INFO
    }

    pub fn err(self: Self, comptime fmt: []const u8, args: anytype) void {
        self.write(3, fmt, args); // LOG_ERR
    }

    pub fn warn(self: Self, comptime fmt: []const u8, args: anytype) void {
        self.write(4, fmt, args); // LOG_WARNING
    }

    pub fn deinit(self: Self) void {
        _ = linux.close(self.fd);
    }
};

// Global logger instance
pub var logger: ?KmsgWriter = null;

pub fn initLogger() void {
    logger = KmsgWriter.init();
}

pub fn info(comptime fmt: []const u8, args: anytype) void {
    if (logger) |l| l.info(fmt, args);
}

pub fn err(comptime fmt: []const u8, args: anytype) void {
    if (logger) |l| l.err(fmt, args);
}

pub fn warn(comptime fmt: []const u8, args: anytype) void {
    if (logger) |l| l.warn(fmt, args);
}
