const std = @import("std");
const linux = std.os.linux;
const syscalls = @import("syscalls.zig");
const loader = @import("loader.zig");
const kmsg = @import("kmsg.zig");

const MAX_MOUNTPOINTS = 4;

const AutoUmount = struct {
    mountpoints: [MAX_MOUNTPOINTS][*:0]const u8,
    count: usize,

    const Self = @This();

    pub fn init() Self {
        return .{
            .mountpoints = undefined,
            .count = 0,
        };
    }

    pub fn add(self: *Self, path: [*:0]const u8) void {
        if (self.count < MAX_MOUNTPOINTS) {
            self.mountpoints[self.count] = path;
            self.count += 1;
        }
    }

    pub fn deinit(self: *Self) void {
        // Unmount in reverse order
        var i = self.count;
        while (i > 0) {
            i -= 1;
            syscalls.umount2(self.mountpoints[i], syscalls.MNT_DETACH) catch {};
        }
    }
};

fn mountFs(fstype: [*:0]const u8, target: [*:0]const u8) !void {
    const fd = try syscalls.fsopen(fstype, syscalls.FSOPEN_CLOEXEC);
    defer _ = linux.close(fd);

    try syscalls.fsconfigCreate(fd);

    const mnt_fd = try syscalls.fsmount(fd, syscalls.FSMOUNT_CLOEXEC, 0);
    defer _ = linux.close(mnt_fd);

    try syscalls.moveMount(mnt_fd, "", syscalls.AT_FDCWD, target, syscalls.MOVE_MOUNT_F_EMPTY_PATH);
}

fn prepareMount() AutoUmount {
    var umounter = AutoUmount.init();

    // Mount procfs
    _ = linux.mkdir("/proc", 0o755);
    if (mountFs("proc", "/proc")) {
        umounter.add("/proc");
        kmsg.info("Mounted /proc", .{});
    } else |_| {
        kmsg.err("Cannot mount procfs", .{});
    }

    // Mount sysfs
    _ = linux.mkdir("/sys", 0o755);
    if (mountFs("sysfs", "/sys")) {
        umounter.add("/sys");
        kmsg.info("Mounted /sys", .{});
    } else |_| {
        kmsg.err("Cannot mount sysfs", .{});
    }

    return umounter;
}

fn setupKmsg() void {
    kmsg.initLogger();
}

fn unlimitKmsg() void {
    const fd_result = linux.open("/proc/sys/kernel/printk_devkmsg", .{ .ACCMODE = .WRONLY }, 0);
    const fd: isize = @bitCast(fd_result);
    if (fd >= 0) {
        _ = linux.write(@intCast(fd), "on\n", 3);
        _ = linux.close(@intCast(fd));
    }
}

fn hasKernelsuLegacy() bool {
    var version: i32 = 0;
    _ = syscalls.prctl(
        syscalls.KSU_MAGIC1,
        syscalls.CMD_GET_VERSION,
        @intFromPtr(&version),
        0,
        0,
    );
    kmsg.info("KernelSU legacy check, version: {d}", .{version});
    return version != 0;
}

fn hasKernelsuV2() bool {
    var fd: i32 = -1;
    syscalls.rebootKsu(syscalls.KSU_MAGIC1, syscalls.KSU_MAGIC2, 0, &fd);

    if (fd >= 0) {
        defer _ = linux.close(@intCast(fd));

        var cmd = syscalls.GetInfoCmd{};
        const ret = syscalls.ioctl(@intCast(fd), syscalls.KSU_IOCTL_GET_INFO, @intFromPtr(&cmd));

        if (ret == 0 and cmd.version != 0) {
            kmsg.info("KernelSU v2 detected, version: {d}", .{cmd.version});
            return true;
        }
    }
    return false;
}

pub fn hasKernelsu() bool {
    return hasKernelsuV2() or hasKernelsuLegacy();
}

pub fn run(allocator: std.mem.Allocator) !void {
    // Setup kernel log first
    setupKmsg();

    kmsg.info("Hello, KernelSU!", .{});

    // Mount /proc and /sys to access kernel interface
    var umounter = prepareMount();
    defer umounter.deinit();

    // This relies on the fact that we have /proc mounted
    unlimitKmsg();

    if (hasKernelsu()) {
        kmsg.info("KernelSU may be already loaded in kernel, skip!", .{});
    } else {
        kmsg.info("Loading kernelsu.ko..", .{});
        loader.loadModule("/kernelsu.ko", allocator) catch |e| {
            kmsg.err("Cannot load kernelsu.ko: {s}", .{@errorName(e)});
        };
    }

    // Prepare the real init to transfer control to it
    _ = linux.unlink("/init");

    // Check if /init.real exists (F_OK = 0)
    const access_result = linux.access("/init.real", 0);
    const access_rc: isize = @bitCast(access_result);
    const real_init: [*:0]const u8 = if (access_rc == 0) "init.real" else "/system/bin/init";

    kmsg.info("init is {s}", .{std.mem.span(real_init)});

    _ = linux.symlink(real_init, "/init");
    _ = linux.chmod("/init", 0o755);
}
