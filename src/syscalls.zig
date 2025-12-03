const std = @import("std");
const linux = std.os.linux;

// Syscall numbers for modern mount API
const SYS = struct {
    const move_mount = 429;
    const fsopen = 430;
    const fsconfig = 431;
    const fsmount = 432;
    const init_module = 175;
};

// Constants
pub const KSU_MAGIC1: u32 = 0xDEADBEEF;
pub const KSU_MAGIC2: u32 = 0xCAFEBABE;
pub const KSU_IOCTL_GET_INFO: u32 = 0x80004b02; // _IOC(_IOC_READ, 'K', 2, 0)
pub const CMD_GET_VERSION: i32 = 2;

pub const FSOPEN_CLOEXEC: u32 = 0x00000001;
pub const FSMOUNT_CLOEXEC: u32 = 0x00000001;
pub const FSCONFIG_CMD_CREATE: u32 = 6;
pub const MOVE_MOUNT_F_EMPTY_PATH: u32 = 0x00000004;
pub const MNT_DETACH: u32 = 0x00000002;

pub const AT_FDCWD: i32 = -100;

pub const SyscallError = error{
    FsOpenFailed,
    FsConfigFailed,
    FsMountFailed,
    MoveMountFailed,
    UmountFailed,
    InitModuleFailed,
};

// fsopen - Open a filesystem
pub fn fsopen(fs_name: [*:0]const u8, flags: u32) SyscallError!linux.fd_t {
    const rc = linux.syscall2(
        @enumFromInt(SYS.fsopen),
        @intFromPtr(fs_name),
        flags,
    );
    const result: isize = @bitCast(rc);
    if (result < 0) {
        return SyscallError.FsOpenFailed;
    }
    return @intCast(result);
}

// fsconfig - Configure a filesystem
pub fn fsconfigCreate(fd: linux.fd_t) SyscallError!void {
    const rc = linux.syscall5(
        @enumFromInt(SYS.fsconfig),
        @as(usize, @intCast(fd)),
        FSCONFIG_CMD_CREATE,
        0,
        0,
        0,
    );
    const result: isize = @bitCast(rc);
    if (result < 0) {
        return SyscallError.FsConfigFailed;
    }
}

// fsmount - Mount a filesystem
pub fn fsmount(fd: linux.fd_t, flags: u32, attr_flags: u32) SyscallError!linux.fd_t {
    const rc = linux.syscall3(
        @enumFromInt(SYS.fsmount),
        @as(usize, @intCast(fd)),
        flags,
        attr_flags,
    );
    const result: isize = @bitCast(rc);
    if (result < 0) {
        return SyscallError.FsMountFailed;
    }
    return @intCast(result);
}

// move_mount - Move mount point
pub fn moveMount(from_fd: linux.fd_t, from_path: [*:0]const u8, to_dirfd: i32, to_path: [*:0]const u8, flags: u32) SyscallError!void {
    const rc = linux.syscall5(
        @enumFromInt(SYS.move_mount),
        @as(usize, @intCast(from_fd)),
        @intFromPtr(from_path),
        @as(usize, @bitCast(@as(isize, to_dirfd))),
        @intFromPtr(to_path),
        flags,
    );
    const result: isize = @bitCast(rc);
    if (result < 0) {
        return SyscallError.MoveMountFailed;
    }
}

// umount2 - Unmount with flags
pub fn umount2(target: [*:0]const u8, flags: u32) SyscallError!void {
    const rc = linux.syscall2(.umount2, @intFromPtr(target), flags);
    const result: isize = @bitCast(rc);
    if (result < 0) {
        return SyscallError.UmountFailed;
    }
}

// init_module - Load kernel module
pub fn initModule(image: []const u8, param_values: [*:0]const u8) SyscallError!void {
    const rc = linux.syscall3(
        @enumFromInt(SYS.init_module),
        @intFromPtr(image.ptr),
        image.len,
        @intFromPtr(param_values),
    );
    const result: isize = @bitCast(rc);
    if (result < 0) {
        return SyscallError.InitModuleFailed;
    }
}

// prctl for KernelSU v1 detection
pub fn prctl(option: usize, arg2: usize, arg3: usize, arg4: usize, arg5: usize) isize {
    const rc = linux.syscall5(.prctl, option, arg2, arg3, arg4, arg5);
    return @bitCast(rc);
}

// reboot for KernelSU v2 detection (abused to get driver fd)
pub fn rebootKsu(magic1: u32, magic2: u32, cmd: u32, arg: *i32) void {
    _ = linux.syscall4(.reboot, magic1, magic2, cmd, @intFromPtr(arg));
}

// ioctl wrapper
pub fn ioctl(fd: linux.fd_t, request: u32, arg: usize) isize {
    const rc = linux.syscall3(.ioctl, @as(usize, @intCast(fd)), request, arg);
    return @bitCast(rc);
}

// GetInfoCmd structure for KernelSU ioctl
pub const GetInfoCmd = extern struct {
    version: u32 = 0,
    flags: u32 = 0,
};
