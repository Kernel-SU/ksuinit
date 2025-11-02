#![allow(dead_code)]
use rustix::fs::{makedev, mknodat, FileType, Mode, CWD};
use obfstr::obfstr as s;
use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use crate::loader::load_module;


/*
 * When the boot image header has a version of 3 - 4, the structure of the boot
 * image is as follows:
 *
 * +---------------------+
 * | boot header         | 4096 bytes
 * +---------------------+
 * | kernel              | m pages
 * +---------------------+
 * | ramdisk             | n pages
 * +---------------------+
 * | boot signature      | g pages
 * +---------------------+
 *
 * m = (kernel_size + 4096 - 1) / 4096
 * n = (ramdisk_size + 4096 - 1) / 4096
 * g = (signature_size + 4096 - 1) / 4096
 *
 * Page size is fixed at 4096 bytes.
 *
 */

// Boot image constants
pub const BOOT_MAGIC_SIZE: usize = 8;
pub const BOOT_ARGS_SIZE: usize = 512;
pub const BOOT_EXTRA_ARGS_SIZE: usize = 1024;
pub const BOOT_MAGIC: &[u8; BOOT_MAGIC_SIZE] = b"ANDROID!";

// Page size for boot image v3-4
pub const BOOT_IMAGE_PAGE_SIZE: usize = 4096;

/// Boot image header (supports version 3 and 4)
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct BootImgHdr {
    magic: [u8; BOOT_MAGIC_SIZE],
    kernel_size: u32,  // size in bytes
    ramdisk_size: u32, // size in bytes
    os_version: u32,
    header_size: u32,
    reserved: [u32; 4],
    header_version: u32,
    cmdline: [u8; BOOT_ARGS_SIZE + BOOT_EXTRA_ARGS_SIZE],
    signature_size: u32, // size in bytes (v4 only)
}

impl BootImgHdr {
    /// Get the magic bytes
    pub fn magic(&self) -> &[u8; BOOT_MAGIC_SIZE] {
        &self.magic
    }

    /// Get kernel size
    pub fn kernel_size(&self) -> u32 {
        self.kernel_size
    }

    /// Get ramdisk size
    pub fn ramdisk_size(&self) -> u32 {
        self.ramdisk_size
    }

    /// Get OS version
    pub fn os_version(&self) -> u32 {
        self.os_version
    }

    /// Get header size
    pub fn header_size(&self) -> u32 {
        self.header_size
    }

    /// Get header version
    pub fn header_version(&self) -> u32 {
        self.header_version
    }

    /// Get command line
    pub fn cmdline(&self) -> &[u8] {
        &self.cmdline
    }

    /// Get signature size (only valid for v4)
    pub fn signature_size(&self) -> Option<u32> {
        if self.header_version >= 4 {
            Some(self.signature_size)
        } else {
            None
        }
    }

    /// Validate the magic header
    pub fn is_valid(&self) -> bool {
        &self.magic == BOOT_MAGIC
    }

    /// Calculate the number of pages needed for kernel
    pub fn kernel_pages(&self) -> usize {
        (self.kernel_size as usize + BOOT_IMAGE_PAGE_SIZE - 1) / BOOT_IMAGE_PAGE_SIZE
    }

    /// Calculate the number of pages needed for ramdisk
    pub fn ramdisk_pages(&self) -> usize {
        (self.ramdisk_size as usize + BOOT_IMAGE_PAGE_SIZE - 1) / BOOT_IMAGE_PAGE_SIZE
    }

    /// Calculate the number of pages needed for signature (v4 only)
    pub fn signature_pages(&self) -> usize {
        if let Some(sig_size) = self.signature_size() {
            (sig_size as usize + BOOT_IMAGE_PAGE_SIZE - 1) / BOOT_IMAGE_PAGE_SIZE
        } else {
            0
        }
    }

    /// Get kernel offset in the boot image
    pub fn kernel_offset(&self) -> usize {
        BOOT_IMAGE_PAGE_SIZE // Right after header
    }

    /// Get ramdisk offset in the boot image
    pub fn ramdisk_offset(&self) -> usize {
        self.kernel_offset() + self.kernel_pages() * BOOT_IMAGE_PAGE_SIZE
    }

    /// Get signature offset in the boot image (v4 only)
    pub fn signature_offset(&self) -> Option<usize> {
        if self.signature_size().is_some() {
            Some(self.ramdisk_offset() + self.ramdisk_pages() * BOOT_IMAGE_PAGE_SIZE)
        } else {
            None
        }
    }

    /// Get KernelSU module size from reserved[3] if os_version == 4
    pub fn ksu_size(&self) -> Option<u32> {
        if self.os_version == 4 {
            Some(self.reserved[3])
        } else {
            None
        }
    }
}

#[derive(Debug, Default)]
struct UeventInfo {
    major: Option<u64>,
    minor: Option<u64>,
    devname: Option<String>,
    partname: Option<String>,
}

fn parse_uevent(path: &std::path::Path) -> Option<UeventInfo> {
    let content = std::fs::read_to_string(path).ok()?;
    let mut info = UeventInfo::default();

    for line in content.lines() {
        if let Some((key, value)) = line.split_once('=') {
            match key {
                "MAJOR" => info.major = value.parse().ok(),
                "MINOR" => info.minor = value.parse().ok(),
                "DEVNAME" => info.devname = Some(value.to_string()),
                "PARTNAME" => info.partname = Some(value.to_string()),
                _ => {}
            }
        }
    }

    Some(info)
}

fn find_uevent_files(dir: &std::path::Path, depth: usize, max_depth: usize) -> Vec<std::path::PathBuf> {
    let mut uevent_files = Vec::new();

    if depth >= max_depth {
        return uevent_files;
    }

    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.filter_map(|e| e.ok()) {
            let path = entry.path();

            if path.is_dir() {
                // 递归遍历子目录
                uevent_files.extend(find_uevent_files(&path, depth + 1, max_depth));
            } else if path.file_name() == Some(std::ffi::OsStr::new("uevent")) {
                uevent_files.push(path);
            }
        }
    }

    uevent_files
}

pub fn setup_boot_devices() {
    log::info!("{}", s!("Scanning for boot partitions..."));

    let uevent_files = find_uevent_files(std::path::Path::new("/sys/block"), 0, 4);

    for path in uevent_files {
        if let Some(info) = parse_uevent(&path) {
            if let (Some(partname), Some(major), Some(minor)) =
                (&info.partname, info.major, info.minor)
            {
                // 检查是否是 boot 分区
                if partname.starts_with("boot") {
                    let dev_path = format!("/dev/{}", partname);

                    log::info!(
                        "{} {} (major={}, minor={})",
                        s!("Creating device node:"),
                        dev_path,
                        major,
                        minor
                    );

                    if let Err(e) = mknodat(
                        CWD,
                        dev_path.as_str(),
                        FileType::BlockDevice,
                        Mode::from_raw_mode(0o600),
                        makedev(major as u32, minor as u32),
                    ) {
                        log::error!("{} {}: {}", s!("Failed to create device node"), dev_path, e);
                    }
                }
            }
        }
    }
}

pub fn parse_bootconfig() -> std::io::Result<HashMap<String, String>> {
    let content = std::fs::read_to_string("/proc/bootconfig")?;
    let mut config = HashMap::new();

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        // 解析格式: key = "value"
        if let Some((key, value)) = line.split_once(" = ") {
            let key = key.trim().to_string();
            // 移除值两边的引号
            let value = value.trim().trim_matches('"').to_string();
            config.insert(key, value);
        }
    }

    Ok(config)
}

/// 从 bootconfig 中获取指定的键值
pub fn get_bootconfig_value(key: &str) -> Option<String> {
    parse_bootconfig()
        .ok()
        .and_then(|config| config.get(key).cloned())
}


pub fn load_module_from_boot() -> anyhow::Result<()> {
    // Setup boot device nodes
    setup_boot_devices();
    log::info!("{}", s!("Boot devices setup completed."));

    // get boot slot suffix for A/B partitions (e.g., "_a" or "_b")
    let slot_suffix = get_bootconfig_value("androidboot.slot_suffix").unwrap_or_else(|| "".into());

    // Construct boot partition path with slot suffix
    let boot_path = format!("/dev/boot{}", slot_suffix);
    log::info!("{} {}", s!("Opening boot partition:"), boot_path);

    let mut boot_file = File::open(&boot_path)
        .map_err(|e| anyhow::anyhow!("{} {}: {}", s!("Failed to open boot partition"), boot_path, e))?;

    // Read boot image header
    let header_size = std::mem::size_of::<BootImgHdr>();
    let mut header_bytes = vec![0u8; header_size];
    boot_file.read_exact(&mut header_bytes)
        .map_err(|e| anyhow::anyhow!("{}: {}", s!("Failed to read boot header"), e))?;

    // Convert bytes to BootImgHdr struct (unsafe due to packed struct)
    let header: BootImgHdr = unsafe {
        std::ptr::read(header_bytes.as_ptr() as *const BootImgHdr)
    };

    // Validate boot image header
    if !header.is_valid() {
        anyhow::bail!("{}", s!("Invalid boot image magic"));
    }

    log::info!("{}", s!("Boot image header validated successfully"));
    log::info!("{}: {}", s!("Header version"), header.header_version());
    log::info!("{}: {}", s!("OS version"), header.os_version());
    log::info!("{}: {} bytes", s!("Kernel size"), header.kernel_size());
    log::info!("{}: {} bytes", s!("Ramdisk size"), header.ramdisk_size());

    // Check if this boot image contains KernelSU module
    let ksu_size = header.ksu_size()
        .ok_or_else(|| anyhow::anyhow!("{}", s!("No KernelSU module found in boot image (os_version != 4)")))?;

    log::info!("{}: {} bytes", s!("KernelSU module size"), ksu_size);

    if ksu_size == 0 {
        anyhow::bail!("{}", s!("KernelSU module size is 0"));
    }

    // Seek to ramdisk offset where KernelSU module is stored
    let ramdisk_offset = header.ramdisk_offset();
    log::info!("{}: {} bytes", s!("Reading KernelSU module from ramdisk offset"), ramdisk_offset);

    boot_file.seek(SeekFrom::Start(ramdisk_offset as u64))
        .map_err(|e| anyhow::anyhow!("{}: {}", s!("Failed to seek to ramdisk offset"), e))?;

    // Read KernelSU module data
    let mut module_data = vec![0u8; ksu_size as usize];
    boot_file.read_exact(&mut module_data)
        .map_err(|e| anyhow::anyhow!("{}: {}", s!("Failed to read KernelSU module data"), e))?;

    log::info!("{}", s!("KernelSU module data read successfully"));

    // Load the module
    log::info!("{}", s!("Loading KernelSU module..."));
    load_module(&mut module_data)
        .map_err(|e| anyhow::anyhow!("{}: {}", s!("Failed to load KernelSU module"), e))?;

    log::info!("{}", s!("KernelSU module loaded successfully"));

    Ok(())
}

fn has_kernelsu_legacy() -> bool {
    use syscalls::{syscall, Sysno};
    let mut version = 0;
    const CMD_GET_VERSION: i32 = 2;
    unsafe {
        let _ = syscall!(
            Sysno::prctl,
            0xDEADBEEF,
            CMD_GET_VERSION,
            std::ptr::addr_of_mut!(version)
        );
    }

    log::info!("{}: {}", s!("KernelSU version"), version);

    version != 0
}

fn has_kernelsu_v2() -> bool {
    use syscalls::{syscall, Sysno};
    const KSU_INSTALL_MAGIC1: u32 = 0xDEADBEEF;
    const KSU_INSTALL_MAGIC2: u32 = 0xCAFEBABE;
    const KSU_IOCTL_GET_INFO: u32 = 0x80004b02; // _IOC(_IOC_READ, 'K', 2, 0)
    const CMD_GET_VERSION: i32 = 2;

    #[repr(C)]
    #[derive(Default)]
    struct GetInfoCmd {
        version: u32,
        flags: u32,
    }

    // Try new method: get driver fd using reboot syscall with magic numbers
    let mut fd: i32 = -1;
    unsafe {
        let _ = syscall!(
            Sysno::reboot,
            KSU_INSTALL_MAGIC1,
            KSU_INSTALL_MAGIC2,
            0,
            std::ptr::addr_of_mut!(fd)
        );
    }

    let version = if fd >= 0 {
        // New method: try to get version info via ioctl
        let mut cmd = GetInfoCmd::default();
        let version = unsafe {
            let ret = syscall!(Sysno::ioctl, fd, KSU_IOCTL_GET_INFO, &mut cmd as *mut _);

            match ret {
                Ok(_) => cmd.version,
                Err(_) => 0,
            }
        };

        unsafe {
            let _ = syscall!(Sysno::close, fd);
        }

        version
    } else {
        0
    };

    log::info!("{}: {}", s!("KernelSU version"), version);

    version != 0
}

pub fn has_kernelsu() -> bool {
    has_kernelsu_v2() || has_kernelsu_legacy()
}