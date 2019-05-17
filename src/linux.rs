// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std;
use std::cmp::min;
use std::error::Error as StdError;
use std::ffi::CStr;
use std::fmt::{self, Display};
use std::fs::{File, OpenOptions};
use std::io::{self, stdin, Read};
use std::net::Ipv4Addr;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::path::{Path, PathBuf};
use std::str;
use std::sync::{Arc, Barrier};
use std::thread;
use std::thread::JoinHandle;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use libc::{self, c_int, gid_t, uid_t};

use devices::virtio::{self, VirtioDevice};
use devices::{self, HostBackendDeviceProvider, PciDevice, VirtioPciDevice, XhciController};
use kvm::*;
use qcow::{self, ImageType, QcowFile};
use remain::sorted;
use sync::{Condvar, Mutex};
use sys_util::{
    self, error, flock,
    info, set_cpu_affinity,
    warn, EventFd, FlockOperation, GuestMemoryMmap, Killable, PollContext, PollToken,
    Terminal, SIGRTMIN,
};
use vm_control::{VmRunMode};

use crate::{Config, DiskOption, TouchDeviceOption};

use arch::{self, LinuxArch, RunnableLinuxVm, VirtioDeviceStub, VmComponents};

#[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
use aarch64::AArch64 as Arch;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use x86_64::X8664arch as Arch;

#[sorted]
#[derive(Debug)]
pub enum Error {
    BlockDeviceNew(sys_util::Error),
    BuildVm(<Arch as LinuxArch>::Error),
    CloneEventFd(sys_util::Error),
    CreateEventFd(sys_util::Error),
    CreatePollContext(sys_util::Error),
    DetectImageType(qcow::Error),
    Disk(io::Error),
    DiskImageLock(sys_util::Error),
    InputDeviceNew(virtio::InputError),
    InputEventsOpen(std::io::Error),
    InvalidFdPath,
    LoadKernel(Box<dyn StdError>),
    NetDeviceNew(virtio::NetError),
    OpenAndroidFstab(PathBuf, io::Error),
    OpenInitrd(PathBuf, io::Error),
    OpenKernel(PathBuf, io::Error),
    OpenVinput(PathBuf, io::Error),
    PivotRootDoesntExist(&'static str),
    PollContextAdd(sys_util::Error),
    PollContextDelete(sys_util::Error),
    QcowDeviceCreate(qcow::Error),
    ReadLowmemAvailable(io::Error),
    ReadLowmemMargin(io::Error),
    RegisterBlock(arch::DeviceRegistrationError),
    RegisterNet(arch::DeviceRegistrationError),
    RegisterRng(arch::DeviceRegistrationError),
    ReserveMemory(sys_util::Error),
    RngDeviceNew(virtio::RngError),
    SpawnVcpu(io::Error),
    VirtioPciDev(sys_util::Error),
}

impl Display for Error {
    #[remain::check]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::Error::*;

        #[sorted]
        match self {
            BlockDeviceNew(e) => write!(f, "failed to create block device: {}", e),
            BuildVm(e) => write!(f, "The architecture failed to build the vm: {}", e),
            CloneEventFd(e) => write!(f, "failed to clone eventfd: {}", e),
            CreateCrasClient(e) => write!(f, "failed to create cras client: {}", e),
            CreateEventFd(e) => write!(f, "failed to create eventfd: {}", e),
            CreatePollContext(e) => write!(f, "failed to create poll context: {}", e),
            DetectImageType(e) => write!(f, "failed to detect disk image type: {}", e),
            DevicePivotRoot(e) => write!(f, "failed to pivot root device: {}", e),
            Disk(e) => write!(f, "failed to load disk image: {}", e),
            DiskImageLock(e) => write!(f, "failed to lock disk image: {}", e),
            InputDeviceNew(e) => write!(f, "failed to set up input device: {}", e),
            InputEventsOpen(e) => write!(f, "failed to open event device: {}", e),
            InvalidFdPath => write!(f, "failed parsing a /proc/self/fd/*"),
            LoadKernel(e) => write!(f, "failed to load kernel: {}", e),
            NetDeviceNew(e) => write!(f, "failed to set up virtio networking: {}", e),
            OpenAndroidFstab(p, e) => write!(
                f,
                "failed to open android fstab file {}: {}",
                p.display(),
                e
            ),
            OpenInitrd(p, e) => write!(f, "failed to open initrd {}: {}", p.display(), e),
            OpenKernel(p, e) => write!(f, "failed to open kernel image {}: {}", p.display(), e),
            OpenVinput(p, e) => write!(f, "failed to open vinput device {}: {}", p.display(), e),
            PollContextAdd(e) => write!(f, "failed to add fd to poll context: {}", e),
            PollContextDelete(e) => write!(f, "failed to remove fd from poll context: {}", e),
            QcowDeviceCreate(e) => write!(f, "failed to read qcow formatted file {}", e),
            ReadLowmemAvailable(e) => write!(
                f,
                "failed to read /sys/kernel/mm/chromeos-low_mem/available: {}",
                e
            ),
            ReadLowmemMargin(e) => write!(
                f,
                "failed to read /sys/kernel/mm/chromeos-low_mem/margin: {}",
                e
            ),
            RegisterBlock(e) => write!(f, "error registering block device: {}", e),
            RegisterNet(e) => write!(f, "error registering net device: {}", e),
            RegisterRng(e) => write!(f, "error registering rng device: {}", e),
            ReserveMemory(e) => write!(f, "failed to reserve memory: {}", e),
            RngDeviceNew(e) => write!(f, "failed to set up rng: {}", e),
            SettingGidMap(e) => write!(f, "error setting GID map: {}", e),
            SettingUidMap(e) => write!(f, "error setting UID map: {}", e),
            SpawnVcpu(e) => write!(f, "failed to spawn VCPU thread: {}", e),
            VirtioPciDev(e) => write!(f, "failed to create virtio pci dev: {}", e),
        }
    }
}

impl std::error::Error for Error {}

type Result<T> = std::result::Result<T, Error>;
type DeviceResult<T = VirtioDeviceStub> = std::result::Result<T, Error>;

fn create_block_device(
    cfg: &Config,
    disk: &DiskOption,
) -> DeviceResult {
    // Special case '/proc/self/fd/*' paths. The FD is already open, just use it.
    let raw_image: File = if disk.path.parent() == Some(Path::new("/proc/self/fd")) {
        // Safe because we will validate |raw_fd|.
        unsafe { File::from_raw_fd(raw_fd_from_path(&disk.path)?) }
    } else {
        OpenOptions::new()
            .read(true)
            .write(!disk.read_only)
            .open(&disk.path)
            .map_err(Error::Disk)?
    };
    // Lock the disk image to prevent other crosvm instances from using it.
    // TODO(lpetrut): we may want to use this on Windows.
    // let lock_op = if disk.read_only {
    //     FlockOperation::LockShared
    // } else {
    //     FlockOperation::LockExclusive
    // };
    // flock(&raw_image, lock_op, true).map_err(Error::DiskImageLock)?;

    let image_type = qcow::detect_image_type(&raw_image).map_err(Error::DetectImageType)?;
    let dev = match image_type {
        ImageType::Raw => {
            // Access as a raw block device.
            let dev = virtio::Block::new(raw_image, disk.read_only)
                .map_err(Error::BlockDeviceNew)?;
            Box::new(dev) as Box<dyn VirtioDevice>
        }
        ImageType::Qcow2 => {
            // Valid qcow header present
            let qcow_image = QcowFile::from(raw_image).map_err(Error::QcowDeviceCreate)?;
            let dev = virtio::Block::new(qcow_image, disk.read_only)
                .map_err(Error::BlockDeviceNew)?;
            Box::new(dev) as Box<dyn VirtioDevice>
        }
    };

    Ok(VirtioDeviceStub {
        dev,
    })
}

fn create_devices(
    cfg: Config,
    mem: &GuestMemoryMmap,
    exit_evt: &EventFd,
) -> DeviceResult<Vec<(Box<dyn PciDevice>)>> {
    let stubs = create_virtio_devices(
        &cfg,
        mem,
        exit_evt,
    )?;

    let mut pci_devices = Vec::new();

    for stub in stubs {
        let dev = VirtioPciDevice::new(mem.clone(), stub.dev).map_err(Error::VirtioPciDev)?;
        let dev = Box::new(dev) as Box<dyn PciDevice>;
        pci_devices.push(dev);
    }

    Ok(pci_devices)
}

#[derive(Copy, Clone)]
struct Ids {
    uid: uid_t,
    gid: gid_t,
}

fn raw_fd_from_path(path: &Path) -> Result<RawFd> {
    if !path.is_file() {
        return Err(Error::InvalidFdPath);
    }
    path.file_name()
        .and_then(|fd_osstr| fd_osstr.to_str())
        .and_then(|fd_str| fd_str.parse::<c_int>().ok())
        .ok_or(Error::InvalidFdPath)?;
}


#[derive(Default)]
struct VcpuRunMode {
    mtx: Mutex<VmRunMode>,
    cvar: Condvar,
}

impl VcpuRunMode {
    fn set_and_notify(&self, new_mode: VmRunMode) {
        *self.mtx.lock() = new_mode;
        self.cvar.notify_all();
    }
}

fn run_vcpu(
    vcpu: Vcpu,
    cpu_id: u32,
    vcpu_affinity: Vec<usize>,
    start_barrier: Arc<Barrier>,
    io_bus: devices::Bus,
    mmio_bus: devices::Bus,
    exit_evt: EventFd,
    requires_kvmclock_ctrl: bool,
    run_mode_arc: Arc<VcpuRunMode>,
) -> Result<JoinHandle<()>> {
    thread::Builder::new()
        .name(format!("crosvm_vcpu{}", cpu_id))
        .spawn(move || {
            start_barrier.wait();

            if sig_ok {
                'vcpu_loop: loop {
                    match vcpu.run() {
                        Ok(VcpuExit::IoIn { port, mut size }) => {
                            let mut data = [0; 8];
                            if size > data.len() {
                                error!("unsupported IoIn size of {} bytes", size);
                                size = data.len();
                            }
                            io_bus.read(port as u64, &mut data[..size]);
                            if let Err(e) = vcpu.set_data(&data[..size]) {
                                error!("failed to set return data for IoIn: {}", e);
                            }
                        }
                        Ok(VcpuExit::IoOut {
                            port,
                            mut size,
                            data,
                        }) => {
                            if size > data.len() {
                                error!("unsupported IoOut size of {} bytes", size);
                                size = data.len();
                            }
                            io_bus.write(port as u64, &data[..size]);
                        }
                        Ok(VcpuExit::MmioRead { address, size }) => {
                            let mut data = [0; 8];
                            mmio_bus.read(address, &mut data[..size]);
                            // Setting data for mmio can not fail.
                            let _ = vcpu.set_data(&data[..size]);
                        }
                        Ok(VcpuExit::MmioWrite {
                            address,
                            size,
                            data,
                        }) => {
                            mmio_bus.write(address, &data[..size]);
                        }
                        Ok(VcpuExit::Hlt) => break,
                        Ok(VcpuExit::Shutdown) => break,
                        Ok(VcpuExit::SystemEvent(_, _)) => break,
                        Ok(r) => warn!("unexpected vcpu exit: {:?}", r),
                        Err(e) => match e.errno() {
                            libc::EAGAIN => {}
                            _ => {
                                error!("vcpu hit unknown error: {}", e);
                                break;
                            }
                        },
                    }
                }
            }
            exit_evt
                .write(1)
                .expect("failed to signal vcpu exit eventfd");
        })
        .map_err(Error::SpawnVcpu)
}

// Reads the contents of a file and converts the space-separated fields into a Vec of u64s.
// Returns an error if any of the fields fail to parse.
fn file_fields_to_u64<P: AsRef<Path>>(path: P) -> io::Result<Vec<u64>> {
    let mut file = File::open(path)?;

    let mut buf = [0u8; 32];
    let count = file.read(&mut buf)?;

    let content =
        str::from_utf8(&buf[..count]).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    content
        .trim()
        .split_whitespace()
        .map(|x| {
            x.parse::<u64>()
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
        })
        .collect()
}

// Reads the contents of a file and converts them into a u64, and if there
// are multiple fields it only returns the first one.
fn file_to_u64<P: AsRef<Path>>(path: P) -> io::Result<u64> {
    file_fields_to_u64(path)?
        .into_iter()
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "empty file"))
}

pub fn run_config(cfg: Config) -> Result<()> {
    let initrd_image = if let Some(initrd_path) = &cfg.initrd_path {
        Some(File::open(initrd_path).map_err(|e| Error::OpenInitrd(initrd_path.clone(), e))?)
    } else {
        None
    };

    let components = VmComponents {
        memory_size: (cfg.memory.unwrap_or(256) << 20) as u64,
        vcpu_count: cfg.vcpu_count.unwrap_or(1),
        vcpu_affinity: cfg.vcpu_affinity.clone(),
        kernel_image: File::open(&cfg.kernel_path)
            .map_err(|e| Error::OpenKernel(cfg.kernel_path.clone(), e))?,
        android_fstab: cfg
            .android_fstab
            .as_ref()
            .map(|x| File::open(x).map_err(|e| Error::OpenAndroidFstab(x.to_path_buf(), e)))
            .map_or(Ok(None), |v| v.map(Some))?,
        initrd_image,
        extra_kernel_params: cfg.params.clone(),
    };

    let linux = Arch::build_vm(components, cfg.split_irqchip, |m, e| {
        create_devices(
            cfg,
            m,
            e,
        )
    })
    .map_err(Error::BuildVm)?;

    run_control(
        linux
    )
}

fn run_control(
    mut linux: RunnableLinuxVm,
) -> Result<()> {

    #[derive(PollToken)]
    enum Token {
        Exit,
        Stdin,
        CheckAvailableMemory,
        LowMemory,
        LowmemTimer,
        VmControlServer,
        VmControl { index: usize },
    }

    let stdin_handle = stdin();
    let stdin_lock = stdin_handle.lock();
    // stdin_lock
    //     .set_raw_mode()
    //     .expect("failed to set terminal raw mode");

    let poll_ctx = PollContext::new().map_err(Error::CreatePollContext)?;
    poll_ctx
        .add(&linux.exit_evt, Token::Exit)
        .map_err(Error::PollContextAdd)?;
    if let Err(e) = poll_ctx.add(&stdin_handle, Token::Stdin) {
        warn!("failed to add stdin to poll context: {}", e);
    }

    let mut vcpu_handles = Vec::with_capacity(linux.vcpus.len());
    let vcpu_thread_barrier = Arc::new(Barrier::new(linux.vcpus.len() + 1));
    let run_mode_arc = Arc::new(VcpuRunMode::default());
    for (cpu_id, vcpu) in linux.vcpus.into_iter().enumerate() {
        let handle = run_vcpu(
            vcpu,
            cpu_id as u32,
            linux.vcpu_affinity.clone(),
            vcpu_thread_barrier.clone(),
            linux.io_bus.clone(),
            linux.mmio_bus.clone(),
            linux.exit_evt.try_clone().map_err(Error::CloneEventFd)?,
            linux.vm.check_extension(Cap::KvmclockCtrl),
            run_mode_arc.clone(),
        )?;
        vcpu_handles.push(handle);
    }
    vcpu_thread_barrier.wait();

    'poll: loop {
        let events = {
            match poll_ctx.wait() {
                Ok(v) => v,
                Err(e) => {
                    error!("failed to poll: {}", e);
                    break;
                }
            }
        };

        let mut vm_control_indices_to_remove = Vec::new();
        for event in events.iter_readable() {
            match event.token() {
                Token::Exit => {
                    info!("vcpu requested shutdown");
                    break 'poll;
                }
                Token::Stdin => {
                    let mut out = [0u8; 64];
                    match stdin_lock.read_raw(&mut out[..]) {
                        Ok(0) => {
                            // Zero-length read indicates EOF. Remove from pollables.
                            let _ = poll_ctx.delete(&stdin_handle);
                        }
                        Err(e) => {
                            warn!("error while reading stdin: {}", e);
                            let _ = poll_ctx.delete(&stdin_handle);
                        }
                        Ok(count) => {
                            linux
                                .stdio_serial
                                .lock()
                                .queue_input_bytes(&out[..count])
                                .expect("failed to queue bytes into serial port");
                        }
                    }
                }
            }
        }

        for event in events.iter_hungup() {
            match event.token() {
                Token::Exit => {}
                Token::Stdin => {
                    let _ = poll_ctx.delete(&stdin_handle);
                }
            }
        }
    }

    // VCPU threads MUST see the VmRunMode flag, otherwise they may re-enter the VM.
    run_mode_arc.set_and_notify(VmRunMode::Exiting);
    for handle in vcpu_handles {
        match handle.kill(SIGRTMIN() + 0) {
            Ok(_) => {
                if let Err(e) = handle.join() {
                    error!("failed to join vcpu thread: {:?}", e);
                }
            }
            Err(e) => error!("failed to kill vcpu thread: {}", e),
        }
    }

    Ok(())
}
