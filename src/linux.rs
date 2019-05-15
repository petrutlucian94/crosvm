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
use std::os::unix::net::UnixStream;
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
use msg_socket::{MsgError, MsgReceiver, MsgSender, MsgSocket};
use net_util::{Error as NetError, MacAddress, Tap};
use qcow::{self, ImageType, QcowFile};
use rand_ish::SimpleRng;
use remain::sorted;
use sync::{Condvar, Mutex};
use sys_util::net::{UnixSeqpacket, UnixSeqpacketListener, UnlinkUnixSeqpacketListener};
use sys_util::{
    self, block_signal, clear_signal, drop_capabilities, error, flock, get_blocked_signals,
    get_group_id, get_user_id, info, register_signal_handler, set_cpu_affinity,
    warn, EventFd, FlockOperation, GuestMemory, Killable, PollContext, PollToken,
    SignalFd, Terminal, SIGRTMIN,
};
use vm_control::{
    BalloonControlCommand, BalloonControlRequestSocket, BalloonControlResponseSocket,
    DiskControlCommand, DiskControlRequestSocket, DiskControlResponseSocket, DiskControlResult,
    VmControlResponseSocket, VmRunMode
};

use crate::{Config, DiskOption, TouchDeviceOption};

use arch::{self, LinuxArch, RunnableLinuxVm, VirtioDeviceStub, VmComponents};

#[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
use aarch64::AArch64 as Arch;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use x86_64::X8664arch as Arch;

#[sorted]
#[derive(Debug)]
pub enum Error {
    BalloonDeviceNew(virtio::BalloonError),
    BlockDeviceNew(sys_util::Error),
    BlockSignal(sys_util::signal::Error),
    BuildVm(<Arch as LinuxArch>::Error),
    CloneEventFd(sys_util::Error),
    CreateEventFd(sys_util::Error),
    CreatePollContext(sys_util::Error),
    CreateSignalFd(sys_util::SignalFdError),
    CreateSocket(io::Error),
    CreateTapDevice(NetError),
    DetectImageType(qcow::Error),
    Disk(io::Error),
    DiskImageLock(sys_util::Error),
    DropCapabilities(sys_util::Error),
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
    RegisterBalloon(arch::DeviceRegistrationError),
    RegisterBlock(arch::DeviceRegistrationError),
    RegisterNet(arch::DeviceRegistrationError),
    RegisterRng(arch::DeviceRegistrationError),
    RegisterSignalHandler(sys_util::Error),
    ReserveMemory(sys_util::Error),
    RngDeviceNew(virtio::RngError),
    SignalFd(sys_util::SignalFdError),
    SpawnVcpu(io::Error),
    VirtioPciDev(sys_util::Error),
}

impl Display for Error {
    #[remain::check]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::Error::*;

        #[sorted]
        match self {
            BalloonDeviceNew(e) => write!(f, "failed to create balloon: {}", e),
            BlockDeviceNew(e) => write!(f, "failed to create block device: {}", e),
            BlockSignal(e) => write!(f, "failed to block signal: {}", e),
            BuildVm(e) => write!(f, "The architecture failed to build the vm: {}", e),
            CloneEventFd(e) => write!(f, "failed to clone eventfd: {}", e),
            CreateCrasClient(e) => write!(f, "failed to create cras client: {}", e),
            CreateEventFd(e) => write!(f, "failed to create eventfd: {}", e),
            CreatePollContext(e) => write!(f, "failed to create poll context: {}", e),
            CreateSignalFd(e) => write!(f, "failed to create signalfd: {}", e),
            CreateSocket(e) => write!(f, "failed to create socket: {}", e),
            CreateTapDevice(e) => write!(f, "failed to create tap device: {}", e),
            DetectImageType(e) => write!(f, "failed to detect disk image type: {}", e),
            DevicePivotRoot(e) => write!(f, "failed to pivot root device: {}", e),
            Disk(e) => write!(f, "failed to load disk image: {}", e),
            DiskImageLock(e) => write!(f, "failed to lock disk image: {}", e),
            DropCapabilities(e) => write!(f, "failed to drop process capabilities: {}", e),
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
            RegisterBalloon(e) => write!(f, "error registering balloon device: {}", e),
            RegisterBlock(e) => write!(f, "error registering block device: {}", e),
            RegisterNet(e) => write!(f, "error registering net device: {}", e),
            RegisterRng(e) => write!(f, "error registering rng device: {}", e),
            RegisterSignalHandler(e) => write!(f, "error registering signal handler: {}", e),
            ReserveMemory(e) => write!(f, "failed to reserve memory: {}", e),
            RngDeviceNew(e) => write!(f, "failed to set up rng: {}", e),
            SettingGidMap(e) => write!(f, "error setting GID map: {}", e),
            SettingUidMap(e) => write!(f, "error setting UID map: {}", e),
            SignalFd(e) => write!(f, "failed to read signal fd: {}", e),
            SpawnVcpu(e) => write!(f, "failed to spawn VCPU thread: {}", e),
            VirtioPciDev(e) => write!(f, "failed to create virtio pci dev: {}", e),
        }
    }
}

impl std::error::Error for Error {}

type Result<T> = std::result::Result<T, Error>;

// TODO(lpetrut): may no longer be needed as we drop wayland support.
enum TaggedControlSocket {
    Vm(VmControlResponseSocket),
}

impl AsRef<UnixSeqpacket> for TaggedControlSocket {
    fn as_ref(&self) -> &UnixSeqpacket {
        use self::TaggedControlSocket::*;
        match &self {
            Vm(ref socket) => socket,
        }
    }
}

impl AsRawFd for TaggedControlSocket {
    fn as_raw_fd(&self) -> RawFd {
        self.as_ref().as_raw_fd()
    }
}

type DeviceResult<T = VirtioDeviceStub> = std::result::Result<T, Error>;

fn create_block_device(
    cfg: &Config,
    disk: &DiskOption,
    disk_device_socket: DiskControlResponseSocket,
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
            let dev = virtio::Block::new(raw_image, disk.read_only, Some(disk_device_socket))
                .map_err(Error::BlockDeviceNew)?;
            Box::new(dev) as Box<dyn VirtioDevice>
        }
        ImageType::Qcow2 => {
            // Valid qcow header present
            let qcow_image = QcowFile::from(raw_image).map_err(Error::QcowDeviceCreate)?;
            let dev = virtio::Block::new(qcow_image, disk.read_only, Some(disk_device_socket))
                .map_err(Error::BlockDeviceNew)?;
            Box::new(dev) as Box<dyn VirtioDevice>
        }
    };

    Ok(VirtioDeviceStub {
        dev,
    })
}

fn create_rng_device(cfg: &Config) -> DeviceResult {
    let dev = virtio::Rng::new().map_err(Error::RngDeviceNew)?;

    Ok(VirtioDeviceStub {
        dev: Box::new(dev),
    })
}

fn create_single_touch_device(cfg: &Config, single_touch_spec: &TouchDeviceOption) -> DeviceResult {
    let socket = create_input_socket(&single_touch_spec.path).map_err(|e| {
        error!("failed configuring virtio single touch: {:?}", e);
        e
    })?;

    let dev = virtio::new_single_touch(socket, single_touch_spec.width, single_touch_spec.height)
        .map_err(Error::InputDeviceNew)?;
    Ok(VirtioDeviceStub {
        dev: Box::new(dev),
    })
}

fn create_trackpad_device(cfg: &Config, trackpad_spec: &TouchDeviceOption) -> DeviceResult {
    let socket = create_input_socket(&trackpad_spec.path).map_err(|e| {
        error!("failed configuring virtio trackpad: {}", e);
        e
    })?;

    let dev = virtio::new_trackpad(socket, trackpad_spec.width, trackpad_spec.height)
        .map_err(Error::InputDeviceNew)?;

    Ok(VirtioDeviceStub {
        dev: Box::new(dev),
    })
}

fn create_mouse_device(cfg: &Config, mouse_socket: &Path) -> DeviceResult {
    let socket = create_input_socket(&mouse_socket).map_err(|e| {
        error!("failed configuring virtio mouse: {}", e);
        e
    })?;

    let dev = virtio::new_mouse(socket).map_err(Error::InputDeviceNew)?;

    Ok(VirtioDeviceStub {
        dev: Box::new(dev),
    })
}

fn create_keyboard_device(cfg: &Config, keyboard_socket: &Path) -> DeviceResult {
    let socket = create_input_socket(&keyboard_socket).map_err(|e| {
        error!("failed configuring virtio keyboard: {}", e);
        e
    })?;

    let dev = virtio::new_keyboard(socket).map_err(Error::InputDeviceNew)?;

    Ok(VirtioDeviceStub {
        dev: Box::new(dev),
    })
}

fn create_vinput_device(cfg: &Config, dev_path: &Path) -> DeviceResult {
    let dev_file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(dev_path)
        .map_err(|e| Error::OpenVinput(dev_path.to_owned(), e))?;

    let dev = virtio::new_evdev(dev_file).map_err(Error::InputDeviceNew)?;

    Ok(VirtioDeviceStub {
        dev: Box::new(dev),
    })
}

fn create_balloon_device(cfg: &Config, socket: BalloonControlResponseSocket) -> DeviceResult {
    let dev = virtio::Balloon::new(socket).map_err(Error::BalloonDeviceNew)?;

    Ok(VirtioDeviceStub {
        dev: Box::new(dev),
    })
}

fn create_tap_net_device(cfg: &Config, tap_fd: RawFd) -> DeviceResult {
    // Safe because we ensure that we get a unique handle to the fd.
    let tap = unsafe {
        Tap::from_raw_fd(tap_fd).map_err(Error::CreateTapDevice)?
    };

    let dev = virtio::Net::from(tap).map_err(Error::NetDeviceNew)?;

    Ok(VirtioDeviceStub {
        dev: Box::new(dev),
    })
}

fn create_net_device(
    cfg: &Config,
    host_ip: Ipv4Addr,
    netmask: Ipv4Addr,
    mac_address: MacAddress,
    mem: &GuestMemory,
) -> DeviceResult {
    let dev = virtio::Net::<Tap>::new(host_ip, netmask, mac_address).map_err(Error::NetDeviceNew)?;

    Ok(VirtioDeviceStub {
        Box::new(dev) as Box<dyn VirtioDevice>,
    })
}

fn create_virtio_devices(
    cfg: &Config,
    mem: &GuestMemory,
    _exit_evt: &EventFd,
    balloon_device_socket: BalloonControlResponseSocket,
    disk_device_sockets: &mut Vec<DiskControlResponseSocket>,
) -> DeviceResult<Vec<VirtioDeviceStub>> {
    let mut devs = Vec::new();

    for disk in &cfg.disks {
        let disk_device_socket = disk_device_sockets.remove(0);
        devs.push(create_block_device(cfg, disk, disk_device_socket)?);
    }

    devs.push(create_rng_device(cfg)?);

    if let Some(single_touch_spec) = &cfg.virtio_single_touch {
        devs.push(create_single_touch_device(cfg, single_touch_spec)?);
    }

    if let Some(trackpad_spec) = &cfg.virtio_trackpad {
        devs.push(create_trackpad_device(cfg, trackpad_spec)?);
    }

    if let Some(mouse_socket) = &cfg.virtio_mouse {
        devs.push(create_mouse_device(cfg, mouse_socket)?);
    }

    if let Some(keyboard_socket) = &cfg.virtio_keyboard {
        devs.push(create_keyboard_device(cfg, keyboard_socket)?);
    }

    for dev_path in &cfg.virtio_input_evdevs {
        devs.push(create_vinput_device(cfg, dev_path)?);
    }

    devs.push(create_balloon_device(cfg, balloon_device_socket)?);

    // We checked above that if the IP is defined, then the netmask is, too.
    for tap_fd in &cfg.tap_fd {
        devs.push(create_tap_net_device(cfg, *tap_fd)?);
    }

    if let (Some(host_ip), Some(netmask), Some(mac_address)) =
        (cfg.host_ip, cfg.netmask, cfg.mac_address)
    {
        devs.push(create_net_device(cfg, host_ip, netmask, mac_address, mem)?);
    }

    Ok(devs)
}

fn create_devices(
    cfg: Config,
    mem: &GuestMemory,
    exit_evt: &EventFd,
    balloon_device_socket: BalloonControlResponseSocket,
    disk_device_sockets: &mut Vec<DiskControlResponseSocket>,
) -> DeviceResult<Vec<(Box<dyn PciDevice>)>> {
    let stubs = create_virtio_devices(
        &cfg,
        mem,
        exit_evt,
        balloon_device_socket,
        disk_device_sockets,
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

fn create_input_socket(path: &Path) -> Result<UnixStream> {
    if path.parent() == Some(Path::new("/proc/self/fd")) {
        // Safe because we will validate |raw_fd|.
        unsafe { Ok(UnixStream::from_raw_fd(raw_fd_from_path(path)?)) }
    } else {
        UnixStream::connect(path).map_err(Error::InputEventsOpen)
    }
}

fn setup_vcpu_signal_handler() -> Result<()> {
    unsafe {
        extern "C" fn handle_signal() {}
        // Our signal handler does nothing and is trivially async signal safe.
        register_signal_handler(SIGRTMIN() + 0, handle_signal)
            .map_err(Error::RegisterSignalHandler)?;
    }
    block_signal(SIGRTMIN() + 0).map_err(Error::BlockSignal)?;
    Ok(())
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
            if vcpu_affinity.len() != 0 {
                if let Err(e) = set_cpu_affinity(vcpu_affinity) {
                    error!("Failed to set CPU affinity: {}", e);
                }
            }

            let mut sig_ok = true;
            match get_blocked_signals() {
                Ok(mut v) => {
                    v.retain(|&x| x != SIGRTMIN() + 0);
                    if let Err(e) = vcpu.set_signal_mask(&v) {
                        error!(
                            "Failed to set the KVM_SIGNAL_MASK for vcpu {} : {}",
                            cpu_id, e
                        );
                        sig_ok = false;
                    }
                }
                Err(e) => {
                    error!(
                        "Failed to retrieve signal mask for vcpu {} : {}",
                        cpu_id, e
                    );
                    sig_ok = false;
                }
            };

            start_barrier.wait();

            if sig_ok {
                'vcpu_loop: loop {
                    let mut interrupted_by_signal = false;
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
                            libc::EINTR => interrupted_by_signal = true,
                            libc::EAGAIN => {}
                            _ => {
                                error!("vcpu hit unknown error: {}", e);
                                break;
                            }
                        },
                    }

                    if interrupted_by_signal {
                        // Try to clear the signal that we use to kick VCPU if it is pending before
                        // attempting to handle pause requests.
                        if let Err(e) = clear_signal(SIGRTMIN() + 0) {
                            error!("failed to clear pending signal: {}", e);
                            break;
                        }
                        let mut run_mode_lock = run_mode_arc.mtx.lock();
                        loop {
                            match *run_mode_lock {
                                VmRunMode::Running => break,
                                VmRunMode::Suspending => {
                                    // On KVM implementations that use a paravirtualized clock (e.g.
                                    // x86), a flag must be set to indicate to the guest kernel that
                                    // a VCPU was suspended. The guest kernel will use this flag to
                                    // prevent the soft lockup detection from triggering when this
                                    // VCPU resumes, which could happen days later in realtime.
                                    if requires_kvmclock_ctrl {
                                        if let Err(e) = vcpu.kvmclock_ctrl() {
                                            error!("failed to signal to kvm that vcpu {} is being suspended: {}", cpu_id, e);
                                        }
                                    }
                                }
                                VmRunMode::Exiting => break 'vcpu_loop,
                            }
                            // Give ownership of our exclusive lock to the condition variable that
                            // will block. When the condition variable is notified, `wait` will
                            // unblock and return a new exclusive lock.
                            run_mode_lock = run_mode_arc.cvar.wait(run_mode_lock);
                        }
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
    // Masking signals is inherently dangerous, since this can persist across clones/execs. Do this
    // before any jailed devices have been spawned, so that we can catch any of them that fail very
    // quickly.
    let sigchld_fd = SignalFd::new(libc::SIGCHLD).map_err(Error::CreateSignalFd)?;

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

    let control_server_socket = match &cfg.socket_path {
        Some(path) => Some(UnlinkUnixSeqpacketListener(
            UnixSeqpacketListener::bind(path).map_err(Error::CreateSocket)?,
        )),
        None => None,
    };

    let mut control_sockets = Vec::new();
    // Balloon gets a special socket so balloon requests can be forwarded from the main process.
    let (balloon_host_socket, balloon_device_socket) =
        msg_socket::pair::<BalloonControlCommand, ()>().map_err(Error::CreateSocket)?;

    // Create one control socket per disk.
    let mut disk_device_sockets = Vec::new();
    let mut disk_host_sockets = Vec::new();
    let disk_count = cfg.disks.len();
    for _ in 0..disk_count {
        let (disk_host_socket, disk_device_socket) =
            msg_socket::pair::<DiskControlCommand, DiskControlResult>()
                .map_err(Error::CreateSocket)?;
        disk_host_sockets.push(disk_host_socket);
        disk_device_sockets.push(disk_device_socket);
    }

    let sandbox = cfg.sandbox;
    let linux = Arch::build_vm(components, cfg.split_irqchip, |m, e| {
        create_devices(
            cfg,
            m,
            e,
            balloon_device_socket,
            &mut disk_device_sockets
        )
    })
    .map_err(Error::BuildVm)?;

    run_control(
        linux,
        control_server_socket,
        control_sockets,
        balloon_host_socket,
        &disk_host_sockets,
        sigchld_fd,
        sandbox,
    )
}

fn run_control(
    mut linux: RunnableLinuxVm,
    control_server_socket: Option<UnlinkUnixSeqpacketListener>,
    mut control_sockets: Vec<TaggedControlSocket>,
    balloon_host_socket: BalloonControlRequestSocket,
    disk_host_sockets: &[DiskControlRequestSocket],
    sigchld_fd: SignalFd,
    sandbox: bool,
) -> Result<()> {
    // Paths to get the currently available memory and the low memory threshold.
    const LOWMEM_MARGIN: &str = "/sys/kernel/mm/chromeos-low_mem/margin";
    const LOWMEM_AVAILABLE: &str = "/sys/kernel/mm/chromeos-low_mem/available";

    // The amount of additional memory to claim back from the VM whenever the system is
    // low on memory.
    const ONE_GB: u64 = (1 << 30);

    let max_balloon_memory = match linux.vm.get_memory().memory_size() {
        // If the VM has at least 1.5 GB, the balloon driver can consume all but the last 1 GB.
        n if n >= (ONE_GB / 2) * 3 => n - ONE_GB,
        // Otherwise, if the VM has at least 500MB the balloon driver will consume at most
        // half of it.
        n if n >= (ONE_GB / 2) => n / 2,
        // Otherwise, the VM is too small for us to take memory away from it.
        _ => 0,
    };
    let mut current_balloon_memory: u64 = 0;
    let balloon_memory_increment: u64 = max_balloon_memory / 16;

    #[derive(PollToken)]
    enum Token {
        Exit,
        Stdin,
        ChildSignal,
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
    poll_ctx
        .add(&sigchld_fd, Token::ChildSignal)
        .map_err(Error::PollContextAdd)?;

    if let Some(socket_server) = &control_server_socket {
        poll_ctx
            .add(socket_server, Token::VmControlServer)
            .map_err(Error::PollContextAdd)?;
    }
    for (index, socket) in control_sockets.iter().enumerate() {
        poll_ctx
            .add(socket.as_ref(), Token::VmControl { index })
            .map_err(Error::PollContextAdd)?;
    }

    // Watch for low memory notifications and take memory back from the VM.
    let low_mem = File::open("/dev/chromeos-low-mem").ok();
    if let Some(low_mem) = &low_mem {
        poll_ctx
            .add(low_mem, Token::LowMemory)
            .map_err(Error::PollContextAdd)?;
    } else {
        warn!("Unable to open low mem indicator, maybe not a chrome os kernel");
    }

    // Used to add jitter to timer values so that we don't have a thundering herd problem when
    // multiple VMs are running.
    let mut simple_rng = SimpleRng::new(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time went backwards")
            .subsec_nanos() as u64,
    );

    if sandbox {
        // Before starting VCPUs, in case we started with some capabilities, drop them all.
        drop_capabilities().map_err(Error::DropCapabilities)?;
    }

    let mut vcpu_handles = Vec::with_capacity(linux.vcpus.len());
    let vcpu_thread_barrier = Arc::new(Barrier::new(linux.vcpus.len() + 1));
    let run_mode_arc = Arc::new(VcpuRunMode::default());
    setup_vcpu_signal_handler()?;
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
                Token::ChildSignal => {
                    // Print all available siginfo structs, then exit the loop.
                    while let Some(siginfo) = sigchld_fd.read().map_err(Error::SignalFd)? {
                        let pid = siginfo.ssi_pid;
                        let pid_label = match linux.pid_debug_label_map.get(&pid) {
                            Some(label) => format!("{} (pid {})", label, pid),
                            None => format!("pid {}", pid),
                        };
                        error!(
                            "child {} died: signo {}, status {}, code {}",
                            pid_label, siginfo.ssi_signo, siginfo.ssi_status, siginfo.ssi_code
                        );
                    }
                    break 'poll;
                }
                Token::VmControlServer => {
                    if let Some(socket_server) = &control_server_socket {
                        match socket_server.accept() {
                            Ok(socket) => {
                                poll_ctx
                                    .add(
                                        &socket,
                                        Token::VmControl {
                                            index: control_sockets.len(),
                                        },
                                    )
                                    .map_err(Error::PollContextAdd)?;
                                control_sockets
                                    .push(TaggedControlSocket::Vm(MsgSocket::new(socket)));
                            }
                            Err(e) => error!("failed to accept socket: {}", e),
                        }
                    }
                }
                Token::VmControl { index } => {
                    if let Some(socket) = control_sockets.get(index) {
                        match socket {
                            TaggedControlSocket::Vm(socket) => match socket.recv() {
                                Ok(request) => {
                                    let mut run_mode_opt = None;
                                    let response = request.execute(
                                        &mut run_mode_opt,
                                        &balloon_host_socket,
                                        disk_host_sockets,
                                    );
                                    if let Err(e) = socket.send(&response) {
                                        error!("failed to send VmResponse: {}", e);
                                    }
                                    if let Some(run_mode) = run_mode_opt {
                                        info!("control socket changed run mode to {}", run_mode);
                                        match run_mode {
                                            VmRunMode::Exiting => {
                                                break 'poll;
                                            }
                                            other => {
                                                run_mode_arc.set_and_notify(other);
                                                for handle in &vcpu_handles {
                                                    let _ = handle.kill(SIGRTMIN() + 0);
                                                }
                                            }
                                        }
                                    }
                                }
                                Err(e) => {
                                    if let MsgError::BadRecvSize { actual: 0, .. } = e {
                                        vm_control_indices_to_remove.push(index);
                                    } else {
                                        error!("failed to recv VmRequest: {}", e);
                                    }
                                }
                            },
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
                Token::ChildSignal => {}
                Token::CheckAvailableMemory => {}
                Token::LowMemory => {}
                Token::LowmemTimer => {}
                Token::VmControlServer => {}
                Token::VmControl { index } => {
                    // It's possible more data is readable and buffered while the socket is hungup,
                    // so don't delete the socket from the poll context until we're sure all the
                    // data is read.
                    match control_sockets
                        .get(index)
                        .map(|s| s.as_ref().get_readable_bytes())
                    {
                        Some(Ok(0)) | Some(Err(_)) => vm_control_indices_to_remove.push(index),
                        Some(Ok(x)) => info!("control index {} has {} bytes readable", index, x),
                        _ => {}
                    }
                }
            }
        }

        // Sort in reverse so the highest indexes are removed first. This removal algorithm
        // preserved correct indexes as each element is removed.
        vm_control_indices_to_remove.sort_unstable_by(|a, b| b.cmp(a));
        vm_control_indices_to_remove.dedup();
        for index in vm_control_indices_to_remove {
            control_sockets.swap_remove(index);
            if let Some(socket) = control_sockets.get(index) {
                poll_ctx
                    .add(socket, Token::VmControl { index })
                    .map_err(Error::PollContextAdd)?;
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
