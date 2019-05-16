// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Runs a virtual machine under KVM

pub mod argument;
pub mod linux;
pub mod panic_hook;

use std::fmt;
use std::fs::{File, OpenOptions};
use std::net;
use std::num::ParseIntError;
use std::os::unix::io::{FromRawFd, RawFd};
use std::path::{Path, PathBuf};
use std::string::String;
use std::thread::sleep;
use std::time::Duration;

use qcow::QcowFile;
use sys_util::{
    debug, error, getpid, info, kill_process_group, net::UnixSeqpacket, reap_child, warn,
};
use vm_control::{
    BalloonControlCommand, DiskControlCommand, MaybeOwnedFd,
    VmControlRequestSocket, VmRequest, VmResponse,
};

use crate::argument::{print_help, set_arguments, Argument};

struct DiskOption {
    path: PathBuf,
    read_only: bool,
}

#[allow(dead_code)]
struct BindMount {
    src: PathBuf,
    dst: PathBuf,
    writable: bool,
}

#[allow(dead_code)]
struct GidMap {
    inner: libc::gid_t,
    outer: libc::gid_t,
    count: u32,
}

const DEFAULT_TOUCH_DEVICE_WIDTH: u32 = 800;
const DEFAULT_TOUCH_DEVICE_HEIGHT: u32 = 1280;

struct TouchDeviceOption {
    path: PathBuf,
    width: u32,
    height: u32,
}

impl TouchDeviceOption {
    fn new(path: PathBuf) -> TouchDeviceOption {
        TouchDeviceOption {
            path,
            width: DEFAULT_TOUCH_DEVICE_WIDTH,
            height: DEFAULT_TOUCH_DEVICE_HEIGHT,
        }
    }
}

pub struct Config {
    vcpu_count: Option<u32>,
    vcpu_affinity: Vec<usize>,
    memory: Option<usize>,
    kernel_path: PathBuf,
    android_fstab: Option<PathBuf>,
    initrd_path: Option<PathBuf>,
    params: Vec<String>,
    socket_path: Option<PathBuf>,
    disks: Vec<DiskOption>,
    host_ip: Option<net::Ipv4Addr>,
    netmask: Option<net::Ipv4Addr>,
    mac_address: Option<net_util::MacAddress>,
    tap_fd: Vec<RawFd>,
    cid: Option<u64>,
    shared_dirs: Vec<(PathBuf, String)>,
    sandbox: bool,
    virtio_single_touch: Option<TouchDeviceOption>,
    virtio_trackpad: Option<TouchDeviceOption>,
    virtio_mouse: Option<PathBuf>,
    virtio_keyboard: Option<PathBuf>,
    virtio_input_evdevs: Vec<PathBuf>,
    split_irqchip: bool,
}

impl Default for Config {
    fn default() -> Config {
        Config {
            vcpu_count: None,
            vcpu_affinity: Vec::new(),
            memory: None,
            kernel_path: PathBuf::default(),
            android_fstab: None,
            initrd_path: None,
            params: Vec::new(),
            socket_path: None,
            disks: Vec::new(),
            host_ip: None,
            netmask: None,
            mac_address: None,
            tap_fd: Vec::new(),
            cid: None,
            shared_dirs: Vec::new(),
            sandbox: !cfg!(feature = "default-no-sandbox"),
            virtio_single_touch: None,
            virtio_trackpad: None,
            virtio_mouse: None,
            virtio_keyboard: None,
            virtio_input_evdevs: Vec::new(),
            split_irqchip: false,
        }
    }
}


/// Parse a comma-separated list of CPU numbers and ranges and convert it to a Vec of CPU numbers.
fn parse_cpu_set(s: &str) -> argument::Result<Vec<usize>> {
    let mut cpuset = Vec::new();
    for part in s.split(',') {
        let range: Vec<&str> = part.split('-').collect();
        if range.len() == 0 || range.len() > 2 {
            return Err(argument::Error::InvalidValue {
                value: part.to_owned(),
                expected: "invalid list syntax",
            });
        }
        let first_cpu: usize = range[0]
            .parse()
            .map_err(|_| argument::Error::InvalidValue {
                value: part.to_owned(),
                expected: "CPU index must be a non-negative integer",
            })?;
        let last_cpu: usize = if range.len() == 2 {
            range[1]
                .parse()
                .map_err(|_| argument::Error::InvalidValue {
                    value: part.to_owned(),
                    expected: "CPU index must be a non-negative integer",
                })?
        } else {
            first_cpu
        };

        if last_cpu < first_cpu {
            return Err(argument::Error::InvalidValue {
                value: part.to_owned(),
                expected: "CPU ranges must be from low to high",
            });
        }

        for cpu in first_cpu..=last_cpu {
            cpuset.push(cpu);
        }
    }
    Ok(cpuset)
}

fn set_argument(cfg: &mut Config, name: &str, value: Option<&str>) -> argument::Result<()> {
    match name {
        "" => {
            if !cfg.kernel_path.as_os_str().is_empty() {
                return Err(argument::Error::TooManyArguments(
                    "expected exactly one kernel path".to_owned(),
                ));
            } else {
                let kernel_path = PathBuf::from(value.unwrap());
                if !kernel_path.exists() {
                    return Err(argument::Error::InvalidValue {
                        value: value.unwrap().to_owned(),
                        expected: "this kernel path does not exist",
                    });
                }
                cfg.kernel_path = kernel_path;
            }
        }
        "android-fstab" => {
            if cfg.android_fstab.is_some()
                && !cfg.android_fstab.as_ref().unwrap().as_os_str().is_empty()
            {
                return Err(argument::Error::TooManyArguments(
                    "expected exactly one android fstab path".to_owned(),
                ));
            } else {
                let android_fstab = PathBuf::from(value.unwrap());
                if !android_fstab.exists() {
                    return Err(argument::Error::InvalidValue {
                        value: value.unwrap().to_owned(),
                        expected: "this android fstab path does not exist",
                    });
                }
                cfg.android_fstab = Some(android_fstab);
            }
        }
        "params" => {
            cfg.params.push(value.unwrap().to_owned());
        }
        "cpus" => {
            if cfg.vcpu_count.is_some() {
                return Err(argument::Error::TooManyArguments(
                    "`cpus` already given".to_owned(),
                ));
            }
            cfg.vcpu_count =
                Some(
                    value
                        .unwrap()
                        .parse()
                        .map_err(|_| argument::Error::InvalidValue {
                            value: value.unwrap().to_owned(),
                            expected: "this value for `cpus` needs to be integer",
                        })?,
                )
        }
        "cpu-affinity" => {
            if cfg.vcpu_affinity.len() != 0 {
                return Err(argument::Error::TooManyArguments(
                    "`cpu-affinity` already given".to_owned(),
                ));
            }
            cfg.vcpu_affinity = parse_cpu_set(value.unwrap())?;
        }
        "mem" => {
            if cfg.memory.is_some() {
                return Err(argument::Error::TooManyArguments(
                    "`mem` already given".to_owned(),
                ));
            }
            cfg.memory =
                Some(
                    value
                        .unwrap()
                        .parse()
                        .map_err(|_| argument::Error::InvalidValue {
                            value: value.unwrap().to_owned(),
                            expected: "this value for `mem` needs to be integer",
                        })?,
                )
        }
        "root" | "disk" | "rwdisk" | "qcow" | "rwqcow" => {
            let disk_path = PathBuf::from(value.unwrap());
            if !disk_path.exists() {
                return Err(argument::Error::InvalidValue {
                    value: value.unwrap().to_owned(),
                    expected: "this disk path does not exist",
                });
            }
            if name == "root" {
                if cfg.disks.len() >= 26 {
                    return Err(argument::Error::TooManyArguments(
                        "ran out of letters for to assign to root disk".to_owned(),
                    ));
                }
                cfg.params.push(format!(
                    "root=/dev/vd{} ro",
                    char::from(b'a' + cfg.disks.len() as u8)
                ));
            }
            cfg.disks.push(DiskOption {
                path: disk_path,
                read_only: !name.starts_with("rw"),
            });
        }
        "host_ip" => {
            if cfg.host_ip.is_some() {
                return Err(argument::Error::TooManyArguments(
                    "`host_ip` already given".to_owned(),
                ));
            }
            cfg.host_ip =
                Some(
                    value
                        .unwrap()
                        .parse()
                        .map_err(|_| argument::Error::InvalidValue {
                            value: value.unwrap().to_owned(),
                            expected: "`host_ip` needs to be in the form \"x.x.x.x\"",
                        })?,
                )
        }
        "netmask" => {
            if cfg.netmask.is_some() {
                return Err(argument::Error::TooManyArguments(
                    "`netmask` already given".to_owned(),
                ));
            }
            cfg.netmask =
                Some(
                    value
                        .unwrap()
                        .parse()
                        .map_err(|_| argument::Error::InvalidValue {
                            value: value.unwrap().to_owned(),
                            expected: "`netmask` needs to be in the form \"x.x.x.x\"",
                        })?,
                )
        }
        "mac" => {
            if cfg.mac_address.is_some() {
                return Err(argument::Error::TooManyArguments(
                    "`mac` already given".to_owned(),
                ));
            }
            cfg.mac_address =
                Some(
                    value
                        .unwrap()
                        .parse()
                        .map_err(|_| argument::Error::InvalidValue {
                            value: value.unwrap().to_owned(),
                            expected: "`mac` needs to be in the form \"XX:XX:XX:XX:XX:XX\"",
                        })?,
                )
        }
        "socket" => {
            if cfg.socket_path.is_some() {
                return Err(argument::Error::TooManyArguments(
                    "`socket` already given".to_owned(),
                ));
            }
            let mut socket_path = PathBuf::from(value.unwrap());
            if socket_path.is_dir() {
                socket_path.push(format!("crosvm-{}.sock", getpid()));
            }
            if socket_path.exists() {
                return Err(argument::Error::InvalidValue {
                    value: socket_path.to_string_lossy().into_owned(),
                    expected: "this socket path already exists",
                });
            }
            cfg.socket_path = Some(socket_path);
        }
        "disable-sandbox" => {
            cfg.sandbox = false;
        }
        "cid" => {
            if cfg.cid.is_some() {
                return Err(argument::Error::TooManyArguments(
                    "`cid` alread given".to_owned(),
                ));
            }
            cfg.cid = Some(
                value
                    .unwrap()
                    .parse()
                    .map_err(|_| argument::Error::InvalidValue {
                        value: value.unwrap().to_owned(),
                        expected: "this value for `cid` must be an unsigned integer",
                    })?,
            );
        }
        "shared-dir" => {
            // Formatted as <src:tag>.
            let param = value.unwrap();
            let mut components = param.splitn(2, ':');
            let src =
                PathBuf::from(
                    components
                        .next()
                        .ok_or_else(|| argument::Error::InvalidValue {
                            value: param.to_owned(),
                            expected: "missing source path for `shared-dir`",
                        })?,
                );
            let tag = components
                .next()
                .ok_or_else(|| argument::Error::InvalidValue {
                    value: param.to_owned(),
                    expected: "missing tag for `shared-dir`",
                })?
                .to_owned();

            if !src.is_dir() {
                return Err(argument::Error::InvalidValue {
                    value: param.to_owned(),
                    expected: "source path for `shared-dir` must be a directory",
                });
            }

            cfg.shared_dirs.push((src, tag));
        }
        "tap-fd" => {
            cfg.tap_fd.push(
                value
                    .unwrap()
                    .parse()
                    .map_err(|_| argument::Error::InvalidValue {
                        value: value.unwrap().to_owned(),
                        expected: "this value for `tap-fd` must be an unsigned integer",
                    })?,
            );
        }
        "single-touch" => {
            if cfg.virtio_single_touch.is_some() {
                return Err(argument::Error::TooManyArguments(
                    "`single-touch` already given".to_owned(),
                ));
            }
            let mut it = value.unwrap().split(":");

            let mut single_touch_spec =
                TouchDeviceOption::new(PathBuf::from(it.next().unwrap().to_owned()));
            if let Some(width) = it.next() {
                single_touch_spec.width = width.trim().parse().unwrap();
            }
            if let Some(height) = it.next() {
                single_touch_spec.height = height.trim().parse().unwrap();
            }

            cfg.virtio_single_touch = Some(single_touch_spec);
        }
        "trackpad" => {
            if cfg.virtio_trackpad.is_some() {
                return Err(argument::Error::TooManyArguments(
                    "`trackpad` already given".to_owned(),
                ));
            }
            let mut it = value.unwrap().split(":");

            let mut trackpad_spec =
                TouchDeviceOption::new(PathBuf::from(it.next().unwrap().to_owned()));
            if let Some(width) = it.next() {
                trackpad_spec.width = width.trim().parse().unwrap();
            }
            if let Some(height) = it.next() {
                trackpad_spec.height = height.trim().parse().unwrap();
            }

            cfg.virtio_trackpad = Some(trackpad_spec);
        }
        "mouse" => {
            if cfg.virtio_mouse.is_some() {
                return Err(argument::Error::TooManyArguments(
                    "`mouse` already given".to_owned(),
                ));
            }
            cfg.virtio_mouse = Some(PathBuf::from(value.unwrap().to_owned()));
        }
        "keyboard" => {
            if cfg.virtio_keyboard.is_some() {
                return Err(argument::Error::TooManyArguments(
                    "`keyboard` already given".to_owned(),
                ));
            }
            cfg.virtio_keyboard = Some(PathBuf::from(value.unwrap().to_owned()));
        }
        "evdev" => {
            let dev_path = PathBuf::from(value.unwrap());
            if !dev_path.exists() {
                return Err(argument::Error::InvalidValue {
                    value: value.unwrap().to_owned(),
                    expected: "this input device path does not exist",
                });
            }
            cfg.virtio_input_evdevs.push(dev_path);
        }
        "split-irqchip" => {
            cfg.split_irqchip = true;
        }
        "initrd" => {
            cfg.initrd_path = Some(PathBuf::from(value.unwrap().to_owned()));
        }
        "help" => return Err(argument::Error::PrintHelp),
        _ => unreachable!(),
    }
    Ok(())
}

fn run_vm(args: std::env::Args) -> std::result::Result<(), ()> {
    let arguments =
        &[Argument::positional("KERNEL", "bzImage of kernel to run"),
          Argument::value("android-fstab", "PATH", "Path to Android fstab"),
          Argument::short_value('i', "initrd", "PATH", "Initial ramdisk to load."),
          Argument::short_value('p',
                                "params",
                                "PARAMS",
                                "Extra kernel or plugin command line arguments. Can be given more than once."),
          Argument::short_value('c', "cpus", "N", "Number of VCPUs. (default: 1)"),
          Argument::value("cpu-affinity", "CPUSET", "Comma-separated list of CPUs or CPU ranges to run VCPUs on. (e.g. 0,1-3,5) (default: no mask)"),
          Argument::short_value('m',
                                "mem",
                                "N",
                                "Amount of guest memory in MiB. (default: 256)"),
          Argument::short_value('r',
                                "root",
                                "PATH",
                                "Path to a root disk image. Like `--disk` but adds appropriate kernel command line option."),
          Argument::short_value('d', "disk", "PATH", "Path to a disk image."),
          Argument::value("qcow", "PATH", "Path to a qcow2 disk image. (Deprecated; use --disk instead.)"),
          Argument::value("rwdisk", "PATH", "Path to a writable disk image."),
          Argument::value("rwqcow", "PATH", "Path to a writable qcow2 disk image. (Deprecated; use --rwdisk instead.)"),
          Argument::value("host_ip",
                          "IP",
                          "IP address to assign to host tap interface."),
          Argument::value("netmask", "NETMASK", "Netmask for VM subnet."),
          Argument::value("mac", "MAC", "MAC address for VM."),
          Argument::short_value('s',
                                "socket",
                                "PATH",
                                "Path to put the control socket. If PATH is a directory, a name will be generated."),
          Argument::flag("disable-sandbox", "Run all devices in one, non-sandboxed process."),
          Argument::value("cid", "CID", "Context ID for virtual sockets."),
          Argument::value("shared-dir", "PATH:TAG",
                          "Directory to be shared with a VM as a source:tag pair. Can be given more than once."),
          Argument::value("evdev", "PATH", "Path to an event device node. The device will be grabbed (unusable from the host) and made available to the guest with the same configuration it shows on the host"),
          Argument::value("single-touch", "PATH:WIDTH:HEIGHT", "Path to a socket from where to read single touch input events (such as those from a touchscreen) and write status updates to, optionally followed by width and height (defaults to 800x1280)."),
          Argument::value("trackpad", "PATH:WIDTH:HEIGHT", "Path to a socket from where to read trackpad input events and write status updates to, optionally followed by screen width and height (defaults to 800x1280)."),
          Argument::value("mouse", "PATH", "Path to a socket from where to read mouse input events and write status updates to."),
          Argument::value("keyboard", "PATH", "Path to a socket from where to read keyboard input events and write status updates to."),
          #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
          Argument::flag("split-irqchip", "(EXPERIMENTAL) enable split-irqchip support"),
          Argument::short_flag('h', "help", "Print help message.")];

    let mut cfg = Config::default();
    let match_res = set_arguments(args, &arguments[..], |name, value| {
        set_argument(&mut cfg, name, value)
    })
    .and_then(|_| {
        if cfg.kernel_path.as_os_str().is_empty() {
            return Err(argument::Error::ExpectedArgument("`KERNEL`".to_owned()));
        }
        if cfg.host_ip.is_some() || cfg.netmask.is_some() || cfg.mac_address.is_some() {
            if cfg.host_ip.is_none() {
                return Err(argument::Error::ExpectedArgument(
                    "`host_ip` missing from network config".to_owned(),
                ));
            }
            if cfg.netmask.is_none() {
                return Err(argument::Error::ExpectedArgument(
                    "`netmask` missing from network config".to_owned(),
                ));
            }
            if cfg.mac_address.is_none() {
                return Err(argument::Error::ExpectedArgument(
                    "`mac` missing from network config".to_owned(),
                ));
            }
        }
        Ok(())
    });

    match match_res {
        Ok(()) => match linux::run_config(cfg) {
            Ok(_) => {
                info!("crosvm has exited normally");
                Ok(())
            }
            Err(e) => {
                error!("{}", e);
                Err(())
            }
        },
        Err(argument::Error::PrintHelp) => {
            print_help("crosvm run", "KERNEL", &arguments[..]);
            Ok(())
        }
        Err(e) => {
            println!("{}", e);
            Err(())
        }
    }
}

fn create_qcow2(mut args: std::env::Args) -> std::result::Result<(), ()> {
    if args.len() != 2 {
        print_help("crosvm create_qcow2", "PATH SIZE", &[]);
        println!("Create a new QCOW2 image at `PATH` of the specified `SIZE` in bytes.");
        return Err(());
    }
    let file_path = args.nth(0).unwrap();
    let size: u64 = match args.nth(0).unwrap().parse::<u64>() {
        Ok(n) => n,
        Err(_) => {
            error!("Failed to parse size of the disk.");
            return Err(());
        }
    };

    let file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .open(&file_path)
        .map_err(|e| {
            error!("Failed opening qcow file at '{}': {}", file_path, e);
        })?;

    QcowFile::new(file, size).map_err(|e| {
        error!("Failed to create qcow file at '{}': {}", file_path, e);
    })?;

    Ok(())
}

fn disk_cmd(mut args: std::env::Args) -> std::result::Result<(), ()> {
    if args.len() < 2 {
        print_help("crosvm disk", "SUBCOMMAND VM_SOCKET...", &[]);
        println!("Manage attached virtual disk devices.");
        println!("Subcommands:");
        println!("  resize DISK_INDEX NEW_SIZE VM_SOCKET");
        return Err(());
    }
    let subcommand: &str = &args.nth(0).unwrap();

    let request = match subcommand {
        "resize" => {
            let disk_index = match args.nth(0).unwrap().parse::<usize>() {
                Ok(n) => n,
                Err(_) => {
                    error!("Failed to parse disk index");
                    return Err(());
                }
            };

            let new_size = match args.nth(0).unwrap().parse::<u64>() {
                Ok(n) => n,
                Err(_) => {
                    error!("Failed to parse disk size");
                    return Err(());
                }
            };

            VmRequest::DiskCommand {
                disk_index,
                command: DiskControlCommand::Resize { new_size },
            }
        }
        _ => {
            error!("Unknown disk subcommand '{}'", subcommand);
            return Err(());
        }
    };

    vms_request(&request, args)
}

fn print_usage() {
    print_help("crosvm", "[stop|run]", &[]);
    println!("Commands:");
    println!("    stop - Stops crosvm instances via their control sockets.");
    println!("    run  - Start a new crosvm instance.");
    println!("    create_qcow2  - Create a new qcow2 disk image file.");
    println!("    disk - Manage attached virtual disk devices.");
}

fn crosvm_main() -> std::result::Result<(), ()> {
    panic_hook::set_panic_hook();

    let mut args = std::env::args();
    if args.next().is_none() {
        error!("expected executable name");
        return Err(());
    }

    // Past this point, usage of exit is in danger of leaking zombie processes.
    let ret = match args.next().as_ref().map(|a| a.as_ref()) {
        None => {
            print_usage();
            Ok(())
        }
        Some("run") => run_vm(args),
        Some("create_qcow2") => create_qcow2(args),
        Some("disk") => disk_cmd(args),
        Some(c) => {
            println!("invalid subcommand: {:?}", c);
            print_usage();
            Err(())
        }
    };

    // TODO(lpetrut): are there any subprocesses that we should wait for?

    // WARNING: Any code added after this point is not guaranteed to run
    // since we may forcibly kill this process (and its children) above.
    ret
}

fn main() {
    std::process::exit(if crosvm_main().is_ok() { 0 } else { 1 });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_cpu_set_single() {
        assert_eq!(parse_cpu_set("123").expect("parse failed"), vec![123]);
    }

    #[test]
    fn parse_cpu_set_list() {
        assert_eq!(
            parse_cpu_set("0,1,2,3").expect("parse failed"),
            vec![0, 1, 2, 3]
        );
    }

    #[test]
    fn parse_cpu_set_range() {
        assert_eq!(
            parse_cpu_set("0-3").expect("parse failed"),
            vec![0, 1, 2, 3]
        );
    }

    #[test]
    fn parse_cpu_set_list_of_ranges() {
        assert_eq!(
            parse_cpu_set("3-4,7-9,18").expect("parse failed"),
            vec![3, 4, 7, 8, 9, 18]
        );
    }

    #[test]
    fn parse_cpu_set_repeated() {
        // For now, allow duplicates - they will be handled gracefully by the vec to cpu_set_t conversion.
        assert_eq!(parse_cpu_set("1,1,1").expect("parse failed"), vec![1, 1, 1]);
    }

    #[test]
    fn parse_cpu_set_negative() {
        // Negative CPU numbers are not allowed.
        parse_cpu_set("-3").expect_err("parse should have failed");
    }

    #[test]
    fn parse_cpu_set_reverse_range() {
        // Ranges must be from low to high.
        parse_cpu_set("5-2").expect_err("parse should have failed");
    }

    #[test]
    fn parse_cpu_set_open_range() {
        parse_cpu_set("3-").expect_err("parse should have failed");
    }

    #[test]
    fn parse_cpu_set_extra_comma() {
        parse_cpu_set("0,1,2,").expect_err("parse should have failed");
    }
}
