// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Facilities for sending log message to syslog.
//!
//! Every function exported by this module is thread-safe. Each function will silently fail until
//! `syslog::init()` is called and returns `Ok`.
//!
//! # Examples
//!
//! ```
//! use sys_util::{error, syslog, warn};
//!
//! fn main() {
//!     if let Err(e) = syslog::init() {
//!         println!("failed to initiailize syslog: {}", e);
//!         return;
//!     }
//!     warn!("this is your {} warning", "final");
//!     error!("something went horribly wrong: {}", "out of RAMs");
//! }
//! ```

use std::env;
use std::ffi::{OsStr, OsString};
use std::fmt::{self, Display};
use std::fs::File;
use std::io;
use std::io::{stderr, Cursor, Write};
use std::path::PathBuf;
use std::sync::{MutexGuard, Once, ONCE_INIT};

use sync::Mutex;

/// The priority (i.e. severity) of a syslog message.
///
/// See syslog man pages for information on their semantics.
#[derive(Copy, Clone, Debug)]
pub enum Priority {
    Emergency = 0,
    Alert = 1,
    Critical = 2,
    Error = 3,
    Warning = 4,
    Notice = 5,
    Info = 6,
    Debug = 7,
}

impl Display for Priority {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::Priority::*;

        let string = match self {
            Emergency => "EMERGENCY",
            Alert => "ALERT",
            Critical => "CRITICAL",
            Error => "ERROR",
            Warning => "WARNING",
            Notice => "NOTICE",
            Info => "INFO",
            Debug => "DEBUG",
        };

        write!(f, "{}", string)
    }
}

/// The facility of a syslog message.
///
/// See syslog man pages for information on their semantics.
pub enum Facility {
    Kernel = 0,
    User = 1 << 3,
    Mail = 2 << 3,
    Daemon = 3 << 3,
    Auth = 4 << 3,
    Syslog = 5 << 3,
    Lpr = 6 << 3,
    News = 7 << 3,
    Uucp = 8 << 3,
    Local0 = 16 << 3,
    Local1 = 17 << 3,
    Local2 = 18 << 3,
    Local3 = 19 << 3,
    Local4 = 20 << 3,
    Local5 = 21 << 3,
    Local6 = 22 << 3,
    Local7 = 23 << 3,
}

/// Errors returned by `syslog::init()`.
#[derive(Debug)]
pub enum Error {
    /// Initialization was never attempted.
    NeverInitialized,
    /// Initialization has previously failed and can not be retried.
    Poisoned,
    /// Error while creating socket.
    Socket(io::Error),
    /// Error while attempting to connect socket.
    Connect(io::Error),
    // There was an error using `open` to get the lowest file descriptor.
    GetLowestFd(io::Error),
    // The guess of libc's file descriptor for the syslog connection was invalid.
    InvalidFd,
}

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::Error::*;

        match self {
            NeverInitialized => write!(f, "initialization was never attempted"),
            Poisoned => write!(f, "initialization previously failed and cannot be retried"),
            Socket(e) => write!(f, "failed to create socket: {}", e),
            Connect(e) => write!(f, "failed to connect socket: {}", e),
            GetLowestFd(e) => write!(f, "failed to get lowest file descriptor: {}", e),
            InvalidFd => write!(f, "guess of fd for syslog connection was invalid"),
        }
    }
}

fn get_proc_name() -> Option<String> {
    env::args_os()
        .next()
        .map(PathBuf::from)
        .and_then(|s| s.file_name().map(OsStr::to_os_string))
        .map(OsString::into_string)
        .and_then(Result::ok)
}

struct State {
    stderr: bool,
    file: Option<File>,
    proc_name: Option<String>,
}

impl State {
    fn new() -> Result<State, Error> {
        Ok(State {
            stderr: true,
            file: None,
            proc_name: get_proc_name(),
        })
    }
}

static STATE_ONCE: Once = ONCE_INIT;
static mut STATE: *const Mutex<State> = 0 as *const _;

fn new_mutex_ptr<T>(inner: T) -> *const Mutex<T> {
    Box::into_raw(Box::new(Mutex::new(inner)))
}

/// Initialize the syslog connection and internal variables.
///
/// This should only be called once per process before any other threads have been spawned or any
/// signal handlers have been registered. Every call made after the first will have no effect
/// besides return `Ok` or `Err` appropriately.
pub fn init() -> Result<(), Error> {
    let mut err = Error::Poisoned;
    STATE_ONCE.call_once(|| match State::new() {
        // Safe because STATE mutation is guarded by `Once`.
        Ok(state) => unsafe { STATE = new_mutex_ptr(state) },
        Err(e) => err = e,
    });

    if unsafe { STATE.is_null() } {
        Err(err)
    } else {
        Ok(())
    }
}

fn lock() -> Result<MutexGuard<'static, State>, Error> {
    // Safe because we assume that STATE is always in either a valid or NULL state.
    let state_ptr = unsafe { STATE };
    if state_ptr.is_null() {
        return Err(Error::NeverInitialized);
    }
    // Safe because STATE only mutates once and we checked for NULL.
    let state = unsafe { &*state_ptr };
    let guard = state.lock();
    Ok(guard)
}

// Attempts to lock and retrieve the state. Returns from the function silently on failure.
macro_rules! lock {
    () => {
        match lock() {
            Ok(s) => s,
            _ => return,
        };
    };
}

/// Replaces the process name reported in each syslog message.
///
/// The default process name is the _file name_ of `argv[0]`. For example, if this program was
/// invoked as
///
/// ```bash
/// $ path/to/app --delete everything
/// ```
///
/// the default process name would be _app_.
///
/// Does nothing if syslog was never initialized.
pub fn set_proc_name<T: Into<String>>(proc_name: T) {
    let mut state = lock!();
    state.proc_name = Some(proc_name.into());
}

/// Replaces the optional `File` to echo log messages to.
///
/// The default behavior is to not echo to a file. Passing `None` to this function restores that
/// behavior.
///
/// Does nothing if syslog was never initialized.
///
/// # Arguments
/// * `file` - `Some(file)` to echo to `file`, `None` to disable echoing to the file previously passed to `echo_file`.
pub fn echo_file(file: Option<File>) {
    let mut state = lock!();
    state.file = file;
}

/// Enables or disables echoing log messages to the `std::io::stderr()`.
///
/// The default behavior is **enabled**.
///
/// Does nothing if syslog was never initialized.
///
/// # Arguments
/// * `enable` - `true` to enable echoing to stderr, `false` to disable echoing to stderr.
pub fn echo_stderr(enable: bool) {
    let mut state = lock!();
    state.stderr = enable;
}


/// Records a log message with the given details.
///
/// Note that this will fail silently if syslog was not initialized.
///
/// # Arguments
/// * `pri` - The `Priority` (i.e. severity) of the log message.
/// * `fac` - The `Facility` of the log message. Usually `Facility::User` should be used.
/// * `file_name` - Name of the file that generated the log.
/// * `line` - Line number within `file_name` that generated the log.
/// * `args` - The log's message to record, in the form of `format_args!()`  return value
///
/// # Examples
///
/// ```
/// # use sys_util::syslog;
/// # fn main() {
/// #   if let Err(e) = syslog::init() {
/// #       println!("failed to initiailize syslog: {}", e);
/// #       return;
/// #   }
/// syslog::log(syslog::Priority::Error,
///             syslog::Facility::User,
///             file!(),
///             line!(),
///             format_args!("hello syslog"));
/// # }
/// ```
pub fn log(pri: Priority, fac: Facility, file_name: &str, line: u32, args: fmt::Arguments) {
    let mut state = lock!();
    let mut buf = [0u8; 1024];

    let (res, len) = {
        let mut buf_cursor = Cursor::new(&mut buf[..]);
        (
            writeln!(&mut buf_cursor, "[{}:{}:{}] {}", pri, file_name, line, args),
            buf_cursor.position() as usize,
        )
    };
    if res.is_ok() {
        if let Some(file) = &mut state.file {
            let _ = file.write_all(&buf[..len]);
        }
        if state.stderr {
            let _ = stderr().write_all(&buf[..len]);
        }
    }
}

/// A macro for logging at an arbitrary priority level.
///
/// Note that this will fail silently if syslog was not initialized.
#[macro_export]
macro_rules! log {
    ($pri:expr, $($args:tt)+) => ({
        $crate::syslog::log($pri, $crate::syslog::Facility::User, file!(), line!(), format_args!($($args)+))
    })
}

/// A macro for logging an error.
///
/// Note that this will fail silently if syslog was not initialized.
#[macro_export]
macro_rules! error {
    ($($args:tt)+) => ($crate::log!($crate::syslog::Priority::Error, $($args)*))
}

/// A macro for logging a warning.
///
/// Note that this will fail silently if syslog was not initialized.
#[macro_export]
macro_rules! warn {
    ($($args:tt)+) => ($crate::log!($crate::syslog::Priority::Warning, $($args)*))
}

/// A macro for logging info.
///
/// Note that this will fail silently if syslog was not initialized.
#[macro_export]
macro_rules! info {
    ($($args:tt)+) => ($crate::log!($crate::syslog::Priority::Info, $($args)*))
}

/// A macro for logging debug information.
///
/// Note that this will fail silently if syslog was not initialized.
#[macro_export]
macro_rules! debug {
    ($($args:tt)+) => ($crate::log!($crate::syslog::Priority::Debug, $($args)*))
}
