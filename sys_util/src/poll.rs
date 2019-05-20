use winapi::um::synchapi::{WaitForMultipleObjects};
use winapi::um::winnt::{HANDLE};
use winapi::shared::winerror::{WAIT_TIMEOUT};
use winapi::um::winbase::{INFINITE, WAIT_FAILED, WAIT_ABANDONED_0};

use crate::errno::{Error};

pub struct PollContext {
    handles: Vec<HANDLE>,
}

#[derive(Debug)]
pub enum PollResult {
    Signaled(HANDLE),
    Abandoned(HANDLE),
    Timeout,
    Failed(u32),
}

impl PollContext {
    pub fn new() -> PollContext {
        PollContext {
            handles: Vec::new(),
        }
    }

    pub fn add(&mut self, handle: HANDLE) {
        // TODO(lpetrut): consider adding tokens so that we can have a similar
        // interface with the crosvm poll module.
        self.handles.push(handle);
    }

    pub fn delete(&mut self, handle: HANDLE) {
        self.handles.iter().position(|item| item == &handle)
                           .map(|i| self.handles.remove(i));
    }

    pub fn wait(&mut self) -> PollResult {
        self.wait_with_timeout(INFINITE)
    }

    pub fn wait_with_timeout(&mut self, timeout: u32) -> PollResult {
        let ret_val = unsafe {
            WaitForMultipleObjects(
                self.handles.len() as u32,
                self.handles.as_mut_ptr(),
                0,  // WaitAll
                timeout)
        };

        let handles_len = self.handles.len() as u32;

        // can't use patterns with variables...
        if ret_val >= 0 && ret_val <= handles_len {
            PollResult::Signaled(
                self.handles[ret_val as usize])
        }
        else if ret_val >= WAIT_ABANDONED_0 && (
                ret_val <= WAIT_ABANDONED_0 + handles_len) {
            PollResult::Abandoned(
                self.handles[(ret_val - WAIT_ABANDONED_0) as usize])
        }
        else if ret_val == WAIT_TIMEOUT {
            PollResult::Timeout
        }
        else if ret_val == WAIT_FAILED {
            PollResult::Failed(Error::last().errno() as u32)
        }
        else {
            panic!(format!("Unexpected WaitForMultipleObjects ret_val: {}",
                           ret_val))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::os::windows::io::{AsRawHandle, FromRawHandle, IntoRawHandle, RawHandle};

    use crate::EventFd;
    use crate::{PollContext, PollResult};

    #[test]
    fn test_wait_events() {
        let evt = EventFd::new().unwrap();
        let evt2 = EventFd::new().unwrap();

        let mut ctxt = PollContext::new();
        ctxt.add(evt.as_raw_handle());
        ctxt.add(evt2.as_raw_handle());

        evt2.write(1);

        let result = ctxt.wait_with_timeout(5000);

        match result {
            PollResult::Signaled(handle) => {
                assert!(handle == evt2.as_raw_handle())
            },
            _ => panic!(format!("Unexpected result {:?}.", result)),
        }

    }
}
