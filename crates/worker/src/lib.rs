//! All native ABI operations are confined to this short-lived, single-threaded worker.
use std::alloc::{Layout, alloc, dealloc, realloc};
use std::ffi::c_void;
use std::io::{self, BufRead, Write};
use std::sync::atomic::{AtomicUsize, Ordering};

#[path = "../generated/roc_platform_abi.rs"]
#[rustfmt::skip]
mod abi;

const MAX_FRAME: usize = 1_048_576;
const MAX_HEAP: usize = 64 * 1_048_576;
static HEAP: AtomicUsize = AtomicUsize::new(0);

fn fatal() -> ! {
    std::process::exit(70)
}

fn layout(length: usize, alignment: usize) -> (Layout, usize) {
    let alignment = alignment.max(std::mem::align_of::<usize>());
    let total = length.checked_add(alignment).unwrap_or_else(|| fatal());
    let layout = Layout::from_size_align(total, alignment).unwrap_or_else(|_| fatal());
    (layout, alignment)
}

#[unsafe(no_mangle)]
pub extern "C" fn roc_alloc(length: usize, alignment: usize) -> *mut c_void {
    let (layout, prefix) = layout(length, alignment);
    let previous = HEAP.fetch_add(layout.size(), Ordering::SeqCst);
    if previous
        .checked_add(layout.size())
        .is_none_or(|n| n > MAX_HEAP)
    {
        fatal();
    }
    // The matching deallocator recovers the exact Rust allocation layout.
    unsafe {
        let base = alloc(layout);
        if base.is_null() {
            fatal();
        }
        let data = base.add(prefix);
        data.cast::<usize>().sub(1).write(layout.size());
        data.cast()
    }
}

#[unsafe(no_mangle)]
/// # Safety
/// The pointer must be null or a live allocation from roc_alloc, with its original alignment.
pub unsafe extern "C" fn roc_dealloc(ptr: *mut c_void, alignment: usize) {
    if ptr.is_null() {
        return;
    }
    let prefix = alignment.max(std::mem::align_of::<usize>());
    // Only compiler-created allocations cross this ABI; process isolation bounds failure.
    unsafe {
        let size = ptr.cast::<usize>().sub(1).read();
        let layout = Layout::from_size_align(size, prefix).unwrap_or_else(|_| fatal());
        dealloc(ptr.cast::<u8>().sub(prefix), layout);
        HEAP.fetch_sub(size, Ordering::SeqCst);
    }
}

#[unsafe(no_mangle)]
/// # Safety
/// The pointer must be null or a live allocation from roc_alloc, with its original alignment.
pub unsafe extern "C" fn roc_realloc(
    ptr: *mut c_void,
    length: usize,
    alignment: usize,
) -> *mut c_void {
    if ptr.is_null() {
        return roc_alloc(length, alignment);
    }
    let (new_layout, prefix) = layout(length, alignment);
    unsafe {
        let old_size = ptr.cast::<usize>().sub(1).read();
        let old_layout = Layout::from_size_align(old_size, prefix).unwrap_or_else(|_| fatal());
        let current = HEAP.load(Ordering::SeqCst);
        let new_total = current
            .checked_sub(old_size)
            .and_then(|n| n.checked_add(new_layout.size()))
            .unwrap_or_else(|| fatal());
        if new_total > MAX_HEAP {
            fatal();
        }
        let base = realloc(ptr.cast::<u8>().sub(prefix), old_layout, new_layout.size());
        if base.is_null() {
            fatal();
        }
        let data = base.add(prefix);
        data.cast::<usize>().sub(1).write(new_layout.size());
        HEAP.store(new_total, Ordering::SeqCst);
        data.cast()
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn roc_dbg(_bytes: *const u8, _len: usize) {
    fatal();
}
#[unsafe(no_mangle)]
pub extern "C" fn roc_expect_failed(_bytes: *const u8, _len: usize) {
    fatal();
}
#[unsafe(no_mangle)]
pub extern "C" fn roc_crashed(_bytes: *const u8, _len: usize) {
    fatal();
}

extern "C" fn host_alloc(_: *mut abi::RocHost, n: usize, a: usize) -> *mut c_void {
    roc_alloc(n, a)
}
extern "C" fn host_dealloc(_: *mut abi::RocHost, p: *mut c_void, a: usize) {
    unsafe { roc_dealloc(p, a) }
}
extern "C" fn host_realloc(
    _: *mut abi::RocHost,
    p: *mut c_void,
    n: usize,
    a: usize,
) -> *mut c_void {
    unsafe { roc_realloc(p, n, a) }
}
extern "C" fn host_diagnostic(_: *mut abi::RocHost, _: *const u8, _: usize) {
    fatal();
}

fn run() -> io::Result<()> {
    let host = abi::RocHost {
        env: std::ptr::null_mut(),
        roc_alloc: host_alloc,
        roc_dealloc: host_dealloc,
        roc_realloc: host_realloc,
        roc_dbg: host_diagnostic,
        roc_expect_failed: host_diagnostic,
        roc_crashed: host_diagnostic,
    };
    let mut input = io::stdin().lock();
    let mut output = io::stdout().lock();
    loop {
        let mut frame = Vec::new();
        loop {
            let available = input.fill_buf()?;
            if available.is_empty() {
                break;
            }
            let count = available
                .iter()
                .position(|b| *b == b'\n')
                .map_or(available.len(), |i| i + 1);
            if frame.len() + count > MAX_FRAME {
                fatal();
            }
            frame.extend_from_slice(&available[..count]);
            input.consume(count);
            if frame.last() == Some(&b'\n') {
                break;
            }
        }
        if frame.is_empty() {
            return Ok(());
        }
        if frame.pop() != Some(b'\n') {
            fatal();
        }
        let source = std::str::from_utf8(&frame).unwrap_or_else(|_| fatal());
        let argument = abi::RocStr::from_str(source, &host);
        // Ownership of argument is transferred to Roc. The returned string is owned here.
        let answer = unsafe { abi::day2_step(argument) };
        if answer.len() > MAX_FRAME {
            fatal();
        }
        let bytes = answer.as_slice();
        std::str::from_utf8(bytes).unwrap_or_else(|_| fatal());
        output.write_all(bytes)?;
        output.write_all(b"\n")?;
        output.flush()?;
        unsafe {
            answer.decref(&host);
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn main(_: i32, _: *const *const i8) -> i32 {
    match run() {
        Ok(()) => 0,
        Err(_) => 74,
    }
}
