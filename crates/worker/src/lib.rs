//! All native ABI operations are confined to this short-lived, single-threaded worker.
use std::alloc::{Layout, alloc, dealloc, realloc};
use std::ffi::c_void;
use std::io::{self, BufRead, Write};
use std::ptr::NonNull;
use std::sync::atomic::{AtomicUsize, Ordering};

#[path = "../generated/roc_platform_abi.rs"]
#[rustfmt::skip]
mod abi;

#[cfg(target_os = "macos")]
mod first_request;

const ORDINARY_MAX_FRAME: usize = 1_048_576;
const ORDINARY_MAX_HEAP: usize = 64 * 1_048_576;
const QUALIFIED_PROPERTY_MAX_FRAME: usize = 6 * 32 * 1024 * 1024 + 65_536;
const QUALIFIED_PROPERTY_MAX_HEAP: usize = 512 * 1024 * 1024;
const QUALIFIED_PROPERTY_ARGUMENT: &[u8] = b"--day2-qualified-property-v1";
static HEAP: AtomicUsize = AtomicUsize::new(0);
static HEAP_LIMIT: AtomicUsize = AtomicUsize::new(ORDINARY_MAX_HEAP);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Limits {
    max_frame: usize,
    max_heap: usize,
}

const ORDINARY_LIMITS: Limits = Limits {
    max_frame: ORDINARY_MAX_FRAME,
    max_heap: ORDINARY_MAX_HEAP,
};
const QUALIFIED_PROPERTY_LIMITS: Limits = Limits {
    max_frame: QUALIFIED_PROPERTY_MAX_FRAME,
    max_heap: QUALIFIED_PROPERTY_MAX_HEAP,
};

fn select_limits(args: &[&[u8]]) -> Option<Limits> {
    match args {
        [] => Some(ORDINARY_LIMITS),
        [QUALIFIED_PROPERTY_ARGUMENT] => Some(QUALIFIED_PROPERTY_LIMITS),
        _ => None,
    }
}

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
        .is_none_or(|n| n > HEAP_LIMIT.load(Ordering::SeqCst))
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
        if new_total > HEAP_LIMIT.load(Ordering::SeqCst) {
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

extern "C" fn host_alloc(_: *mut abi::RocHost, n: usize, a: usize) -> NonNull<c_void> {
    NonNull::new(roc_alloc(n, a)).unwrap_or_else(|| fatal())
}
extern "C" fn host_dealloc(_: *mut abi::RocHost, p: *mut c_void, a: usize) {
    unsafe { roc_dealloc(p, a) }
}
extern "C" fn host_realloc(
    _: *mut abi::RocHost,
    p: *mut c_void,
    n: usize,
    a: usize,
) -> NonNull<c_void> {
    NonNull::new(unsafe { roc_realloc(p, n, a) }).unwrap_or_else(|| fatal())
}
extern "C" fn host_diagnostic(_: *mut abi::RocHost, _: *const u8, _: usize) {
    fatal();
}

#[cfg_attr(test, allow(dead_code))]
fn run(limits: Limits) -> io::Result<()> {
    HEAP_LIMIT.store(limits.max_heap, Ordering::SeqCst);
    #[cfg(target_os = "macos")]
    let mut observed = first_request::FirstRequest::new();
    #[cfg(target_os = "macos")]
    observed.emit(first_request::Milestone::Run, &mut io::stderr());
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
    #[cfg(target_os = "macos")]
    observed.emit(first_request::Milestone::Locked, &mut io::stderr());
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
            if frame.len() + count > limits.max_frame {
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
        #[cfg(target_os = "macos")]
        observed.emit(first_request::Milestone::Frame, &mut io::stderr());
        let argument = abi::RocStr::from_str(source, &host);
        #[cfg(target_os = "macos")]
        observed.emit(first_request::Milestone::Argument, &mut io::stderr());
        // Ownership of argument is transferred to Roc. The returned string is owned here.
        let answer = unsafe { abi::day2_step(argument) };
        #[cfg(target_os = "macos")]
        observed.emit(first_request::Milestone::Returned, &mut io::stderr());
        if answer.len() >= limits.max_frame {
            fatal();
        }
        let bytes = answer.as_slice();
        std::str::from_utf8(bytes).unwrap_or_else(|_| fatal());
        #[cfg(target_os = "macos")]
        observed.emit(first_request::Milestone::Answer, &mut io::stderr());
        output.write_all(bytes)?;
        output.write_all(b"\n")?;
        output.flush()?;
        #[cfg(target_os = "macos")]
        {
            observed.emit(first_request::Milestone::Flushed, &mut io::stderr());
            observed.finish();
        }
        unsafe {
            answer.decref(&host);
        }
    }
}

/// # Safety
/// `argv` must be a readable process-ABI argument array with `argc` entries;
/// each selected argument must point to a valid NUL-terminated string.
#[cfg(not(test))]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn main(argc: i32, argv: *const *const i8) -> i32 {
    if !(1..=2).contains(&argc) || argv.is_null() {
        return 64;
    }
    // The exported C entrypoint is invoked before Rust's process runtime is initialized.
    // Read only the ABI-provided argv array here; policy selection itself is pure and safe.
    let limits = unsafe {
        let mut args = Vec::with_capacity((argc - 1) as usize);
        for index in 1..argc as usize {
            let argument = *argv.add(index);
            if argument.is_null() {
                return 64;
            }
            args.push(std::ffi::CStr::from_ptr(argument).to_bytes());
        }
        select_limits(&args)
    };
    let Some(limits) = limits else {
        return 64;
    };
    match run(limits) {
        Ok(()) => 0,
        Err(_) => 74,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selects_only_ordinary_or_qualified_property_profile() {
        assert_eq!(select_limits(&[]), Some(ORDINARY_LIMITS));
        assert_eq!(
            select_limits(&[QUALIFIED_PROPERTY_ARGUMENT]),
            Some(QUALIFIED_PROPERTY_LIMITS)
        );
        assert_eq!(select_limits(&[b"--unknown"]), None);
        assert_eq!(
            select_limits(&[QUALIFIED_PROPERTY_ARGUMENT, b"extra"]),
            None
        );
        assert_eq!(select_limits(&[b"--day2-qualified-property-v1x"]), None);
    }

    #[test]
    fn allocator_budget_probe() {
        let Ok(case) = std::env::var("DAY2_ALLOCATOR_BUDGET_PROBE") else {
            return;
        };
        let alignment = std::mem::align_of::<usize>();
        HEAP_LIMIT.store(32, Ordering::SeqCst);
        match case.as_str() {
            "exact_and_release" => {
                let pointer = roc_alloc(32 - alignment, alignment);
                assert_eq!(HEAP.load(Ordering::SeqCst), 32);
                unsafe {
                    let pointer = roc_realloc(pointer, 16 - alignment, alignment);
                    assert_eq!(HEAP.load(Ordering::SeqCst), 16);
                    let pointer = roc_realloc(pointer, 32 - alignment, alignment);
                    assert_eq!(HEAP.load(Ordering::SeqCst), 32);
                    roc_dealloc(pointer, alignment);
                }
                assert_eq!(HEAP.load(Ordering::SeqCst), 0);
            }
            "sum_over" => {
                roc_alloc(16 - alignment, alignment);
                roc_alloc(16 - alignment, alignment);
                roc_alloc(1, alignment);
                panic!("aggregate heap quota was not enforced");
            }
            "realloc_over" => {
                let pointer = roc_alloc(32 - alignment, alignment);
                unsafe { roc_realloc(pointer, 33 - alignment, alignment) };
                panic!("reallocation heap quota was not enforced");
            }
            "qualified_over" => {
                HEAP_LIMIT.store(QUALIFIED_PROPERTY_LIMITS.max_heap, Ordering::SeqCst);
                roc_alloc(QUALIFIED_PROPERTY_LIMITS.max_heap, alignment);
                panic!("qualified heap quota did not include allocation headers");
            }
            "ordinary_over" => {
                HEAP_LIMIT.store(ORDINARY_LIMITS.max_heap, Ordering::SeqCst);
                roc_alloc(ORDINARY_LIMITS.max_heap, alignment);
                panic!("ordinary heap quota did not include allocation headers");
            }
            _ => panic!("unknown allocator probe"),
        }
    }

    #[test]
    fn native_allocator_enforces_live_heap_quota_before_allocating() {
        for (case, expected) in [
            ("exact_and_release", 0),
            ("sum_over", 70),
            ("realloc_over", 70),
            ("qualified_over", 70),
            ("ordinary_over", 70),
        ] {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "tests::allocator_budget_probe", "--nocapture"])
                .env("DAY2_ALLOCATOR_BUDGET_PROBE", case)
                .output()
                .unwrap();
            assert_eq!(
                output.status.code(),
                Some(expected),
                "{case}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }
}
