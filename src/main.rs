#![no_main]

mod init;
mod loader;

use libc::c_char;

/// # Safety 
/// This is the entry point of the program
/// We cannot use the main because rust will abort if we don't have std{in/out/err}
/// https://github.com/rust-lang/rust/blob/3071aefdb2821439e2e6f592f41a4d28e40c1e79/library/std/src/sys/unix/mod.rs#L80
/// So we use the C main function and call rust code from there
#[no_mangle]
pub unsafe extern "C" fn main(_argc: i32, argv: *const *const std::os::raw::c_char) -> i32 {
    let _ = init::init();
    let program = "/init\0".as_ptr() as *const c_char;
    libc::execv(program, argv);
    0
}
