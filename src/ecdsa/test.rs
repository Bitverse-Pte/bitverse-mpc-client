use std::ffi::CString;
use std::os::raw::c_char;

#[no_mangle]
pub fn hello() -> *mut c_char {
    CString::new("Hello BW MPC!").unwrap().into_raw()
}