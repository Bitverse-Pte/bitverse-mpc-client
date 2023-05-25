use std::os::raw::c_char;

use std::ffi::CString;

#[no_mangle]
pub extern "C" fn free_char(data_ptr: *mut c_char) {
    unsafe {
        let c_string=CString::from_raw(data_ptr);
    }
}
