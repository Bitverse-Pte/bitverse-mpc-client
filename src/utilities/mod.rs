use std::ffi::CString;
use std::os::raw::c_char;
use serde::Serialize;

pub mod requests;

pub const SYSTEM_ERROR_CODE: i32 = 10104000;
pub const SUCCESS_CODE: i32 = 0;


pub fn error_to_c_string_whith_code(err_code: i32,e: failure::Error) -> *mut c_char {
    let c_result = CResult {
        ret_code: SYSTEM_ERROR_CODE,
        ret_msg: format!("Error: {}", e.to_string()),
        result: "".to_string(),
    };

    let c_result_str = serde_json::to_string(&c_result).unwrap();
    CString::new(c_result_str.to_owned()).unwrap().into_raw()
}

pub fn error_to_c_string(e: failure::Error) -> *mut c_char {
    error_to_c_string_whith_code(SYSTEM_ERROR_CODE,e)
}

pub fn success_to_c_string<T: Serialize>(result: T) -> *mut c_char {
    let c_result = CResult {
        ret_code: SUCCESS_CODE,
        ret_msg: "OK".to_string(),
        result: serde_json::to_string(&result).unwrap(),
    };

    let c_result_str = serde_json::to_string(&c_result).unwrap();
    CString::new(c_result_str.to_owned()).unwrap().into_raw()
}

#[derive(Serialize)]
pub struct CResult {
    ret_code: i32,
    ret_msg: String,
    result: String,
}