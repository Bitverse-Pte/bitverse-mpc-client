use std::ffi::{CStr, CString};
use std::os::raw::c_char;

use curv::BigInt;
use kms::ecdsa::two_party::MasterKey2;
use crate::utilities::{error_to_c_string, success_to_c_string};

#[derive(Serialize, Deserialize)]
pub struct MasterDeriveKey {
    master_key: MasterKey2,
    x_pos: BigInt,
    y_pos: BigInt,
}

#[no_mangle]
pub extern "C" fn key_derive(    
    c_master_key_json: *const c_char,//masterkey
    c_x_pos: i32,//coinType
    c_y_pos: i32,//account:1,2
) -> *mut c_char {

    let x: BigInt = BigInt::from(c_x_pos);
    let y: BigInt = BigInt::from(c_y_pos);

    let raw_master_key_json = unsafe { CStr::from_ptr(c_master_key_json) };
    let master_key_json = match raw_master_key_json.to_str() {
        Ok(s) => s,
        Err(e) => return error_to_c_string(format_err!("decoding raw master_key_json failed: {}", e))
    };

    let master_key: MasterKey2 = match serde_json::from_str(master_key_json){
        Ok(s) => s,
        Err(e) => {
            return error_to_c_string(format_err!("decoding master_key_json to MasterKey2 failed: {}", e))
        }
    };

   let child_master_key =  master_key.get_child(vec![x.clone(), y.clone()]);

    let derive_key = MasterDeriveKey{
        master_key:child_master_key,
        x_pos:x,
        y_pos:y
    };

    return success_to_c_string(derive_key)
}


#[test]
fn test_key_derive() {
    let fs = std::fs::read_to_string("testAssets/mk.json").unwrap();
    let rt = key_derive(CString::new(fs).unwrap().into_raw(), 60,0);
}


