// iOS bindings
use std::ffi::{CStr, CString};
use std::os::raw::c_char;

use curv::BigInt;
use kms::ecdsa::two_party::MasterKey2;
use kms::ecdsa::two_party::party2;
use multi_party_ecdsa::protocols::two_party_ecdsa::lindell_2017::party_one;
use multi_party_ecdsa::protocols::two_party_ecdsa::lindell_2017::party_two;

use crate::utilities::{SUCCESS_CODE, success_to_c_string};

use super::super::ClientShim;
use super::super::Result;
use super::super::utilities::error_to_c_string;
use super::super::utilities::requests;
use super::ServerReply;

const SIGN_PATH_PRE: &str = "bitverse/wallet/v1/private/mpc/ecdsa/sign";

#[derive(Serialize, Deserialize)]
pub struct SignFirstRequest{
    id:String,
    ephKeyGenFirstMsg:String
}

#[derive(Serialize, Deserialize)]
pub struct SignSecondRequest{
    id:String,
    signSecondMsgReq:String
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SignSecondMsgRequest {
    pub message: BigInt,
    pub party_two_sign_message: party2::SignMessage,
    pub x_pos_child_key: BigInt,
    pub y_pos_child_key: BigInt,
}

pub fn sign(
    client_shim: &ClientShim,
    message: BigInt,
    mk: &MasterKey2,
    x_pos: BigInt,
    y_pos: BigInt,
    id: &String,
) -> Result<party_one::SignatureRecid> {
    let (eph_key_gen_first_message_party_two, eph_comm_witness, eph_ec_key_pair_party2) =
        MasterKey2::sign_first_message();

    let sign_first_req = SignFirstRequest{
        id:id.to_string(),
        ephKeyGenFirstMsg : serde_json::to_string(&eph_key_gen_first_message_party_two).unwrap()
    };

    let server_reply:ServerReply = match requests::postb(client_shim, &format!("{}/first", SIGN_PATH_PRE), &sign_first_req) {
            Some(s) => s,
            None => return Err(failure::err_msg("party1 sign first message request failed"))
        };

    if server_reply.retCode != SUCCESS_CODE || server_reply.result == None {
        return Err(format_err!("{}:{}",server_reply.retCode,server_reply.retMsg))
    }
    let sign_party_one_first_message: party_one::EphKeyGenFirstMsg = match serde_json::from_str(server_reply.result.unwrap().as_str()){
        Ok(s) => s,
        Err(e) => return Err(format_err!("{}","Parse content erro from server!"))
    };


    let party_two_sign_message = mk.sign_second_message(
        &eph_ec_key_pair_party2,
        eph_comm_witness.clone(),
        &sign_party_one_first_message,
        &message,
    );

    let signature = match get_signature(
        client_shim,
        message,
        party_two_sign_message,
        x_pos,
        y_pos,
        &id,
    ) {
        Ok(s) => s,
        Err(e) => return Err(format_err!("ecdsa::get_signature failed failed: {}", e))
    };

    Ok(signature)
}

fn get_signature(
    client_shim: &ClientShim,
    message: BigInt,
    party_two_sign_message: party2::SignMessage,
    x_pos_child_key: BigInt,
    y_pos_child_key: BigInt,
    id: &String,
) -> Result<party_one::SignatureRecid> {
    let sign_secod_msg_request: SignSecondMsgRequest = SignSecondMsgRequest {
        message,
        party_two_sign_message,
        x_pos_child_key,
        y_pos_child_key,
    };

    let sign_second_request = SignSecondRequest{
        id:id.to_string(),
        signSecondMsgReq:serde_json::to_string(&sign_secod_msg_request).unwrap()
    };

    let server_reply:ServerReply = match requests::postb(client_shim, &format!("{}/second", SIGN_PATH_PRE), &sign_second_request) {
        Some(s) => s,
        None => return Err(failure::err_msg("party1 sign second message request failed"))
    };
    if server_reply.retCode != SUCCESS_CODE || server_reply.result == None {
        return Err(format_err!("{}:{}",server_reply.retCode,server_reply.retMsg))
    }

    let signature: party_one::SignatureRecid = match serde_json::from_str(server_reply.result.unwrap().as_str()){
        Ok(s) => s,
        Err(e) => return Err(format_err!("convert to SignatureRecid failed: {}", e))
    };
    Ok(signature)
}

#[no_mangle]
pub extern "C" fn sign_message(
    c_endpoint: *const c_char,
    c_auth_token: *const c_char,
    c_message_le_hex: *const c_char,
    c_master_key_json: *const c_char,//masterkey
    c_x_pos: i32,//coinType
    c_y_pos: i32,//account:1,2
    c_id: *const c_char,
) -> *mut c_char {
    let raw_endpoint = unsafe { CStr::from_ptr(c_endpoint) };
    let endpoint = match raw_endpoint.to_str() {
        Ok(s) => s,
        Err(e) => return error_to_c_string(format_err!("decoding raw endpoint failed: {}", e))
    };

    let raw_auth_token = unsafe { CStr::from_ptr(c_auth_token) };
    let auth_token = match raw_auth_token.to_str() {
        Ok(s) => s,
        Err(e) => return error_to_c_string(format_err!("decoding raw auth_token failed: {}", e))
    };

    let raw_message_hex = unsafe { CStr::from_ptr(c_message_le_hex) };
    let message_hex = match raw_message_hex.to_str() {
        Ok(s) => s,
        Err(e) => return error_to_c_string(format_err!("decoding raw message_hex failed: {}", e))
    };

    let raw_master_key_json = unsafe { CStr::from_ptr(c_master_key_json) };
    let master_key_json = match raw_master_key_json.to_str() {
        Ok(s) => s,
        Err(e) => return error_to_c_string(format_err!("decoding raw master_key_json failed: {}", e))
    };

    let raw_id = unsafe { CStr::from_ptr(c_id) };
    let id = match raw_id.to_str() {
        Ok(s) => s,
        Err(e) => return error_to_c_string(format_err!("decoding raw id failed: {}", e))
    };

    let x: BigInt = BigInt::from(c_x_pos);

    let y: BigInt = BigInt::from(c_y_pos);

    let client_shim = ClientShim::new(endpoint.to_string(), Some(auth_token.to_string()));

    let mk: MasterKey2 = match serde_json::from_str(master_key_json){
        Ok(s) => s,
        Err(e) => return error_to_c_string(format_err!("decoding master_key_json to MasterKey2 failed: {}", e))
    };

    let mk_child: MasterKey2 = mk.get_child(vec![x.clone(), y.clone()]);

    let message: BigInt = match serde_json::from_str(message_hex){
        Ok(s) => s,
        Err(e) => return error_to_c_string(format_err!("decoding message_hex failed: {}", e))
    };

    let sig = sign(
        &client_shim,
        message,
        &mk_child,
        x,
        y,
        &id.to_string(),
    );

    match sig {
        Ok(result) => return success_to_c_string(result),
        Err(e) => return error_to_c_string(format_err!("signing to endpoint {} failed: {}", endpoint, e)),
    }
}