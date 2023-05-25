// iOS bindings
use super::super::Result;
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::time::Instant;

use curv::BigInt;
use curv::cryptographic_primitives::proofs::sigma_dlog::DLogProof;
use curv::cryptographic_primitives::twoparty::dh_key_exchange_variant_with_pok_comm::*;
use curv::elliptic::curves::secp256_k1::GE;
use curv::elliptic::curves::traits::ECPoint;
use floating_duration::TimeFormat;
use kms::chain_code::two_party as chain_code;
use kms::ecdsa::two_party::*;
use multi_party_ecdsa::protocols::two_party_ecdsa::lindell_2017::*;
use serde_json::{self, ser};
use zk_paillier::zkproofs::SALT_STRING;

use crate::ecdsa::ServerReply;
use crate::utilities::{SUCCESS_CODE, success_to_c_string, error_to_c_string};

// use super::super::utilities::requests;
use super::super::ClientShim;
use super::super::utilities::requests;
use super::types::PrivateShare;

const KG_PATH_PRE: &str = "bitverse/wallet/v1/private/mpc/ecdsa/keygen";


#[derive(Serialize, Deserialize)]
pub struct KeyGenSecondReq{
    id : String,
    d_log_proof:String,
}

#[derive(Serialize, Deserialize)]
pub struct ChainCodeFirstReq{
    id : String,
}

#[derive(Serialize, Deserialize)]
pub struct ChainCodeSecondReq{
    id : String,
    d_log_proof: String,
}


pub fn get_master_key(client_shim: &ClientShim) -> Result<PrivateShare> {
    let start = Instant::now();

    let server_reply:ServerReply = match requests::post(&client_shim, &format!("{}/first", KG_PATH_PRE)){
        Some(s) => s,
        None =>  return Err(format_err!("{}","Net error!"))
    };

    if server_reply.retCode != SUCCESS_CODE || server_reply.result == None {
        return Err(format_err!("{}:{}",server_reply.retCode,server_reply.retMsg))
    }
    let (id, kg_party_one_first_message): (String, party_one::KeyGenFirstMsg)  = match serde_json::from_str(server_reply.result.unwrap().as_str()){
        Ok(s) => s,
        Err(e) => return Err(format_err!("{}","Parse content erro from server!"))
    };

    let (kg_party_two_first_message, kg_ec_key_pair_party2) = MasterKey2::key_gen_first_message();

    let ids_str = id.as_str();
    
    let key_gen_second_req = KeyGenSecondReq { 
        id:ids_str.to_string(), 
        d_log_proof:serde_json::to_string(&kg_party_two_first_message.d_log_proof).unwrap()
    };
    
    let server_reply:ServerReply =  match requests::postb(client_shim, &format!("{}/second", KG_PATH_PRE), key_gen_second_req){
        Some(s) => s,
        None =>  return Err(format_err!("{}","Net error!"))
    };

    if server_reply.retCode != SUCCESS_CODE || server_reply.result == None {
        return Err(format_err!("{}:{}",server_reply.retCode,server_reply.retMsg))
    }

    let kg_party_one_second_message: party1::KeyGenParty1Message2 = match serde_json::from_str(server_reply.result.unwrap().as_str()){
        Ok(s) => s,
        Err(e) => return Err(format_err!("{}","Parse content erro from server!"))
    };

    let key_gen_second_message = MasterKey2::key_gen_second_message(
        &kg_party_one_first_message,
        &kg_party_one_second_message,
        SALT_STRING,
    );

    let (_, party_two_paillier) = key_gen_second_message.unwrap();

    let chain_code_first_req = ChainCodeFirstReq { id:ids_str.to_string()  };

    let server_reply:ServerReply = match requests::postb(client_shim,&format!("{}/chaincode/first", KG_PATH_PRE), chain_code_first_req){
        Some(s) => s,
        None =>  return Err(format_err!("{}","Net error!"))
    };
    
    if server_reply.retCode != SUCCESS_CODE || server_reply.result == None{
        return Err(format_err!("{}:{}",server_reply.retCode,server_reply.retMsg))
    }
    let cc_party_one_first_message: Party1FirstMessage = match serde_json::from_str(server_reply.result.unwrap().as_str()){
        Ok(s) => s,
        Err(e) => return Err(format_err!("{}","Parse content erro from server!"))
    };

    let (cc_party_two_first_message, cc_ec_key_pair2) =
        chain_code::party2::ChainCode2::chain_code_first_message();

    let chain_code_second_req = ChainCodeSecondReq{
        id:ids_str.to_string(),
        d_log_proof:serde_json::to_string(&cc_party_two_first_message.d_log_proof).unwrap()
    };

    let server_reply:ServerReply = match requests::postb(client_shim,&format!("{}/chaincode/second", KG_PATH_PRE),chain_code_second_req,){
        Some(s) => s,
        None =>  return Err(format_err!("{}","Net error!"))
    };

    if server_reply.retCode != SUCCESS_CODE || server_reply.result == None{
        return Err(format_err!("{}:{}",server_reply.retCode,server_reply.retMsg))
    }
    let cc_party_one_second_message: Party1SecondMessage<GE> = match serde_json::from_str(server_reply.result.unwrap().as_str()){
        Ok(s) => s,
        Err(e) => return Err(format_err!("{}","Parse content erro from server!"))
    };


    let cc_party_two_second_message = chain_code::party2::ChainCode2::chain_code_second_message(
        &cc_party_one_first_message,
        &cc_party_one_second_message,
    );

    assert!(cc_party_two_second_message.is_ok());

    let party2_cc = chain_code::party2::ChainCode2::compute_chain_code(
        &cc_ec_key_pair2,
        &cc_party_one_second_message.comm_witness.public_share,
    )
        .chain_code;

    let master_key = MasterKey2::set_master_key(
        &party2_cc,
        &kg_ec_key_pair_party2,
        &kg_party_one_second_message
            .ecdh_second_message
            .comm_witness
            .public_share,
        &party_two_paillier,
    );

    Ok(PrivateShare { id, master_key })
}

#[no_mangle]
pub extern "C" fn get_client_master_key(
    c_endpoint: *const c_char,
    c_auth_token: *const c_char,
) -> *mut c_char {
    let raw_endpoint = unsafe { CStr::from_ptr(c_endpoint) };
    let endpoint = match raw_endpoint.to_str() {
        Ok(s) => s,
        Err(e) => {
            return error_to_c_string(format_err!(
                "Error while decoding raw endpoint: {}",
                e
            ))
        }
    };

    let raw_auth_token = unsafe { CStr::from_ptr(c_auth_token) };
    let auth_token = match raw_auth_token.to_str() {
        Ok(s) => s,
        Err(e) => {
            return error_to_c_string(format_err!(
                "Error while decoding auth token: {}",
                e
            ))
        }
    };

    let client_shim = ClientShim::new(endpoint.to_string(), Some(auth_token.to_string()));

    let private_share = get_master_key(&client_shim);

    match private_share {
        Ok(result) => return success_to_c_string(result),
        Err(e) => return error_to_c_string(format_err!("{}", e)),
    }
}


#[no_mangle]
pub extern "C" fn get_public_share_key(
    c_party2_public_key_json:*const c_char
) -> *mut c_char {

    let raw_party2_public_key_json = unsafe { CStr::from_ptr(c_party2_public_key_json) };
    let party2_public_key_json = match raw_party2_public_key_json.to_str() {
        Ok(s) => s,
        Err(e) => return error_to_c_string(format_err!("decoding raw private_share_json failed: {}", e))
    };

    let party2_public:Party2Public = match serde_json::from_str(party2_public_key_json){
        Ok(s) => s,
        Err(e) => {
            return error_to_c_string(format_err!("decoding private_share_json to PrivateShare failed: {}", e))
        }
    };

    let pk = party2_public.q.get_element();
    return success_to_c_string(pk)
}

#[no_mangle]
pub extern "C" fn get_public_share_key_with_derive(
    c_master_key_json: *const c_char,//masterkey
    c_x_pos: i32,//coinType
    c_y_pos: i32,//account:1,2
) -> *mut c_char {
    let raw_master_key_json = unsafe { CStr::from_ptr(c_master_key_json) };
    let master_key_json = match raw_master_key_json.to_str() {
        Ok(s) => s,
        Err(e) => return error_to_c_string(format_err!("decoding raw master_key_json failed: {}", e))
    };

    let x: BigInt = BigInt::from(c_x_pos);
    let y: BigInt = BigInt::from(c_y_pos);

    let mk: MasterKey2 = match serde_json::from_str(master_key_json){
        Ok(s) => s,
        Err(e) => {
            return error_to_c_string(format_err!("decoding master_key_json to MasterKey2 failed: {}", e))
        }
    };

    let mk_child: MasterKey2 = mk.get_child(vec![x.clone(), y.clone()]);

    let pk = mk_child.public.q.get_element();
    return success_to_c_string(pk)
}

#[test]
fn test_public_share_key() {
    let fs = std::fs::read_to_string("testAssets/party2public.json").unwrap();
    let rt = get_public_share_key(CString::new(fs).unwrap().into_raw());
}