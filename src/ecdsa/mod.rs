pub use keygen::get_master_key;
pub use types::PrivateShare;

pub mod test;
pub mod keygen;
pub mod types;
pub mod sign;
pub mod free;
pub mod key_derive;

#[derive(Serialize, Deserialize)]
pub struct ServerReply{
    retCode: i32,
    retMsg : String,
    result : Option<String>
}

