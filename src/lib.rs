// #![feature(core_ffi_c)]
extern crate core;
extern crate curv;
#[macro_use]
extern crate failure;
extern crate kms;
#[macro_use]
extern crate log;
extern crate multi_party_ecdsa;
extern crate reqwest;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate serde_json;
extern crate zk_paillier;
extern crate alloc;

pub use curv::{arithmetic::traits::Converter, BigInt};

pub mod ecdsa;
pub mod utilities;

type Result<T> = std::result::Result<T, failure::Error>;

#[derive(Debug)]
pub struct ClientShim {
    pub client: reqwest::Client,
    pub auth_token: Option<String>,
    pub endpoint: String,
}

impl ClientShim {
    pub fn new(endpoint: String, auth_token: Option<String>) -> ClientShim {
        let client = reqwest::Client::new();
        ClientShim {
            client,
            auth_token,
            endpoint,
        }
    }
}

