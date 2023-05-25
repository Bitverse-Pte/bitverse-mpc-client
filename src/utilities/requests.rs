use std::time::Instant;

use floating_duration::TimeFormat;
use serde;

use super::super::ClientShim;

pub fn post<V>(client_shim: &ClientShim, path: &str) -> Option<V>
    where V: serde::de::DeserializeOwned
{
    _postb(client_shim, path, "{}")
}

pub fn postb<T, V>(client_shim: &ClientShim, path: &str, body: T) -> Option<V>
    where
        T: serde::ser::Serialize,
        V: serde::de::DeserializeOwned
{
    _postb(client_shim, path, body)
}

fn _postb<T, V>(client_shim: &ClientShim, path: &str, body: T) -> Option<V>
    where
        T: serde::ser::Serialize,
        V: serde::de::DeserializeOwned
{
    let start = Instant::now();

    let mut b = client_shim
        .client
        .post(&format!("{}/{}", client_shim.endpoint, path));

    if client_shim.auth_token.is_some() {
        b = b.bearer_auth(client_shim.auth_token.clone().unwrap());
    }

    let res = b.json(&body).send();

    info!("(req {}, took: {})", path, TimeFormat(start.elapsed()));

    let value = match res {
        Ok(mut v) => v.text().unwrap(),
        Err(_) => return None
    };

    Some(serde_json::from_str(value.as_str()).unwrap())
}