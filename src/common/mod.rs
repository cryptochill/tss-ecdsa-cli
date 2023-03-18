pub mod hd_keys;
pub mod keygen;
pub mod manager;
pub mod signer;
pub mod signing_room;

use std::{iter::repeat, thread, time, time::Duration};
use std::time::Instant;

use aes_gcm::{Aes256Gcm, Nonce};
use aes_gcm::aead::{NewAead, Aead, Payload};

use curv::{
    elliptic::curves::secp256_k1::{FE, GE},
    elliptic::curves::traits::{ECPoint, ECScalar},
    BigInt,
};
use curv::arithmetic::Converter;
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use curv::cryptographic_primitives::hashing::hash_sha256::HSha256;
use curv::cryptographic_primitives::hashing::traits::Hash;


pub type Key = String;

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct AEAD {
    pub ciphertext: Vec<u8>,
    pub tag: Vec<u8>,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct PartySignupRequestBody {
    pub threshold: u16,
    pub room_id: String,
    pub party_number: u16,  // It's better to rename this to fragment_index
    pub party_uuid: String
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct PartySignup {
    pub number: u16,
    pub uuid: String,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct SigningPartySignup {
    pub party_order: u16,
    pub party_uuid: String,
    pub room_uuid: String,
    pub total_joined: u16,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct SigningPartyInfo {
    pub party_id: String,
    pub party_order: u16,
    pub last_ping: u64,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct Index {
    pub key: Key,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct Entry {
    pub key: Key,
    pub value: String,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct ManagerError {
    pub error: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Params {
    pub parties: String,
    pub threshold: String,
}

#[allow(dead_code)]
pub fn aes_encrypt(key: &[u8], plaintext: &[u8]) -> AEAD {

    let mut full_length_key:[u8; 32] = [0; 32];
    full_length_key[(32 - key.len())..].copy_from_slice(key);//Pad key with zeros

    let aes_key = aes_gcm::Key::from_slice(full_length_key.as_slice());
    let cipher = Aes256Gcm::new(aes_key);

    let nonce_vector: Vec<u8> = repeat(3).take(12).collect();
    let nonce = Nonce::from_slice(nonce_vector.as_slice());

    let out_tag: Vec<u8> = repeat(0).take(16).collect();

    let text_payload = Payload {
        msg: plaintext,
        aad: &out_tag.as_slice()
    };

    let ciphertext = cipher.encrypt(nonce, text_payload)
        .expect("encryption failure!"); // NOTE: handle this error to avoid panics!

    AEAD {
        ciphertext: ciphertext,
        tag: out_tag.to_vec(),
    }
}

#[allow(dead_code)]
pub fn aes_decrypt(key: &[u8], aead_pack: AEAD) -> Vec<u8> {

    let mut full_length_key:[u8; 32] = [0; 32];
    full_length_key[(32 - key.len())..].copy_from_slice(key);//Pad key with zeros

    let aes_key = aes_gcm::Key::from_slice(full_length_key.as_slice());

    let nonce_vector: Vec<u8> = repeat(3).take(12).collect();
    let nonce = Nonce::from_slice(nonce_vector.as_slice());

    let gcm = Aes256Gcm::new(aes_key);

    let text_payload = Payload {
        msg: aead_pack.ciphertext.as_slice(),
        aad: aead_pack.tag.as_slice()
    };

    let out = gcm.decrypt(nonce, text_payload);
    out.unwrap_or_default()
}

pub fn postb<T>(addr: &String, client: &Client, path: &str, body: T) -> Option<String>
where
    T: serde::ser::Serialize,
{
    //    let mut addr = env::args()
    //        .nth(4)
    //        .unwrap_or_else(|| "http://127.0.0.1:8001".to_string());
    //    for argument in env::args() {
    //        if argument.contains("://") {
    //            let addr_parts: Vec<&str> = argument.split("http:").collect();
    //            addr = format!("http:{}", addr_parts[1]);
    //        }
    //    }
    let retries = 3;
    let retry_delay = time::Duration::from_millis(250);
    for _i in 1..retries {
        let addr = format!("{}/{}", addr, path);
        let res = client.post(&addr).json(&body).send();

        if let Ok(res) = res {
            return Some(res.text().unwrap());
        }
        thread::sleep(retry_delay);
    }
    None
}

pub fn broadcast(
    addr: &String,
    client: &Client,
    party_num: u16,
    round: &str,
    data: String,
    sender_uuid: String,
) -> Result<(), ()> {
    let key = format!("{}-{}-{}", party_num, round, sender_uuid);
    let entry = Entry {
        key: key.clone(),
        value: data,
    };

    let res_body = postb(&addr, &client, "set", entry).unwrap();
    serde_json::from_str(&res_body).unwrap()
}

pub fn sendp2p(
    addr: &String,
    client: &Client,
    party_from: u16,
    party_to: u16,
    round: &str,
    data: String,
    sender_uuid: String,
) -> Result<(), ()> {
    let key = format!("{}-{}-{}-{}", party_from, party_to, round, sender_uuid);

    let entry = Entry {
        key: key.clone(),
        value: data,
    };

    let res_body = postb(&addr, &client, "set", entry).unwrap();
    serde_json::from_str(&res_body).unwrap()
}

pub fn poll_for_broadcasts(
    addr: &String,
    client: &Client,
    party_num: u16,
    n: u16,
    delay: Duration,
    round: &str,
    sender_uuid: String,
) -> Vec<String> {
    let mut ans_vec = Vec::new();
    let timeout = std::env::var("TSS_CLI_POLL_TIMEOUT")
        .unwrap_or("30".to_string()).parse::<u64>().unwrap();
    for i in 1..=n {
        if i != party_num {
            let key = format!("{}-{}-{}", i, round, sender_uuid);
            let index = Index { key };
            let start_time = Instant::now();
            loop {
                // add delay to allow the server to process request:
                let res_body = postb(&addr, &client, "get", index.clone()).unwrap();
                let answer: Result<Entry, ManagerError> = serde_json::from_str(&res_body).unwrap();
                match answer {
                    Ok(answer) => {
                        ans_vec.push(answer.value);
                        println!("[{:?}] party {:?} => party {:?}", round, i, party_num);
                        break;
                    },
                    Err(ManagerError{error}) => {
                        #[cfg(debug_assertions)]
                        println!("[{:?}] party {:?} => party {:?}, error: {:?}", round, i, party_num, error);
                    }
                }
                if start_time.elapsed().as_secs() > timeout {
                    panic!("Polling timed out! No response received from party number {:?}", i);
                };

                thread::sleep(delay);
            }
        }
    }
    ans_vec
}

pub fn poll_for_p2p(
    addr: &String,
    client: &Client,
    party_num: u16,
    n: u16,
    delay: Duration,
    round: &str,
    sender_uuid: String,
) -> Vec<String> {
    let mut ans_vec = Vec::new();
    for i in 1..=n {
        if i != party_num {
            let key = format!("{}-{}-{}-{}", i, party_num, round, sender_uuid);
            let index = Index { key };
            loop {
                // add delay to allow the server to process request:
                thread::sleep(delay);
                let res_body = postb(&addr, &client, "get", index.clone()).unwrap();
                let answer: Result<Entry, ManagerError> = serde_json::from_str(&res_body).unwrap();
                match answer {
                    Ok(answer) => {
                        ans_vec.push(answer.value);
                        println!("[{:?}] party {:?} => party {:?}", round, i, party_num);
                        break;
                    },
                    Err(ManagerError{error}) => {
                        #[cfg(debug_assertions)]
                        println!("[{:?}] party {:?} => party {:?}, error: {:?}", round, i, party_num, error);
                        break;
                    }
                }
            }
        }
    }
    ans_vec
}

#[allow(dead_code)]
pub fn check_sig(r: &FE, s: &FE, msg: &BigInt, pk: &GE) {
    use secp256k1::{verify, Message, PublicKey, PublicKeyFormat, Signature};

    let raw_msg = BigInt::to_bytes(&msg);
    let mut msg: Vec<u8> = Vec::new(); // padding
    msg.extend(vec![0u8; 32 - raw_msg.len()]);
    msg.extend(raw_msg.iter());

    let msg = Message::parse_slice(msg.as_slice()).unwrap();
    let mut raw_pk = pk.pk_to_key_slice();
    if raw_pk.len() == 64 {
        raw_pk.insert(0, 4u8);
    }
    let pk = PublicKey::parse_slice(&raw_pk, Some(PublicKeyFormat::Full)).unwrap();

    let mut compact: Vec<u8> = Vec::new();
    let bytes_r = &r.get_element()[..];
    compact.extend(vec![0u8; 32 - bytes_r.len()]);
    compact.extend(bytes_r.iter());

    let bytes_s = &s.get_element()[..];
    compact.extend(vec![0u8; 32 - bytes_s.len()]);
    compact.extend(bytes_s.iter());

    let secp_sig = Signature::parse_slice(compact.as_slice()).unwrap();

    let is_correct = verify(&msg, &secp_sig, &pk);
    assert!(is_correct);
}


fn sha256_digest(input: &[u8]) -> String {
    return HSha256::create_hash_from_slice(input).to_hex();
}
