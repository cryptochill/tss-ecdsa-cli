pub mod hd_keys;
pub mod keygen;
pub mod manager;
pub mod signer;

use std::{env, iter::repeat, thread, time, time::Duration};
use std::collections::HashMap;
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};
use std::time::Instant;

use aes_gcm::{Aes256Gcm, Nonce};
use aes_gcm::aead::{NewAead, Aead, Payload};
use std::convert::TryFrom;

use curv::{
    arithmetic::traits::Converter,
    elliptic::curves::secp256_k1::{FE, GE},
    elliptic::curves::traits::{ECPoint, ECScalar},
    BigInt,
};
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use curv::cryptographic_primitives::hashing::hash_sha256::HSha256;
use curv::cryptographic_primitives::hashing::traits::Hash;
use uuid::Uuid;


pub type Key = String;
pub const SIGNUP_TIMEOUT_ENV: &str = "TSS_MANAGER_SIGNUP_TIMEOUT";
pub const SIGNUP_TIMEOUT_DEFAULT: &str = "5";

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
    pub room_uuid: String
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct SigningPartyInfo {
    pub party_id: String,
    pub party_order: u16,
    pub last_ping: u64,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct SigningRoom {
    pub room_id: String, // ID set by clients/parties, used during signup
    pub room_uuid: String, // ID set by manager, used during the rounds
    pub room_size: u16,
    pub member_info: HashMap<u16, SigningPartyInfo>,
    pub last_stage: String
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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
enum Thing {
    ThingA(Entry),
    ThingB(ManagerError),
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
                let answer: Result<Entry, ()> = serde_json::from_str(&res_body).unwrap();
                if let Ok(answer) = answer {
                    ans_vec.push(answer.value);
                    println!("[{:?}] party {:?} => party {:?}", round, i, party_num);
                    break;
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

fn new_sign_party(party_order: u16) -> SigningPartySignup {
    SigningPartySignup {
        party_order,
        room_uuid: "".to_string(),
        party_uuid: Uuid::new_v4().to_string(),
    }
}

fn new_signing_room(room_id: String, size: u16) -> SigningRoom {
    SigningRoom {
        room_size: size,
        member_info: Default::default(),
        room_id,
        last_stage: "signup".to_string(),
        room_uuid: Uuid::new_v4().to_string(),
    }
}

fn sha256_digest(input: &[u8]) -> String {
    return HSha256::create_hash_from_slice(input).to_hex();
}

impl SigningRoom {

    fn is_full(&self) -> bool {
       self.member_info.len() == usize::from(self.room_size)
    }

    fn add_party(&mut self, party_number: u16) -> SigningPartySignup {
        let party_signup= new_sign_party(
            u16::try_from(self.member_info.len()).unwrap() + 1,
        );
        self.member_info.insert(party_number, SigningPartyInfo{
            party_id: party_signup.party_uuid.clone(),
            party_order: party_signup.party_order,
            last_ping: SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs()
        });

        /*if self.member_info.len() >= self.room_size {
            self.last_stage = "signup-completed".to_string();
        }*/

        party_signup.clone()
    }

    fn replace_party(&mut self, party_number: u16) -> SigningPartySignup {
        let old_party = self.member_info.get(&party_number).unwrap();
        let party_signup= new_sign_party(old_party.party_order);
        *self.member_info.get_mut(&party_number).unwrap() = SigningPartyInfo{
            party_id: party_signup.party_uuid.clone(),
            party_order: party_signup.party_order,
            last_ping: SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs()
        };

        party_signup.clone()
    }

    fn are_all_members_active(&self) -> bool {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let timeout = u64::from_str(
            env::var(SIGNUP_TIMEOUT_ENV).unwrap_or(SIGNUP_TIMEOUT_DEFAULT.to_string()).as_str()
        ).unwrap();

        self.member_info.values().all(
            |x| x.last_ping > now - timeout
        )
    }

    fn are_all_members_inactive(&self) -> bool {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let timeout = u64::from_str(
            env::var(SIGNUP_TIMEOUT_ENV).unwrap_or(SIGNUP_TIMEOUT_DEFAULT.to_string()).as_str()
        ).unwrap();

        self.is_full() && (!self.member_info.values().any(
            |x| x.last_ping > now - timeout
        ))
    }

    fn is_member_active(&self, party_number: u16) -> bool {
        let party_data = self.member_info.get(&party_number).unwrap();
        let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();
        let timeout = u64::from_str(
            env::var(SIGNUP_TIMEOUT_ENV).unwrap_or(SIGNUP_TIMEOUT_DEFAULT.to_string()).as_str()
        ).unwrap();

        party_data.last_ping > now - timeout
    }

    fn update_ping(&mut self, party_number: u16) -> SigningPartySignup {
        let party_data = self.member_info.get_mut(&party_number).unwrap();
        party_data.last_ping = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();
        if self.is_full() && self.are_all_members_active() {
            self.last_stage = "terminated".to_string();
        }
        self.get_signup_info(party_number)
    }

    fn has_member(&self, party_number: u16, party_uuid: String) -> bool {
        self.member_info.contains_key(&party_number) &&
            self.member_info.get(&party_number).unwrap().party_id == party_uuid
    }

    fn get_signup_info(&self, party_number: u16) -> SigningPartySignup {
        let member_info = self.member_info.get(&party_number).unwrap();
        let room_uuid = if self.last_stage == "signup" {
            "".to_string()
        }
        else {
            self.room_uuid.clone()
        };
        SigningPartySignup{
            party_order: member_info.party_order,
            party_uuid: member_info.party_id.clone(),
            room_uuid
        }
    }
}