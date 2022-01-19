pub mod manager;
pub mod hd_keys;

use std::{thread, time, time::Duration};

use aes_gcm::{Aes256Gcm, Nonce};
use aes_gcm::aead::{Aead, NewAead};

use reqwest::blocking::Client as RequestClient;
use serde::{Deserialize, Serialize};
use rand::{rngs::OsRng, RngCore};


pub type Key = String;

#[derive(Clone)]
pub struct Client {
    client: RequestClient,
    address: String,
    pub uuid: String,
    delay: Duration,
    pub party_number: u16,
}

#[allow(dead_code)]
pub const AES_KEY_BYTES_LEN: usize = 32;

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct AEAD {
    pub ciphertext: Vec<u8>,
    pub tag: Vec<u8>,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct PartySignup {
    pub number: u16,
    pub uuid: String,
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

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Params {
    pub parties: String,
    pub threshold: String,
}

impl Client {
    pub fn new(purpose: String, curve_name: &str, address: String, delay: Duration, tn_params: Params) -> Self {

        let mut instance = Self {
            client: RequestClient::new(),
            address,
            delay,
            uuid: "".to_string(),
            party_number: 0
        };

        let signup_path = "signup".to_owned() + &purpose;
        let (party_num_int, uuid) = match instance.signup(&signup_path, &tn_params, curve_name).unwrap() {
            PartySignup { number, uuid } => (number, uuid),
        };

        instance.uuid = uuid;
        instance.party_number = party_num_int;

        instance
    }

    pub fn signup(&self, path:&str, params: &Params, curve_name: &str) -> Result<PartySignup, ()> {
        let res_body = self.post_request(path, (params, curve_name)).unwrap();
        serde_json::from_str(&res_body).unwrap()
    }

    pub fn post_request<T>(&self, path: &str, body: T) -> Option<String>
        where
            T: serde::ser::Serialize,
    {
        let address = self.address.clone();
        let retries = 3;
        let retry_delay = time::Duration::from_millis(250);
        for _i in 1..retries {
            let url = format!("{}/{}", address, path);
            let res = self.client.post(&url).json(&body).send();

            if let Ok(res) = res {
                return Some(res.text().unwrap());
            }
            thread::sleep(retry_delay);
        }
        None
    }

    pub fn broadcast(
        &self,
        round: &str,
        data: String,
    ) -> Result<(), ()> {
        let party_num: u16 = self.party_number;
        let sender_uuid: String = self.uuid.clone();
        let key = format!("{}-{}-{}", party_num, round, sender_uuid);
        let entry = Entry {
            key: key.clone(),
            value: data,
        };
        let res_body = self.post_request("set", entry).unwrap();
        serde_json::from_str(&res_body).unwrap()
    }

    pub fn sendp2p(
        &self,
        party_to: u16,
        round: &str,
        data: String,
    ) -> Result<(), ()> {
        let party_from: u16 = self.party_number;
        let sender_uuid: String = self.uuid.clone();

        let key = format!("{}-{}-{}-{}", party_from, party_to, round, sender_uuid);

        let entry = Entry {
            key: key.clone(),
            value: data,
        };

        let res_body = self.post_request("set", entry).unwrap();
        serde_json::from_str(&res_body).unwrap()
    }

    pub fn poll_for_broadcasts(
        &self,
        n: u16,
        round: &str,
    ) -> Vec<String> {
        let party_num: u16 = self.party_number;
        let sender_uuid: String = self.uuid.clone();

        let mut ans_vec = Vec::new();
        for i in 1..=n {
            if i != party_num {
                let key = format!("{}-{}-{}", i, round, sender_uuid);
                let index = Index { key };
                loop {
                    // add delay to allow the server to process request:
                    thread::sleep(self.delay);
                    let res_body = self.post_request("get", index.clone()).unwrap();
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

    pub fn poll_for_p2p(
        &self,
        n: u16,
        round: &str,
    ) -> Vec<String> {
        let party_num: u16 = self.party_number;
        let sender_uuid: String = self.uuid.clone();

        let mut ans_vec = Vec::new();
        for i in 1..=n {
            if i != party_num {
                let key = format!("{}-{}-{}-{}", i, party_num, round, sender_uuid);
                let index = Index { key };
                loop {
                    // add delay to allow the server to process request:
                    thread::sleep(self.delay);
                    let res_body = self.post_request("get", index.clone()).unwrap();
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

    pub fn exchange_data<T>(&self, n:u16, round: &str, data:T) -> Vec<T>
        where
            T: Clone + serde::de::DeserializeOwned + serde::Serialize,
    {
        let party_num:u16 = self.party_number;
        assert!(self.broadcast(
            &round,
            serde_json::to_string(&data).unwrap(),
        )
            .is_ok());
        let round_ans_vec = self.poll_for_broadcasts(
            n,
            &round,
        );

        let json_answers = round_ans_vec.clone();
        let mut j = 0;
        let mut answers: Vec<T> = Vec::new();
        for i in 1..=n {
            if i == party_num {
                answers.push(data.clone());
            } else {
                let data_j: T = serde_json::from_str::<T>(&json_answers[j].clone()).unwrap();
                answers.push(data_j);
                j += 1;
            }
        }

        return answers;
    }

}

#[allow(dead_code)]
pub fn aes_encrypt(key: &[u8], plaintext: &[u8]) -> AEAD {
    let aes_key = aes_gcm::Key::from_slice(key);
    let cipher = Aes256Gcm::new(aes_key);

    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let nonce = Nonce::from_slice(&nonce);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .expect("encryption failure!");

    AEAD {
        ciphertext: ciphertext,
        tag: nonce.to_vec(),
    }
}

#[allow(dead_code)]
pub fn aes_decrypt(key: &[u8], aead_pack: AEAD) -> Vec<u8> {
    let aes_key = aes_gcm::Key::from_slice(key);
    let nonce = Nonce::from_slice(&aead_pack.tag);
    let gcm = Aes256Gcm::new(aes_key);

    let out = gcm.decrypt(nonce, aead_pack.ciphertext.as_slice());
    out.unwrap()
}
