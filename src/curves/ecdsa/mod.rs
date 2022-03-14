pub mod keygen;
pub mod signer;
mod test;
pub mod curv7_conversion;

extern crate serde_json;
use serde_json::{json, Value};

use std::fs;

use crate::common::{hd_keys, Params};

//use aes_gcm::aead::{NewAead};

use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
use paillier::EncryptionKey;

use curv::{
    arithmetic::traits::Converter,
    BigInt,
};
use curv::elliptic::curves::{Point, Scalar, Secp256k1};
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2018::party_i::{
    Keys, SharedKeys
};
use crate::ecdsa::curv7_conversion::convert_store_data;
use crate::ecdsa::keygen::KeygenFragment;


//pub type Key = String;
pub static CURVE_NAME: &str = "ECDSA";
pub type FE = Scalar<Secp256k1>;
pub type GE = Point<Secp256k1>;

#[allow(dead_code)]
pub fn check_sig(
    r: &Scalar<Secp256k1>,
    s: &Scalar<Secp256k1>,
    msg: &BigInt,
    pk: &Point<Secp256k1>,
) {
    use secp256k1::{verify, Message, PublicKey, PublicKeyFormat, Signature};

    let raw_msg = BigInt::to_bytes(msg);
    let mut msg: Vec<u8> = Vec::new(); // padding
    msg.extend(vec![0u8; 32 - raw_msg.len()]);
    msg.extend(raw_msg.iter());

    let msg = Message::parse_slice(msg.as_slice()).unwrap();
    let mut raw_pk = pk.to_bytes(false).to_vec();
    if raw_pk.len() == 64 {
        raw_pk.insert(0, 4u8);
    }
    let pk = PublicKey::parse_slice(&raw_pk, Some(PublicKeyFormat::Full)).unwrap();

    let mut compact: Vec<u8> = Vec::new();
    let bytes_r = &r.to_bytes().to_vec();
    compact.extend(vec![0u8; 32 - bytes_r.len()]);
    compact.extend(bytes_r.iter());

    let bytes_s = &s.to_bytes().to_vec();
    compact.extend(vec![0u8; 32 - bytes_s.len()]);
    compact.extend(bytes_s.iter());

    let secp_sig = Signature::parse_slice(compact.as_slice()).unwrap();

    let is_correct = verify(&msg, &secp_sig, &pk);
    assert!(is_correct);
}


pub fn run_pubkey_or_sign(action:&str, keysfile_path:&str, path:&str, message_str:&str, manager_addr:String, params:Vec<&str>) -> Value {

    let party_fragment = read_keygen_fragment_file(keysfile_path.to_string());
    let KeygenFragment {
        party_keys,
        shared_keys,
        party_id,
        mut vss_scheme_vector,
        paillier_key_vector,
        public_key
    } = party_fragment;

    // Get root pub key or HD pub key at specified path
    let (f_l_new, public_key) = match path.is_empty() {
        true => (Scalar::<Secp256k1>::zero(), public_key),
        false => {
            let path_vector: Vec<BigInt> = path
                .split('/')
                .map(|s| BigInt::from_str_radix(s.trim(), 10).unwrap())
                .collect();
            let (y_sum_child, f_l_new) = hd_keys::get_hd_key(&public_key, path_vector.clone());
            (f_l_new, y_sum_child.clone())
        }
    };

    // Return pub key as x,y
    let result = if action == "pubkey" {
        let ret_dict = json!({
                    "x": &public_key.x_coord().unwrap().to_str_radix(16),
                    "y": &public_key.y_coord().unwrap().to_str_radix(16),
                    "path": path,
                });
        ret_dict
    }
    else {
        // Parse message to sign
        let message = match hex::decode(message_str.clone()) {
            Ok(x) => x,
            Err(_e) => message_str.as_bytes().to_vec(),
        };
        let message = &message[..];

        //            println!("sign me {:?} / {:?} / {:?}", manager_addr, message, params);
        let params = Params {
            threshold: params[0].to_string(),
            parties: params[1].to_string(),
        };
        signer::sign(
            manager_addr,
            party_keys,
            shared_keys,
            party_id,
            &mut vss_scheme_vector,
            paillier_key_vector,
            &public_key,
            &params,
            &message,
            &f_l_new,
            !path.is_empty(),
        )
    };

    result
}

fn read_keygen_fragment_file(fragment_path: String) -> KeygenFragment{
    // Read data from keys file
    let data = fs::read_to_string(fragment_path.clone()).expect(
        format!("Unable to load keys file at location: {}", fragment_path).as_str(),
    );

    let res = serde_json::from_str(&data);

    if res.is_ok() {
        let (party_keys, shared_keys, party_id, vss_scheme_vector, paillier_key_vector, public_key): (
            Keys,
            SharedKeys,
            u16,
            Vec<VerifiableSS<Secp256k1>>,
            Vec<EncryptionKey>,
            GE,
        ) = res.unwrap();

        return KeygenFragment{
            party_keys,
            shared_keys,
            party_id,
            vss_scheme_vector,
            paillier_key_vector,
            public_key
        }
    }

    //println!("Could not load the fragment file. Trying to convert from format curv v0.7 if possible...");
    let fragment_data = convert_store_data(data);

    fragment_data
}