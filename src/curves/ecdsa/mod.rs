pub mod hd_keys;
pub mod keygen;
pub mod signer;
extern crate serde_json;
use serde_json::{json, Value};

use std::fs;

use crate::common::{Params};

//use aes_gcm::aead::{NewAead};

use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
use paillier::EncryptionKey;

use curv::{
    arithmetic::traits::Converter,
    elliptic::curves::secp256_k1::{FE, GE},
    elliptic::curves::traits::{ECPoint, ECScalar},
    BigInt,
};
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2018::party_i::{
    Keys, SharedKeys
};


//pub type Key = String;


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


pub fn run_pubkey_or_sign(action:&str, keysfile_path:&str, path:&str, message_str:&str, manager_addr:String, params:Vec<&str>) -> Value {

    // Read data from keys file
    let data = fs::read_to_string(keysfile_path).expect(
        format!("Unable to load keys file at location: {}", keysfile_path).as_str(),
    );
    let (party_keys, shared_keys, party_id, mut vss_scheme_vec, paillier_key_vector, y_sum): (
        Keys,
        SharedKeys,
        u16,
        Vec<VerifiableSS<GE>>,
        Vec<EncryptionKey>,
        GE,
    ) = serde_json::from_str(&data).unwrap();

    // Get root pub key or HD pub key at specified path
    let (f_l_new, y_sum) = match path.is_empty() {
        true => (ECScalar::zero(), y_sum),
        false => {
            let path_vector: Vec<BigInt> = path
                .split('/')
                .map(|s| BigInt::from_str_radix(s.trim(), 10).unwrap())
                .collect();
            let (y_sum_child, f_l_new) = hd_keys::get_hd_key(&y_sum, path_vector.clone());
            (f_l_new, y_sum_child.clone())
        }
    };

    // Return pub key as x,y
    let result = if action == "pubkey" {
        let ret_dict = json!({
                    "x": &y_sum.x_coor(),
                    "y": &y_sum.y_coor(),
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
            &mut vss_scheme_vec,
            paillier_key_vector,
            &y_sum,
            &params,
            &message,
            &f_l_new,
            !path.is_empty(),
        )
    };

    result
}
