use std::fs;
use curv::arithmetic::Converter;
use curv::BigInt;
use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
use curv::elliptic::curves::{Ed25519, Scalar};
use multi_party_eddsa::protocols::{FE, GE};
use multi_party_eddsa::protocols::thresholdsig::{Keys, SharedKeys};
use serde_json::{json, Value};
use crate::common::Params;
use crate::eddsa::signer::update_hd_derived_public_key;
use crate::hd_keys;

pub mod keygen;
pub mod signer;
mod test;

pub static CURVE_NAME: &str = "EdDSA";


pub fn sign(manager_address:String, key_file_path: String, params: Vec<&str>, message_str:String, path: &str)
            -> Value {
    let params = Params {
        threshold: params[0].to_string(),
        parties: params[1].to_string(),
    };

    let (signature, y_sum) = signer::run_signer(manager_address, key_file_path, params, message_str.clone(), path);

    let ret_dict = json!({
        "r": (BigInt::from_bytes(&(signature.R.to_bytes(false)))).to_str_radix(16),
        "s": (BigInt::from_bytes(&(signature.s.to_bytes()))).to_str_radix(16),
        "status": "signature_ready",
        "x": &y_sum.x_coord().unwrap().to_str_radix(16),
        "y": &y_sum.y_coord().unwrap().to_str_radix(16),
        "msg_int": message_str.as_bytes().to_vec().as_slice(),
    });

    //fs::write("signature.json".to_string(), ret_dict.clone().to_string()).expect("Unable to save !");

    ret_dict
}


pub fn run_pubkey(keys_file_path:&str, path:&str) -> Value {

    // Read data from keys file
    let data = fs::read_to_string(keys_file_path).expect(
        format!("Unable to load keys file at location: {}", keys_file_path).as_str(),
    );
    let (_party_keys, _shared_keys, _party_id, _vss_scheme_vec, y_sum): (
        Keys,
        SharedKeys,
        u16,
        Vec<VerifiableSS<Ed25519>>,
        GE,
    ) = serde_json::from_str(&data).unwrap();

    // Get root pub key or HD pub key at specified path
    let (_f_l_new, y_sum): (FE, GE) = match path.is_empty() {
        true => (Scalar::<Ed25519>::zero(), y_sum),
        false => {
            let path_vector: Vec<BigInt> = path
                .split('/')
                .map(|s| BigInt::from_str_radix(s.trim(), 10).unwrap())
                .collect();
            let (y_sum_child, f_l_new) = hd_keys::get_hd_key(&y_sum, path_vector.clone());

            let safe_public_key_child = update_hd_derived_public_key(y_sum_child);

            (f_l_new, safe_public_key_child)
        }
    };

    // Return pub key as x,y
    let ret_dict = json!({
                "x": &y_sum.x_coord().unwrap().to_str_radix(16),
                "y": &y_sum.y_coord().unwrap().to_str_radix(16),
                "path": path,
            });
    ret_dict
}
