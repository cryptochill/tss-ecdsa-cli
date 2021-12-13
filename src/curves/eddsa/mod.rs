use curv::arithmetic::Converter;
use curv::BigInt;
use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
use curv::elliptic::curves::ed25519::{Ed25519Scalar, GE};
use curv::elliptic::curves::traits::{ECScalar, ECPoint};
use serde_json::{json, Value};
use crate::common::Params;

pub mod keygen;
pub mod signer;
pub mod hd_keys;
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
        "r": (BigInt::from_bytes(&(signature.R.get_element()).to_bytes())).to_str_radix(16),
        "s": (BigInt::from_bytes(&(signature.sigma.get_element()).to_bytes())).to_str_radix(16),
        "status": "signature_ready",
        //TODO Implement recid
        //"recid": signature.recid.clone(),
        "x": &y_sum.x_coor(),
        "y": &y_sum.y_coor(),
        "msg_int": message_str.as_bytes().to_vec().as_slice(),
    });

    ret_dict
}

pub fn correct_verifiable_ss(vss: VerifiableSS<GE>) -> VerifiableSS<GE> {
    //Since curv v0.7 does multiply GE's with 8 in deserialization, we have to correct them here:
    //See https://github.com/ZenGo-X/curv/issues/156#issuecomment-987657279
    let eight: Ed25519Scalar = ECScalar::from(&BigInt::from(8));
    let eight_invert = eight.invert();

    let corrected_commitments = vss.commitments.iter()
        .map(|g| g * &eight_invert)
        .collect();

    let corrected_vss = VerifiableSS {
        parameters: vss.parameters,
        commitments: corrected_commitments,
    };

    corrected_vss
}