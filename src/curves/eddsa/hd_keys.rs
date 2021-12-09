use std::fs;
use curv::arithmetic::{BasicOps, Converter, One};
use curv::BigInt;
use curv::cryptographic_primitives::hashing::hmac_sha512;
use curv::cryptographic_primitives::hashing::traits::KeyedHash;
use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
use curv::elliptic::curves::ed25519::{Ed25519Scalar, FE, GE};
use curv::elliptic::curves::traits::{ECScalar, ECPoint};
use multi_party_eddsa::protocols::thresholdsig::{Keys, SharedKeys};
use paillier::EncryptionKey;
use serde_json::{json, Value};
use crate::eddsa::hd_keys;

pub fn run_pubkey(keys_file_path:&str, path:&str) -> Value {

    // Read data from keys file
    let data = fs::read_to_string(keys_file_path).expect(
        format!("Unable to load keys file at location: {}", keys_file_path).as_str(),
    );
    let (_party_keys, _shared_keys, _party_id, _vss_scheme_vec, _paillier_key_vector, mut y_sum): (
        Keys,
        SharedKeys,
        u16,
        Vec<VerifiableSS<GE>>,
        Vec<EncryptionKey>,
        GE,
    ) = serde_json::from_str(&data).unwrap();

    //Since curv v0.7 does multiply GE's with 8 in deserialization, we have to correct them here:
    //See https://github.com/ZenGo-X/curv/issues/156#issuecomment-987657279
    let eight: Ed25519Scalar = ECScalar::from(&BigInt::from(8));
    let eight_invert = eight.invert();
    y_sum = y_sum * eight_invert;

    // Get root pub key or HD pub key at specified path
    let (_f_l_new, y_sum): (Ed25519Scalar, GE) = match path.is_empty() {
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
    let ret_dict = json!({
                "x": &y_sum.x_coor(),
                "y": &y_sum.y_coor(),
                "path": path,
            });
    ret_dict
}


//This is almost the duplicate of the ecdsa::hd_keys::get_hd_key()
//TODO Implement a generic version of this function over ECDSA and EdDSA curves
pub fn get_hd_key(y_sum: &GE, path_vector: Vec<BigInt>) -> (GE, FE) {
    // generate a random but shared chain code, this will do
    let chain_code = GE::generator();
    //    println!("chain code {:?}", chain_code);
    // derive a new pubkey and LR sequence, y_sum becomes a new child pub key
    let (y_sum_child, f_l_new, _cc_new) = hd_key(
        path_vector,
        &y_sum,
        &chain_code.bytes_compressed_to_big_int(),
    );
    let y_sum = y_sum_child.clone();
    //    println!("New public key: {:?}", &y_sum);
    //    println!("Public key X: {:?}", &y_sum.x_coor());
    //    println!("Public key Y: {:?}", &y_sum.y_coor());
    (y_sum, f_l_new)
}

//This is almost the duplicate of the ecdsa::hd_keys::hd_key()
//TODO Implement a generic version of this function over ECDSA and EdDSA curves
pub fn hd_key(
    mut location_in_hir: Vec<BigInt>,
    pubkey: &GE,
    chain_code_bi: &BigInt,
) -> (GE, FE, GE) {
    let mask = BigInt::from(2).pow(256) - BigInt::one();
    // let public_key = self.public.q.clone();

    // calc first element:
    let first = location_in_hir.remove(0);
    let pub_key_bi = pubkey.bytes_compressed_to_big_int();
    let f = hmac_sha512::HMacSha512::create_hmac(&chain_code_bi, &[&pub_key_bi, &first]);
    let f_l = &f >> 256;
    let f_r = &f & &mask;
    let f_l_fe: FE = ECScalar::from(&f_l);
    let f_r_fe: FE = ECScalar::from(&f_r);

    let bn_to_slice = BigInt::to_bytes(chain_code_bi);
    let chain_code = GE::from_bytes(&bn_to_slice.as_slice()).unwrap() * &f_r_fe;
    let g: GE = ECPoint::generator();
    let pub_key = *pubkey + g * &f_l_fe;

    let (public_key_new_child, f_l_new, cc_new) =
        location_in_hir
            .iter()
            .fold((pub_key, f_l_fe, chain_code), |acc, index| {
                let pub_key_bi = acc.0.bytes_compressed_to_big_int();
                let f = hmac_sha512::HMacSha512::create_hmac(
                    &acc.2.bytes_compressed_to_big_int(),
                    &[&pub_key_bi, index],
                );
                let f_l = &f >> 256;
                let f_r = &f & &mask;
                let f_l_fe: FE = ECScalar::from(&f_l);
                let f_r_fe: FE = ECScalar::from(&f_r);

                (acc.0 + g * &f_l_fe, f_l_fe + &acc.1, &acc.2 * &f_r_fe)
            });
    (public_key_new_child, f_l_new, cc_new)
}
