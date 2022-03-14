use curv::arithmetic::Converter;
use curv::BigInt;

use serde::{Deserialize, Serialize};
use curv::cryptographic_primitives::secret_sharing::feldman_vss::{ShamirSecretSharing, VerifiableSS};
use paillier::{DecryptionKey, EncryptionKey};
use curv::elliptic::curves::Secp256k1;
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2018::party_i::{Keys, SharedKeys};
use crate::ecdsa::{FE, GE};
use crate::ecdsa::keygen::KeygenFragment;


type OldFE = String;

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct OldGE {
    x: String,
    y: String
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OldKeys {
    pub u_i: OldFE,
    pub y_i: OldGE,
    pub dk: DecryptionKey,
    pub ek: EncryptionKey,
    pub party_index: u16,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OldSharedKeys {
    pub y: OldGE,
    pub x_i: OldFE,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct OldVerifiableSS {
    pub parameters: ShamirSecretSharing,
    pub commitments: Vec<OldGE>,
}

fn convert_old_GE(old: &OldGE) -> GE {
    let old_x = BigInt::from_hex(&old.x).unwrap();
    let old_y = &BigInt::from_hex(&old.y).unwrap();

    GE::from_coords(&old_x, &old_y).unwrap()
}

fn convert_old_FE(old: OldFE) -> FE {
    let old_bytes = hex::decode(old).unwrap();

    FE::from_bytes(old_bytes.as_slice()).unwrap()
}

fn convert_old_vss(vss: &OldVerifiableSS) -> VerifiableSS<Secp256k1> {

    let commitments = vss.commitments
        .iter()
        .map(|x| convert_old_GE(x))
        .collect();

    VerifiableSS{
        parameters: vss.clone().parameters,
        commitments
    }
}

pub fn convert_store_data(data: String) -> KeygenFragment{

    let (old_party_keys, old_shared_keys, party_id, old_vss_scheme_vec, paillier_key_vector, old_y_sum): (
        OldKeys,
        OldSharedKeys,
        u16,
        Vec<OldVerifiableSS>,
        Vec<EncryptionKey>,
        OldGE,
    ) = serde_json::from_str(&data).unwrap();


    let party_keys: Keys = Keys {
        u_i: convert_old_FE(old_party_keys.u_i),
        y_i: convert_old_GE(&old_party_keys.y_i),
        dk: old_party_keys.dk,
        ek: old_party_keys.ek,
        party_index: old_party_keys.party_index
    };

    let shared_keys = SharedKeys {
        y: convert_old_GE(&old_shared_keys.y),
        x_i: convert_old_FE(old_shared_keys.x_i)
    };

    let public_key = convert_old_GE(&old_y_sum);
    let vss_scheme_vector:Vec<VerifiableSS<Secp256k1>>  = old_vss_scheme_vec
        .iter()
        .map(|x| convert_old_vss(x))
        .collect();

    KeygenFragment{
        party_keys,
        shared_keys,
        party_id,
        vss_scheme_vector,
        paillier_key_vector,
        public_key
    }
}