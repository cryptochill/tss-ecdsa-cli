use std::{fs, time};

use curv::{
    arithmetic::traits::Converter,
    cryptographic_primitives::{
        proofs::sigma_dlog::DLogProof,
    },
    BigInt,
};
use curv::elliptic::curves::{Scalar, Secp256k1};
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2018::party_i::{
    KeyGenDecommitMessage1, Keys, Parameters,
};
use paillier::EncryptionKey;
use sha2::{Sha256};

use crate::common::{
    aes_decrypt, aes_encrypt, Params, AEAD, Client
};
use crate::ecdsa::{CURVE_NAME, FE, GE};

pub fn run_keygen(addr: &String, keysfile_path: &String, params: &Vec<&str>) {
    let THRESHOLD: u16 = params[0].parse::<u16>().unwrap();
    let PARTIES: u16 = params[1].parse::<u16>().unwrap();

    // delay:
    let delay = time::Duration::from_millis(25);
    let params = Parameters {
        threshold: THRESHOLD,
        share_count: PARTIES,
    };

    //signup:
    let tn_params = Params {
        threshold: THRESHOLD.to_string(),
        parties: PARTIES.to_string(),
    };

    let client_purpose = "keygen".to_string();
    let client = Client::new(client_purpose, CURVE_NAME, addr.to_string(), delay, tn_params);
    let (party_num_int, uuid) = (client.party_number, client.uuid.clone());
    println!("number: {:?}, uuid: {:?}, curve: {:?}", party_num_int, uuid, CURVE_NAME);

    let party_keys = Keys::create(party_num_int);
    let (bc_i, decom_i) = party_keys.phase1_broadcast_phase3_proof_of_correct_key();

    // send commitment to ephemeral public keys, get round 1 commitments of other parties
    let bc1_vector = client.exchange_data(PARTIES, "round1", bc_i);

    // send ephemeral public keys and check commitments correctness
    let decommit_vector: Vec<KeyGenDecommitMessage1> = client.exchange_data(PARTIES, "round2", decom_i);

    let point_vec: Vec<GE> = decommit_vector
        .iter()
        .map(|x| x.clone().y_i)
        .collect();

    let mut enc_keys: Vec<BigInt> = Vec::new();
    for i in 1..=PARTIES {
        if i != party_num_int {
            let decom_j = &decommit_vector[(i-1) as usize];
            enc_keys.push((decom_j.clone().y_i * party_keys.clone().u_i).x_coord().unwrap());
        }
    }

    let (head, tail) = point_vec.split_at(1);
    let public_key = tail.iter().fold(head[0].clone(), |acc, x| acc + x);

    let (vss_scheme, secret_shares, _index) = party_keys
        .phase1_verify_com_phase3_verify_correct_key_phase2_distribute(
            &params, &decommit_vector, &bc1_vector,
        )
        .expect("invalid key");

    //////////////////////////////////////////////////////////////////////////////

    let mut j = 0;
    for (k, i) in (1..=PARTIES).enumerate() {
        if i != party_num_int {
            // prepare encrypted ss for party i:
            let key_i = BigInt::to_bytes(&enc_keys[j]);
            let plaintext = BigInt::to_bytes(&secret_shares[k].to_bigint());
            let aead_pack_i = aes_encrypt(&key_i, &plaintext);
            assert!(client.sendp2p(
                i,
                "round3",
                serde_json::to_string(&aead_pack_i).unwrap(),
            )
            .is_ok());
            j += 1;
        }
    }

    let round3_ans_vec = client.poll_for_p2p(
        PARTIES,
        "round3",
    );

    let mut j = 0;
    let mut party_shares: Vec<FE> = Vec::new();
    for i in 1..=PARTIES {
        if i == party_num_int {
            party_shares.push(secret_shares[(i - 1) as usize].clone());
        } else {
            let aead_pack: AEAD = serde_json::from_str(&round3_ans_vec[j]).unwrap();
            let key_i = BigInt::to_bytes(&enc_keys[j]);
            let out = aes_decrypt(&key_i, aead_pack);
            let out_bn = BigInt::from_bytes(&out);
            let out_fe = Scalar::<Secp256k1>::from(&out_bn);
            party_shares.push(out_fe);

            j += 1;
        }
    }

    // round 4: send vss commitments
    let vss_scheme_vec = client.exchange_data(PARTIES, "round4", vss_scheme);

    let (shared_keys, dlog_proof) = party_keys
        .phase2_verify_vss_construct_keypair_phase3_pok_dlog(
            &params,
            &point_vec,
            &party_shares,
            &vss_scheme_vec,
            party_num_int,
        )
        .expect("invalid vss");

    // round 5: send dlog proof
    let dlog_proof_vec: Vec<DLogProof<Secp256k1, Sha256>> = client.exchange_data(PARTIES, "round5", dlog_proof);

    Keys::verify_dlog_proofs(&params, &dlog_proof_vec, &point_vec).expect("bad dlog proof");

    //save key to file:
    let paillier_key_vec = (0..PARTIES)
        .map(|i| bc1_vector[i as usize].e.clone())
        .collect::<Vec<EncryptionKey>>();

    let keygen_json = serde_json::to_string(&(
        party_keys,
        shared_keys,
        party_num_int,
        vss_scheme_vec,
        paillier_key_vec,
        public_key,
    ))
    .unwrap();
    println!("Keys data written to file: {:?}", keysfile_path);
    fs::write(&keysfile_path, keygen_json).expect("Unable to save !");
}
