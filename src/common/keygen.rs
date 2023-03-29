use std::{fs, time};

use curv::{
    arithmetic::traits::Converter,
    cryptographic_primitives::{
        proofs::sigma_dlog::DLogProof, secret_sharing::feldman_vss::VerifiableSS,
    },
    elliptic::curves::traits::{ECPoint, ECScalar},
    BigInt,
    elliptic::curves::secp256_k1::{FE, GE}
};
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2018::party_i::{
    KeyGenBroadcastMessage1, KeyGenDecommitMessage1, Keys, Parameters,
};
use paillier::EncryptionKey;
use reqwest::blocking::Client;

use crate::common::{aes_decrypt, aes_encrypt, broadcast, poll_for_broadcasts, poll_for_p2p, postb, sendp2p, PartySignup, AEAD, KeygenParams};

pub fn run_keygen(addr: &String, keysfile_path: &String, params: &Vec<&str>) {
    let THRESHOLD: u16 = params[0].parse::<u16>().unwrap();
    let PARTIES: u16 = params[1].parse::<u16>().unwrap();

    let client = Client::new();

    // delay:
    let delay = time::Duration::from_millis(25);
    let params = Parameters {
        threshold: THRESHOLD,
        share_count: PARTIES,
    };

    //signup:
    let tn_params = KeygenParams {
        threshold: THRESHOLD.to_string(),
        parties: PARTIES.to_string(),
    };
    let (party_num_int, uuid) = match keygen_signup(&addr, &client, &tn_params).unwrap() {
        PartySignup { number, uuid } => (number, uuid),
    };
    println!("number: {:?}, uuid: {:?}", party_num_int, uuid);

    let party_keys = Keys::create(party_num_int as usize);
    let (bc_i, decom_i) = party_keys.phase1_broadcast_phase3_proof_of_correct_key();

    // send commitment to ephemeral public keys, get round 1 commitments of other parties
    assert!(broadcast(
        &addr,
        &client,
        party_num_int,
        "round1",
        serde_json::to_string(&bc_i).unwrap(),
        uuid.clone(),
    )
    .is_ok());
    let round1_ans_vec = poll_for_broadcasts(
        &addr,
        &client,
        party_num_int,
        PARTIES,
        delay,
        "round1",
        uuid.clone(),
    );

    let mut bc1_vec = round1_ans_vec
        .iter()
        .map(|m| serde_json::from_str::<KeyGenBroadcastMessage1>(m).unwrap())
        .collect::<Vec<_>>();

    bc1_vec.insert(party_num_int as usize - 1, bc_i);

    // send ephemeral public keys and check commitments correctness
    assert!(broadcast(
        &addr,
        &client,
        party_num_int,
        "round2",
        serde_json::to_string(&decom_i).unwrap(),
        uuid.clone(),
    )
    .is_ok());
    let round2_ans_vec = poll_for_broadcasts(
        &addr,
        &client,
        party_num_int,
        PARTIES,
        delay,
        "round2",
        uuid.clone(),
    );

    let mut j = 0;
    let mut point_vec: Vec<GE> = Vec::new();
    let mut decom_vec: Vec<KeyGenDecommitMessage1> = Vec::new();
    let mut enc_keys: Vec<BigInt> = Vec::new();
    for i in 1..=PARTIES {
        if i == party_num_int {
            point_vec.push(decom_i.y_i);
            decom_vec.push(decom_i.clone());
        } else {
            let decom_j: KeyGenDecommitMessage1 = serde_json::from_str(&round2_ans_vec[j]).unwrap();
            point_vec.push(decom_j.y_i);
            decom_vec.push(decom_j.clone());
            enc_keys.push((decom_j.y_i.clone() * party_keys.u_i).x_coor().unwrap());
            j = j + 1;
        }
    }

    let (head, tail) = point_vec.split_at(1);
    let y_sum = tail.iter().fold(head[0], |acc, x| acc + x);

    let (vss_scheme, secret_shares, _index) = party_keys
        .phase1_verify_com_phase3_verify_correct_key_phase2_distribute(
            &params, &decom_vec, &bc1_vec,
        )
        .expect("invalid key");

    //////////////////////////////////////////////////////////////////////////////

    let mut j = 0;
    for (k, i) in (1..=PARTIES).enumerate() {
        if i != party_num_int {
            // prepare encrypted ss for party i:
            let key_i = BigInt::to_bytes(&enc_keys[j]);
            let plaintext = BigInt::to_bytes(&secret_shares[k].to_big_int());
            let aead_pack_i = aes_encrypt(&key_i, &plaintext);
            assert!(sendp2p(
                &addr,
                &client,
                party_num_int,
                i,
                "round3",
                serde_json::to_string(&aead_pack_i).unwrap(),
                uuid.clone(),
            )
            .is_ok());
            j += 1;
        }
    }

    let round3_ans_vec = poll_for_p2p(
        &addr,
        &client,
        party_num_int,
        PARTIES,
        delay,
        "round3",
        uuid.clone(),
    );

    let mut j = 0;
    let mut party_shares: Vec<FE> = Vec::new();
    for i in 1..=PARTIES {
        if i == party_num_int {
            party_shares.push(secret_shares[(i - 1) as usize]);
        } else {
            let aead_pack: AEAD = serde_json::from_str(&round3_ans_vec[j]).unwrap();
            let key_i = BigInt::to_bytes(&enc_keys[j]);
            let out = aes_decrypt(&key_i, aead_pack);
            let out_bn = BigInt::from_bytes(&out);
            let out_fe = ECScalar::from(&out_bn);
            party_shares.push(out_fe);

            j += 1;
        }
    }

    // round 4: send vss commitments
    assert!(broadcast(
        &addr,
        &client,
        party_num_int,
        "round4",
        serde_json::to_string(&vss_scheme).unwrap(),
        uuid.clone(),
    )
    .is_ok());
    let round4_ans_vec = poll_for_broadcasts(
        &addr,
        &client,
        party_num_int,
        PARTIES,
        delay,
        "round4",
        uuid.clone(),
    );

    let mut j = 0;
    let mut vss_scheme_vec: Vec<VerifiableSS<GE>> = Vec::new();
    for i in 1..=PARTIES {
        if i == party_num_int {
            vss_scheme_vec.push(vss_scheme.clone());
        } else {
            let vss_scheme_j: VerifiableSS<GE> = serde_json::from_str(&round4_ans_vec[j]).unwrap();
            vss_scheme_vec.push(vss_scheme_j);
            j += 1;
        }
    }

    let (shared_keys, dlog_proof) = party_keys
        .phase2_verify_vss_construct_keypair_phase3_pok_dlog(
            &params,
            &point_vec,
            &party_shares,
            &vss_scheme_vec,
            party_num_int as usize,
        )
        .expect("invalid vss");

    // round 5: send dlog proof
    assert!(broadcast(
        &addr,
        &client,
        party_num_int,
        "round5",
        serde_json::to_string(&dlog_proof).unwrap(),
        uuid.clone(),
    )
    .is_ok());
    let round5_ans_vec = poll_for_broadcasts(
        &addr,
        &client,
        party_num_int,
        PARTIES,
        delay,
        "round5",
        uuid.clone(),
    );

    let mut j = 0;
    let mut dlog_proof_vec: Vec<DLogProof<GE>> = Vec::new();
    for i in 1..=PARTIES {
        if i == party_num_int {
            dlog_proof_vec.push(dlog_proof.clone());
        } else {
            let dlog_proof_j: DLogProof<GE> = serde_json::from_str(&round5_ans_vec[j]).unwrap();
            dlog_proof_vec.push(dlog_proof_j);
            j += 1;
        }
    }
    Keys::verify_dlog_proofs(&params, &dlog_proof_vec, &point_vec).expect("bad dlog proof");

    //save key to file:
    let paillier_key_vec = (0..PARTIES)
        .map(|i| bc1_vec[i as usize].e.clone())
        .collect::<Vec<EncryptionKey>>();

    let keygen_json = serde_json::to_string(&(
        party_keys,
        shared_keys,
        party_num_int,
        vss_scheme_vec,
        paillier_key_vec,
        y_sum,
    ))
    .unwrap();
    println!("Keys data written to file: {:?}", keysfile_path);
    fs::write(&keysfile_path, keygen_json).expect("Unable to save !");
}

pub fn keygen_signup(addr: &String, client: &Client, params: &KeygenParams) -> Result<PartySignup, ()> {
    let res_body = postb(&addr, &client, "signupkeygen", params).unwrap();
    serde_json::from_str(&res_body).unwrap()
}
