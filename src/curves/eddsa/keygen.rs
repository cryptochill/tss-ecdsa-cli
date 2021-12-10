use std::{fs, time};
use std::string::String;
use curv::arithmetic::Converter;
use curv::BigInt;
use curv::cryptographic_primitives::proofs::sigma_dlog::DLogProof;
use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
use curv::elliptic::curves::ed25519::{Ed25519Scalar, FE, GE};
use curv::elliptic::curves::traits::{ECScalar, ECPoint};
use multi_party_eddsa::protocols::thresholdsig::{KeyGenBroadcastMessage1, KeyGenDecommitMessage1, Keys, Parameters};
use paillier::EncryptionKey;

use crate::common::{AEAD, aes_decrypt, aes_encrypt, AES_KEY_BYTES_LEN,
                    broadcast, Client, Params, PartySignup, poll_for_broadcasts,
                    poll_for_p2p, sendp2p, signup};
use crate::eddsa::{correct_verifiable_ss, CURVE_NAME};


pub fn run_keygen(addr: &String, keys_file_path: &String, params: &Vec<&str>) {
    let THRESHOLD: u16 = params[0].parse::<u16>().unwrap();
    let PARTIES: u16 = params[1].parse::<u16>().unwrap();
    let client = Client::new(addr.clone());

    // delay:
    let delay = time::Duration::from_millis(25);
    let parameters = Parameters {
        threshold: THRESHOLD as usize,
        share_count: PARTIES as usize,
    };

    //signup:
    let tn_params = Params {
        threshold: THRESHOLD.to_string(),
        parties: PARTIES.to_string(),
    };
    let signup_path = "signupkeygen";
    let (party_num_int, uuid) = match signup(signup_path, &client, &tn_params, CURVE_NAME).unwrap() {
        PartySignup { number, uuid } => (number, uuid),
    };
    println!("number: {:?}, uuid: {:?}, curve: {:?}", party_num_int, uuid, CURVE_NAME);

    let party_keys = Keys::phase1_create(party_num_int as usize);
    let (bc_i, decom_i) = party_keys.phase1_broadcast();

    // send commitment to ephemeral public keys, get round 1 commitments of other parties
    assert!(broadcast(
        &client,
        party_num_int,
        "round1",
        serde_json::to_string(&bc_i).unwrap(),
        uuid.clone()
    )
        .is_ok());
    let round1_ans_vec = poll_for_broadcasts(
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
        &client,
        party_num_int,
        "round2",
        serde_json::to_string(&decom_i).unwrap(),
        uuid.clone()
    )
    .is_ok());
    let round2_ans_vec = poll_for_broadcasts(
        &client,
        party_num_int,
        PARTIES,
        delay,
        "round2",
        uuid.clone(),
    );

    let mut j = 0;
    let mut point_vec: Vec<GE> = Vec::new();
    let mut blind_vec: Vec<BigInt> = Vec::new();
    let mut enc_keys: Vec<Vec<u8>> = Vec::new();
    let eight: Ed25519Scalar = ECScalar::from(&BigInt::from(8));
    let eight_invert = eight.invert();
    for i in 1..=PARTIES {
        if i == party_num_int {
            point_vec.push(decom_i.y_i);
            blind_vec.push(decom_i.clone().blind_factor);
        } else {
            let decom_j: KeyGenDecommitMessage1 = serde_json::from_str::<KeyGenDecommitMessage1>(&round2_ans_vec[j]).unwrap();
            let corrected_y_i = decom_j.y_i * eight_invert;
            point_vec.push(corrected_y_i);
            blind_vec.push(decom_j.clone().blind_factor);
            let key_bn: BigInt = (corrected_y_i * party_keys.u_i).x_coor().unwrap();
            let key_bytes = BigInt::to_bytes(&key_bn);
            let mut template: Vec<u8> = vec![0u8; AES_KEY_BYTES_LEN - key_bytes.len()];
            template.extend_from_slice(&key_bytes[..]);
            enc_keys.push(template);
            j = j + 1;
        }
    }

    let (head, tail) = point_vec.split_at(1);
    let y_sum = tail.iter().fold(head[0], |acc, x| acc + x);

    let key_gen_parties_points_vec = (0..PARTIES)
        .map(|i| i as usize + 1)
        .collect::<Vec<usize>>();

    let (vss_scheme, secret_shares, _index) = party_keys
        .phase1_verify_com_phase2_distribute(
            &parameters, &blind_vec, &point_vec, &bc1_vec, &key_gen_parties_points_vec
        )
        .expect("invalid key");

    //////////////////////////////////////////////////////////////////////////////

    let mut j = 0;
    for (k, i) in (1..=PARTIES).enumerate() {
        if i != party_num_int {
            // prepare encrypted ss for party i:
            let key_i = &enc_keys[j];
            let plaintext = BigInt::to_bytes(&secret_shares[k].to_big_int());
            let aead_pack_i = aes_encrypt(key_i, &plaintext);
            assert!(sendp2p(
                &client,
                party_num_int,
                i,
                "round3",
                serde_json::to_string(&aead_pack_i).unwrap(),
                uuid.clone()
            )
                .is_ok());
            j += 1;
        }
    }

    let round3_ans_vec = poll_for_p2p(
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
            let key_i = &enc_keys[j];
            let out = aes_decrypt(key_i, aead_pack);
            let out_bn = BigInt::from_bytes(&out[..]);
            let out_fe = ECScalar::from(&out_bn);
            party_shares.push(out_fe);

            j += 1;
        }
    }

    // round 4: send vss commitments
    assert!(broadcast(
        &client,
        party_num_int,
        "round4",
        serde_json::to_string(&vss_scheme).unwrap(),
        uuid.clone()
    )
        .is_ok());
    let round4_ans_vec = poll_for_broadcasts(
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
            //Since curv v0.7 does multiply GE's with 8 in deserialization, we have to correct them here:
            //See https://github.com/ZenGo-X/curv/issues/156#issuecomment-987657279
            let corrected_vss_scheme_j = correct_verifiable_ss(vss_scheme_j);
            vss_scheme_vec.push(corrected_vss_scheme_j);
            j += 1;
        }
    }

    let (shared_keys, dlog_proof) = party_keys
        .phase2_verify_vss_construct_keypair(
            &parameters,
            &point_vec,
            &party_shares,
            &vss_scheme_vec,
            &(party_num_int as usize),
        )
        .expect("invalid vss");

    // round 5: send dlog proof
    assert!(broadcast(
        &client,
        party_num_int,
        "round5",
        serde_json::to_string(&dlog_proof).unwrap(),
        uuid.clone()
    )
        .is_ok());
    let round5_ans_vec = poll_for_broadcasts(
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
            //Since curv v0.7 does multiply GE with 8 in deserialization, we have to correct them here:
            //See https://github.com/ZenGo-X/curv/issues/156#issuecomment-987657279
            let corrected_dlog_proof_j = DLogProof {
                pk: dlog_proof_j.pk * eight_invert,
                pk_t_rand_commitment: dlog_proof_j.pk_t_rand_commitment * eight_invert,
                challenge_response: dlog_proof_j.challenge_response
            };
            dlog_proof_vec.push(corrected_dlog_proof_j);
            j += 1;
        }
    }
    Keys::verify_dlog_proofs(&parameters, &dlog_proof_vec, &point_vec)
        .expect("bad dlog proof");

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

    fs::write(keys_file_path, keygen_json).expect("Unable to save !");
}