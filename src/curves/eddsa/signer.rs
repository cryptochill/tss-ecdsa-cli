use std::{fs, time};
use std::time::Duration;
use curv::arithmetic::{Converter};
use curv::BigInt;
use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
use curv::elliptic::curves::{Ed25519, Point, Scalar};
use multi_party_eddsa::protocols::{Signature, thresholdsig};
use multi_party_eddsa::protocols::thresholdsig::{
    EphemeralKey, EphemeralSharedKeys, KeyGenBroadcastMessage1, Keys, LocalSig, Parameters,
    SharedKeys
};
use sha2::{Sha512, Digest};
use crate::common::{AEAD, aes_decrypt, aes_encrypt, AES_KEY_BYTES_LEN, broadcast, Client, hd_keys, Params, PartySignup, poll_for_broadcasts, poll_for_p2p, sendp2p, signup};
use crate::eddsa::{CURVE_NAME};

type GE = Point<Ed25519>;
type FE = Scalar<Ed25519>;

//TODO Find a better approach to import and reuse run_signer() from multi-party-eddsa repo
pub fn run_signer(manager_address:String, key_file_path: String, params: Params, message_str:String, path: &str)
                  -> (Signature, GE) {
    // This function is written inspired from the
    // test function: protocols::thresholdsig::test::tests::test_t2_n5_sign_with_4_internal()
    let message = match hex::decode(message_str.clone()) {
        Ok(x) => x,
        Err(_e) => message_str.as_bytes().to_vec(),
    };
    let message = &message[..];
    let client = Client::new(manager_address);
    // delay:
    let delay = time::Duration::from_millis(25);

    let data = fs::read_to_string(key_file_path)
        .expect("Unable to load keys, did you run keygen first? ");
    let (party_keys, mut shared_keys, _, vss_scheme_vec, Y): (
        Keys,
        SharedKeys,
        u16,
        Vec<VerifiableSS<Ed25519>>,
        GE,
    ) = serde_json::from_str(&data).unwrap();

    let sign_at_path = !path.is_empty();
    // Get root pub key or HD pub key at specified path
    let (Y, f_l_new) = match path.is_empty() {
        true => (Y, FE::zero()),
        false => {
            let path_vector: Vec<BigInt> = path
                .split('/')
                .map(|s| BigInt::from_str_radix(s.trim(), 10).unwrap())
                .collect();
            let (y_sum_child, f_l_new) = hd_keys::get_hd_key(&Y, path_vector.clone());
            (y_sum_child.clone(), f_l_new)
        }
    };

    let THRESHOLD = params.threshold.parse::<u16>().unwrap();
    let PARTIES = params.parties.parse::<u16>().unwrap();
    //signup:
    let signup_path = "signupsign";
    let (party_num_int, uuid) = match signup(signup_path, &client, &params, CURVE_NAME.clone()).unwrap() {
        PartySignup { number, uuid } => (number, uuid),
    };
    println!("number: {:?}, uuid: {:?}, curve: {:?}", party_num_int, uuid, CURVE_NAME);

    if sign_at_path == true {
        shared_keys.y = Y.clone();
    }

    let (_eph_keys_vec, eph_shared_keys_vec, R, eph_vss_vec) = eph_keygen_t_n_parties(
        client.clone(),
        uuid.clone(),
        delay,
        THRESHOLD.clone(),
        PARTIES,
        party_num_int,
        &party_keys,
        &message,
    );

    let local_sig = LocalSig::compute(
        &message,
        &eph_shared_keys_vec[(party_num_int-1) as usize],
        &shared_keys,
    );

    let local_sig_vec = exchange_data(
        client.clone(),
        party_num_int,
        PARTIES,
        uuid,
        "round1_local_sig",
        delay,
        local_sig
    );

    let parties_index_vec = (0..PARTIES)
        .map(|i| i )
        .collect::<Vec<u16>>();

    let verify_local_sig = LocalSig::verify_local_sigs(
        &local_sig_vec,
        &parties_index_vec,
        &vss_scheme_vec,
        &eph_vss_vec,
    );

    assert!(verify_local_sig.is_ok());

    let vss_sum_local_sigs = verify_local_sig.unwrap();

    // each party / dealer can generate the signature
    let mut signature =
        thresholdsig::generate(&vss_sum_local_sigs, &local_sig_vec, &parties_index_vec, R);

    if sign_at_path {
        //This is a tweak made by Elichai Turkel but not recommended by him:
        update_signature(&mut signature, &Y, &message, f_l_new);
    }

    let verify_sig = signature.verify(&message, &Y);
    assert!(verify_sig.is_ok());

    (signature, Y)
}

fn update_signature(signature: &mut Signature, public_key: &Point<Ed25519>, message: &[u8], f_l_new: Scalar<Ed25519>) {
    let mut k = Sha512::new()
        .chain(&*signature.R.to_bytes(true))
        .chain(&*public_key.to_bytes(true))
        .chain(message)
        .finalize();
    // reverse because BigInt uses BigEndian.
    k.reverse();
    // This will reduce it mod the group order.
    let add_to_sigma = Scalar::from_bigint(&BigInt::from_bytes(&k));
    signature.s = signature.s.clone() + f_l_new * add_to_sigma;
}


pub fn eph_keygen_t_n_parties(
    client: Client,
    uuid: String,
    delay: Duration,
    t: u16, // system threshold
    n: u16, // number of signers
    party_num_int: u16,
    key_i: &Keys,
    message: &[u8],
) -> (
    EphemeralKey,
    Vec<EphemeralSharedKeys>,
    GE,
    Vec<VerifiableSS<Ed25519>>,
) {
    let parties = (0..n)
        .map(|i| i + 1)
        .collect::<Vec<u16>>();

    let parames = Parameters {
        threshold: t,
        share_count: n.clone(),
    };
    assert!(parties.len() as u16 > t && parties.len() as u16 <= n);

    let eph_party_key: EphemeralKey = EphemeralKey::ephermeral_key_create_from_deterministic_secret(
        key_i,
        message,
        party_num_int,
    );

    let mut bc1_vec = Vec::new();
    let mut blind_vec = Vec::new();
    let mut R_vec = Vec::new();
    let (bc_i, blind) = eph_party_key.phase1_broadcast();

    assert!(broadcast(
        &client,
        party_num_int,
        "eph_keygen_round1",
        serde_json::to_string(&(bc_i.clone(), blind.clone(), eph_party_key.R_i.clone())).unwrap(),
        uuid.clone()
    )
        .is_ok());
    let round1_ans_vec = poll_for_broadcasts(
        &client,
        party_num_int,
        n as u16,
        delay,
        "eph_keygen_round1",
        uuid.clone(),
    );

    let mut j = 0;
    let mut enc_keys: Vec<Vec<u8>> = Vec::new();
    for i in 1..=n {
        if i == party_num_int {
            bc1_vec.push(bc_i.clone());
            blind_vec.push(blind.clone());
            R_vec.push(eph_party_key.R_i.clone());
        } else {
            let (bc1_j, blind_j, R_i_j) =
                serde_json::from_str::<(KeyGenBroadcastMessage1, BigInt, GE)>(&round1_ans_vec[j]).unwrap();
            bc1_vec.push(bc1_j);
            blind_vec.push(blind_j);
            R_vec.push(R_i_j.clone());
            let key_bn: BigInt = (R_i_j * eph_party_key.r_i.clone()).x_coord().unwrap();
            let key_bytes = BigInt::to_bytes(&key_bn);
            let mut template: Vec<u8> = vec![0u8; AES_KEY_BYTES_LEN - key_bytes.len()];
            template.extend_from_slice(&key_bytes[..]);
            enc_keys.push(template);
            j += 1;
        }
    }

    let mut R_vec_iter = R_vec.iter();
    let head = R_vec_iter.next().unwrap();
    let tail = R_vec_iter;
    let R_sum = tail.fold(head.clone(), |acc, x| acc + x);
    let (vss_scheme, secret_shares) = eph_party_key
        .phase1_verify_com_phase2_distribute(
            &parames, &blind_vec, &R_vec, &bc1_vec, parties.as_slice(),
        )
        .expect("invalid key");

    // round 2: send vss commitments
    assert!(broadcast(
        &client,
        party_num_int,
        "eph_keygen_round2",
        serde_json::to_string(&vss_scheme).unwrap(),
        uuid.clone()
    )
        .is_ok());
    let round2_ans_vec = poll_for_broadcasts(
        &client,
        party_num_int,
        n as u16,
        delay,
        "eph_keygen_round2",
        uuid.clone(),
    );

    let mut j = 0;
    let mut vss_scheme_vec: Vec<VerifiableSS<Ed25519>> = Vec::new();
    for i in 1..=n {
        if i == party_num_int {
            vss_scheme_vec.push(vss_scheme.clone());
        } else {
            let vss_scheme_j: VerifiableSS<Ed25519> = serde_json::from_str(&round2_ans_vec[j]).unwrap();
            vss_scheme_vec.push(vss_scheme_j);
            j += 1;
        }
    }

    //////////////////////////////////////////////////////////////////////////////
    //I'm not sure if we need this phase in ephemeral mode or not?
    let mut j = 0;
    for (k, i) in (1..=n).enumerate() {
        if i != party_num_int {
            // prepare encrypted ss for party i:
            let key_i = &enc_keys[j];
            let plaintext = BigInt::to_bytes(&secret_shares[k].to_bigint());
            let aead_pack_i = aes_encrypt(key_i, &plaintext);
            assert!(sendp2p(
                &client,
                party_num_int,
                i as u16,
                "eph_keygen_round3",
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
        n as u16,
        delay,
        "eph_keygen_round3",
        uuid.clone(),
    );

    let mut j = 0;
    let mut party_shares: Vec<FE> = Vec::new();
    for i in 1..=n {
        if i == party_num_int {
            party_shares.push(secret_shares[(i - 1) as usize].clone());
        } else {
            let aead_pack: AEAD = serde_json::from_str(&round3_ans_vec[j]).unwrap();
            let key_i = &enc_keys[j];
            let out = aes_decrypt(key_i, aead_pack);
            let out_bn = BigInt::from_bytes(&out[..]);
            let out_fe = FE::from(&out_bn);
            party_shares.push(out_fe);
            j += 1;
        }
    }
    //////////////////////////////////////////////////////////////////////////////

    let mut shared_keys_vec = Vec::new();
    let eph_shared_key = eph_party_key
        .phase2_verify_vss_construct_keypair(
            &parames,
            &R_vec,
            &party_shares,
            &vss_scheme_vec,
            party_num_int,
        )
        .expect("invalid vss");

    // round 4: send shared key
    assert!(broadcast(
        &client,
        party_num_int,
        "eph_keygen_round4",
        serde_json::to_string(&eph_shared_key).unwrap(),
        uuid.clone()
    )
        .is_ok());
    let round4_ans_vec = poll_for_broadcasts(
        &client,
        party_num_int,
        n as u16,
        delay,
        "eph_keygen_round4",
        uuid.clone(),
    );

    let mut j = 0;
    for i in 1..=n {
        if i == party_num_int {
            shared_keys_vec.push(eph_shared_key.clone());
        } else {
            let shared_key_j:EphemeralSharedKeys = serde_json::from_str(&round4_ans_vec[j]).unwrap();
            shared_keys_vec.push(shared_key_j);
            j += 1;
        }
    }

    (eph_party_key, shared_keys_vec, R_sum, vss_scheme_vec)
}



pub fn exchange_data<T>(client:Client, party_num:u16, n:u16, uuid:String, round: &str, delay: Duration, data:T) -> Vec<T>
    where
        T: Clone + serde::de::DeserializeOwned + serde::Serialize,
{
    assert!(broadcast(
        &client,
        party_num,
        &round,
        serde_json::to_string(&data).unwrap(),
        uuid.clone()
    )
        .is_ok());
    let round_ans_vec = poll_for_broadcasts(
        &client,
        party_num,
        n,
        delay,
        &round,
        uuid.clone(),
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

