#[cfg(test)]
mod tests {
    use std::{fs, thread};
    use std::time::Duration;
    use curv::arithmetic::Converter;
    use curv::BigInt;
    use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
    use curv::elliptic::curves::Secp256k1;
    use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2018::party_i::{Keys, SharedKeys};
    use paillier::EncryptionKey;
    use glob::glob;
    use crate::common::hd_keys;
    use crate::ecdsa::GE;
    use crate::ecdsa::keygen::run_keygen;
    use crate::manager::run_manager;

    #[test]
    fn test_key_generation() {
        let parties_count: u16 = 5;
        let address = "http://127.0.0.1:8001";
        let mut threads = Vec::new();

        for entry in glob("/tmp/ecdsa-test-*.store").unwrap() {
            let entry = entry.unwrap();
            let _ = std::fs::remove_file(entry.as_path());
        }

        thread::spawn( || {
            println!("Trying to run manager");
            let _ = run_manager();
        });

        thread::sleep(Duration::from_secs(2));

        for i in 1..parties_count+1 {
            let handle = thread::spawn(move || {
                println!("Trying to run party number {}", i);
                let params_vector = vec!["3", "5"];
                let key_file_path = format!("/tmp/ecdsa-test-{:?}.store", i);
                let address_str= &address.clone()[..];
                run_keygen(&address_str.to_string(), &key_file_path, &params_vector.clone());
                thread::sleep(Duration::from_millis(100));
            });
            threads.push(handle);
        }

        //Wait for all parties to finish:
        for handle in threads {
            handle.join().unwrap();
        }

        let created_files = glob("/tmp/ecdsa-test-*.store").unwrap();
        assert_eq!(created_files.count(), parties_count as usize);
    }

    #[test]
    fn test_tss_sign() {
        /*for entry in glob("/tmp/ecdsa-test-*.store").unwrap() {
            let entry = entry.unwrap();
            std::fs::remove_file(entry.as_path());
        }*/
    }

    #[test]
    fn test_hd_keys_hierarchy() {
        let key_file_path = "src/curves/ecdsa/tss-test-1.store";
        let path = "1/2/3/1";
        let path_splites = ["1/2", "3/1"];

        let data = fs::read_to_string(key_file_path).expect(
            format!("Unable to load keys file at location: {}", key_file_path).as_str(),
        );
        let (_party_keys, _shared_keys, _party_id, _vss_scheme_vec, _paillier_key_vector, y_sum): (
            Keys,
            SharedKeys,
            u16,
            Vec<VerifiableSS<Secp256k1>>,
            Vec<EncryptionKey>,
            GE,
        ) = serde_json::from_str(&data).unwrap();

        // Get root pub key or HD pub key at specified path

        let path_vector: Vec<BigInt> = path
            .split('/')
            .map(|s| BigInt::from_str_radix(s.trim(), 10).unwrap())
            .collect();
        let (expected_y, _f_l_new) = hd_keys::get_hd_key(&y_sum, path_vector.clone());

        let path_vector: Vec<BigInt> = path_splites[0]
            .split('/')
            .map(|s| BigInt::from_str_radix(s.trim(), 10).unwrap())
            .collect();
        let (mid_y, _f_l_new) = hd_keys::get_hd_key(&y_sum, path_vector.clone());

        let path_vector: Vec<BigInt> = path_splites[1]
            .split('/')
            .map(|s| BigInt::from_str_radix(s.trim(), 10).unwrap())
            .collect();
        let (final_y, _f_l_new) = hd_keys::get_hd_key(&mid_y, path_vector.clone());

        assert_eq!(final_y.x_coord().unwrap().to_hex(), expected_y.x_coord().unwrap().to_hex());
        assert_eq!(final_y.y_coord().unwrap().to_hex(), expected_y.y_coord().unwrap().to_hex());
    }
}