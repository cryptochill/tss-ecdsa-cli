#[cfg(test)]
mod tests {
    use std::fs;
    use curv::arithmetic::Converter;
    use curv::BigInt;
    use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
    use curv::elliptic::curves::Ed25519;
    use multi_party_eddsa::protocols::GE;
    use multi_party_eddsa::protocols::thresholdsig::{Keys, SharedKeys};
    use crate::eddsa::hd_keys;

    #[test]
    fn test_hd_keys_hierarchicy() {
        let key_file_path = "src/curves/eddsa/tss-test-1.store";
        let path = "1/2/3/1";
        let path_splites = ["1/2", "3/1"];

        let data = fs::read_to_string(key_file_path).expect(
            format!("Unable to load keys file at location: {}", key_file_path).as_str(),
        );
        let (_party_keys, _shared_keys, _party_id, _vss_scheme_vec, y_sum): (
            Keys,
            SharedKeys,
            u16,
            Vec<VerifiableSS<Ed25519>>,
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