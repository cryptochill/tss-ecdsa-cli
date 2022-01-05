

use curv::arithmetic::{Converter, BasicOps, One};
use curv::BigInt;
use curv::elliptic::curves::{Curve, Point, Scalar};

use curv::cryptographic_primitives::hashing::HmacExt;
use hmac::Hmac;
use sha2::{Sha512};


pub fn get_hd_key<E: Curve>(y_sum: &Point<E>, path_vector: Vec<BigInt>) -> (Point<E>, Scalar<E>) {
    // generate a random but shared chain code, this will do
    let chain_code = Point::<E>::generator();
    //    println!("chain code {:?}", chain_code);
    // derive a new pubkey and LR sequence, y_sum becomes a new child pub key
    let (y_sum_child, f_l_new, _cc_new) = hd_key(
        path_vector,
        &y_sum,
        &BigInt::from_bytes(&chain_code.to_bytes(true)),
    );
    let y_sum = y_sum_child.clone();
    //    println!("New public key: {:?}", &y_sum);
    //    println!("Public key X: {:?}", &y_sum.x_coor());
    //    println!("Public key Y: {:?}", &y_sum.y_coor());
    (y_sum, f_l_new)
}

pub fn hd_key<E: Curve>(
    mut location_in_hir: Vec<BigInt>,
    pubkey: &Point<E>,
    chain_code_bi: &BigInt,
) -> (Point<E>, Scalar<E>, Point<E>) {
    let mask = BigInt::from(2 as i32).pow(256) - BigInt::one();
    // let public_key = self.public.q.clone();

    // calc first element:
    let first = location_in_hir.remove(0);
    let pub_key_bi = BigInt::from_bytes(&pubkey.to_bytes(true));
    let f = Hmac::<Sha512>::new_bigint(chain_code_bi)
        .chain_bigint(&pub_key_bi)
        .chain_bigint(&first)
        .result_bigint();

    let f_l = &f >> 256;
    let f_r = &f & &mask;
    let f_l_fe: Scalar<E> = Scalar::<E>::from(&f_l);
    let f_r_fe: Scalar<E> = Scalar::<E>::from(&f_r);

    let bn_to_slice = BigInt::to_bytes(chain_code_bi);
    let chain_code = Point::<E>::from_bytes(&bn_to_slice.as_slice()).unwrap() * &f_r_fe;
    let g: Point<E> = Point::<E>::generator().to_point();
    let pub_key = pubkey.clone() + g.clone() * &f_l_fe;

    let (public_key_new_child, f_l_new, cc_new) =
        location_in_hir
            .iter()
            .fold((pub_key, f_l_fe, chain_code), |acc, index| {
                let pub_key_bi = BigInt::from_bytes(&acc.0.to_bytes(true));
                let f = Hmac::<Sha512>::new_bigint(&BigInt::from_bytes(&acc.2.to_bytes(true)))
                    .chain_bigint(&pub_key_bi)
                    .chain_bigint(index)
                    .result_bigint();

                let f_l = &f >> 256;
                let f_r = &f & &mask;
                let f_l_fe: Scalar<E> = Scalar::<E>::from(&f_l);
                let f_r_fe: Scalar<E> = Scalar::<E>::from(&f_r);

                (acc.0 + &g * &f_l_fe, f_l_fe + &acc.1, &acc.2 * &f_r_fe)
            });
    (public_key_new_child, f_l_new, cc_new)
}
