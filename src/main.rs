#![allow(non_snake_case)]
#![feature(proc_macro_hygiene, decl_macro)]

extern crate clap;
extern crate curv;
extern crate hex;
extern crate multi_party_ecdsa;
extern crate paillier;
extern crate reqwest;
extern crate serde_json;

use std::fs;

use clap::{App, AppSettings, Arg, SubCommand};
use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
use curv::elliptic::curves::traits::*;

use curv::{
    BigInt,
    elliptic::curves::secp256_k1::{GE},
    arithmetic::Converter
};
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2018::party_i::*;
use paillier::*;
use serde_json::json;

use common::{hd_keys, keygen, manager, signer, Params};

mod common;

fn main() {
    let matches = App::new("TSS CLI Utility")
        .version("0.1.0")
        .author("Kaspars Sprogis <darklow@gmail.com>")
//        .about("")
        .setting(AppSettings::SubcommandRequiredElseHelp)
        .subcommands(vec![
            SubCommand::with_name("manager").about("Run state manager"),
            SubCommand::with_name("keygen").about("Run keygen")
                .arg(Arg::with_name("keysfile")
                    .required(true)
                    .index(1)
                    .takes_value(true)
                    .help("Target keys file"))
                .arg(Arg::with_name("params")
                    .index(2)
                    .required(true)
                    .takes_value(true)
                    .help("Threshold params: threshold/parties (t+1/n). E.g. 1/3 for 2 of 3 schema."))
                .arg(Arg::with_name("manager_addr")
                    .short("a")
                    .long("addr")
                    .takes_value(true)
                    .help("URL to manager. E.g. http://127.0.0.2:8002")),
            SubCommand::with_name("pubkey").about("Get X,Y of a pub key")
                .arg(Arg::with_name("keysfile")
                    .required(true)
                    .index(1)
                    .takes_value(true)
                    .help("Keys file"))
                .arg(Arg::with_name("path")
                    .short("p")
                    .long("path")
                    .takes_value(true)
                    .help("Derivation path (Optional)")),
            SubCommand::with_name("sign").about("Run signer")
                .arg(Arg::with_name("keysfile")
                    .required(true)
                    .index(1)
                    .takes_value(true)
                    .help("Keys file"))
                .arg(Arg::with_name("params")
                    .index(2)
                    .required(true)
                    .takes_value(true)
                    .help("Threshold params: threshold/parties (t+1/n). E.g. 1/3 for 2 of 3 schema."))
                .arg(Arg::with_name("message")
                    .index(3)
                    .required(true)
                    .takes_value(true)
                    .help("Message to sign in hex format"))
                .arg(Arg::with_name("path")
                    .short("p")
                    .long("path")
                    .takes_value(true)
                    .help("Derivation path"))
                .arg(Arg::with_name("manager_addr")
                    .short("a")
                    .long("addr")
                    .takes_value(true)
                    .help("URL to manager"))
                .arg(Arg::with_name("signer_id")
                    .short("i")
                    .long("sid")
                    .takes_value(true)
                    .help("Unique Signer ID to identify signer"))
        ])
        .get_matches();

    match matches.subcommand() {
        ("pubkey", Some(sub_matches)) | ("sign", Some(sub_matches)) => {
            let keysfile_path = sub_matches.value_of("keysfile").unwrap_or("");

            // Read data from keys file
            let data = fs::read_to_string(keysfile_path).expect(
                format!("Unable to load keys file at location: {}", keysfile_path).as_str(),
            );
            let (party_keys, shared_keys, party_id, mut vss_scheme_vec, paillier_key_vector, y_sum): (
                Keys,
                SharedKeys,
                u16,
                Vec<VerifiableSS<GE>>,
                Vec<EncryptionKey>,
                GE,
            ) = serde_json::from_str(&data).unwrap();

            // Get root pub key or HD pub key at specified path
            let path = sub_matches.value_of("path").unwrap_or("");
            let (f_l_new, y_sum) = match path.is_empty() {
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
            if let Some(_sub_matches) = matches.subcommand_matches("pubkey") {
                let ret_dict = json!({
                    "x": &y_sum.x_coor(),
                    "y": &y_sum.y_coor(),
                    "path": path,
                });
                println!("{}", ret_dict.to_string());
            } else if let Some(sub_matches) = matches.subcommand_matches("sign") {
                // Parse message to sign
                let message_str = sub_matches.value_of("message").unwrap_or("");
                let message = match hex::decode(message_str.clone()) {
                    Ok(x) => x,
                    Err(_e) => message_str.as_bytes().to_vec(),
                };
                let message = &message[..];
                let manager_addr = sub_matches
                    .value_of("manager_addr")
                    .unwrap_or("http://127.0.0.1:8001")
                    .to_string();
                let signer_id = sub_matches.value_of("signer_id").unwrap_or("").to_string();

                // Parse threshold params
                let params: Vec<&str> = sub_matches
                    .value_of("params")
                    .unwrap_or("")
                    .split("/")
                    .collect();
                //            println!("sign me {:?} / {:?} / {:?}", manager_addr, message, params);
                let params = Params {
                    threshold: params[0].to_string(),
                    parties: params[1].to_string(),
                    signer_id: signer_id,
                };
                signer::sign(
                    manager_addr,
                    party_keys,
                    shared_keys,
                    party_id,
                    &mut vss_scheme_vec,
                    paillier_key_vector,
                    &y_sum,
                    &params,
                    &message,
                    &f_l_new,
                    !path.is_empty(),
                )
            }
        }
        ("manager", Some(_matches)) => {
            manager::run_manager();
        }
        ("keygen", Some(sub_matches)) => {
            let addr = sub_matches
                .value_of("manager_addr")
                .unwrap_or("http://127.0.0.1:8001")
                .to_string();
            let keysfile_path = sub_matches.value_of("keysfile").unwrap_or("").to_string();

            let params: Vec<&str> = sub_matches
                .value_of("params")
                .unwrap_or("")
                .split("/")
                .collect();
            keygen::run_keygen(&addr, &keysfile_path, &params);
        }
        _ => {}
    }
}
