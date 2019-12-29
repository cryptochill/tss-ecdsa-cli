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
use curv::{BigInt, GE};
use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
use curv::elliptic::curves::traits::*;
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2018::party_i::*;
use paillier::*;
use serde_json::json;

use common::{
    keygen, keys, manager, Params, signer,
};

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
                    .index(3)
                    .required(false)
                    .takes_value(true)
                    .help("URL to manager. E.g. http://127.0.0.2:8002")),
            SubCommand::with_name("signer").about("Run signer")
                .arg(Arg::with_name("keysfile")
                    .required(true)
                    .index(1)
                    .takes_value(true)
                    .help("Keys file"))
                .arg(Arg::with_name("path")
                    .required(true)
                    .index(2)
                    .takes_value(true)
                    .help("Derivation path"))
                .subcommands(vec![
                    SubCommand::with_name("address").about("Get HD pub key at specified path"),
                    SubCommand::with_name("sign").about("Get HD pub key at specified path")
                        .arg(Arg::with_name("manager_addr")
                            .index(1)
                            .required(true)
                            .takes_value(true)
                            .help("URL to manager"))
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
                ])
        ])
        .get_matches();

    if let Some(matches) = matches.subcommand_matches("signer") {
        let keysfile_path = matches.value_of("keysfile").unwrap_or("");

        // Read data from keys file
        let data = fs::read_to_string(keysfile_path)
            .expect(format!("Unable to load keys file at location: {}", keysfile_path).as_str());
        let (party_keys, shared_keys, party_id, mut vss_scheme_vec, paillier_key_vector, y_sum): (
            Keys,
            SharedKeys,
            u16,
            Vec<VerifiableSS>,
            Vec<EncryptionKey>,
            GE,
        ) = serde_json::from_str(&data).unwrap();

        // Get HD pub key at specified path
        let path = matches.value_of("path").unwrap_or("0");
        let path_vector: Vec<BigInt> = path.split('/').map(|s| s.trim().parse::<BigInt>().unwrap()).collect();
        let (y_sum_child, f_l_new) = keys::get_hd_key(&y_sum, path_vector.clone());
        let y_sum = y_sum_child.clone();

        // Return pub key as x,y
        if let Some(_matches) = matches.subcommand_matches("address") {
            let ret_dict = json!({
                "x": &y_sum.x_coor(),
                "y": &y_sum.y_coor(),
                "path": path,
            });
            println!("{}", ret_dict.to_string());
        } else if let Some(matches) = matches.subcommand_matches("sign") {

            // Parse message to sign
            let message_str = matches.value_of("message").unwrap_or("");
            let message = match hex::decode(message_str.clone()) {
                Ok(x) => x,
                Err(_e) => message_str.as_bytes().to_vec(),
            };
            let message = &message[..];
            let manager_addr = matches.value_of("manager_addr").unwrap_or("http://127.0.0.1:8001").to_string();

            // Parse threshold params
            let params: Vec<&str> = matches.value_of("params").unwrap_or("").split("/").collect();
//            println!("sign me {:?} / {:?} / {:?}", manager_addr, message, params);
            let params = Params { threshold: params[0].to_string(), parties: params[1].to_string() };
            let THRESHOLD: u16 = params.threshold.parse::<u16>().unwrap();
            signer::sign(manager_addr, party_keys, shared_keys, party_id, &mut vss_scheme_vec, paillier_key_vector,
                         &y_sum, THRESHOLD, &message, &f_l_new)
        }
    } else if let Some(_matches) = matches.subcommand_matches("manager") {
        manager::run_manager();
    } else if let Some(matches) = matches.subcommand_matches("keygen") {
        let addr = matches.value_of("manager_addr").unwrap_or("http://127.0.0.1:8001").to_string();
        let keysfile_path = matches.value_of("keysfile").unwrap_or("").to_string();

        let params: Vec<&str> = matches.value_of("params").unwrap_or("").split("/").collect();
        keygen::run_keygen(&addr, &keysfile_path, &params);
    }
}

