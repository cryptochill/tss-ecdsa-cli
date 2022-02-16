#![allow(non_snake_case)]

extern crate clap;
extern crate curv;
extern crate hex;
extern crate multi_party_ecdsa;
extern crate paillier;
extern crate reqwest;
extern crate serde_json;

use clap::{App, AppSettings, Arg, SubCommand};

use common::{manager};

mod common;
mod curves;
mod test;

use curves::ecdsa;
use curves::eddsa;
use crate::common::hd_keys;

fn main() {
    let matches = App::new("TSS CLI Utility")
        .version("0.2.0")
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
                    .help("URL to manager. E.g. http://127.0.0.2:8002"))
                .arg(Arg::with_name("algorithm")
                    .short("l")
                    .long("alg")
                    .takes_value(true)
                    .help("Either ecdsa (default) or eddsa")),
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
                    .help("Derivation path (Optional)"))
                .arg(Arg::with_name("algorithm")
                    .short("l")
                    .long("alg")
                    .takes_value(true)
                    .help("Either ecdsa (default) or eddsa")),
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
                .arg(Arg::with_name("algorithm")
                    .short("l")
                    .long("alg")
                    .takes_value(true)
                    .help("Either ecdsa (default) or eddsa"))
                .arg(Arg::with_name("manager_addr")
                    .short("a")
                    .long("addr")
                    .takes_value(true)
                    .help("URL to manager")),
            SubCommand::with_name("convert_curv_07_to_09").about("Convert format of store files from v0.1.0 to v0.2.0")
                .arg(Arg::with_name("input_file")
                    .required(true)
                    .index(1)
                    .takes_value(true)
                    .help("Source keys file"))
                .arg(Arg::with_name("output_file")
                    .required(true)
                    .index(2)
                    .takes_value(true)
                    .help("Output keys file"))
        ])
        .get_matches();

    match matches.subcommand() {
        ("pubkey", Some(sub_matches)) | ("sign", Some(sub_matches)) => {
            let keysfile_path = sub_matches.value_of("keysfile").unwrap_or("");
            let path = sub_matches.value_of("path").unwrap_or("");
            let message_str = sub_matches.value_of("message").unwrap_or("");
            let curve = sub_matches.value_of("algorithm").unwrap_or("ecdsa");
            let manager_addr = sub_matches
                .value_of("manager_addr")
                .unwrap_or("http://127.0.0.1:8001")
                .to_string();
            // Parse threshold params
            let params: Vec<&str> = sub_matches
                .value_of("params")
                .unwrap_or("")
                .split("/")
                .collect();
            let action = matches.subcommand_name().unwrap();
            let result = match curve {
                "ecdsa" => ecdsa::run_pubkey_or_sign(action, keysfile_path, path, message_str, manager_addr, params),
                "eddsa" => match action {
                    "sign" => eddsa::sign(manager_addr, keysfile_path.to_string(), params, message_str.to_string(), path),
                    "pubkey" => eddsa::run_pubkey(keysfile_path, path),
                    _ => serde_json::Value::String("".to_string())
                }
                _ => serde_json::Value::String("".to_string())
            };
            println!("{}", result.to_string());
        }
        ("manager", Some(_matches)) => {
            let _ = manager::run_manager();
        }
        ("keygen", Some(sub_matches)) => {
            let addr = sub_matches
                .value_of("manager_addr")
                .unwrap_or("http://127.0.0.1:8001")
                .to_string();
            let keysfile_path = sub_matches.value_of("keysfile").unwrap_or("").to_string();
            let curve = sub_matches.value_of("algorithm").unwrap_or("ecdsa");
            let params: Vec<&str> = sub_matches
                .value_of("params")
                .unwrap_or("")
                .split("/")
                .collect();
            match curve {
                "ecdsa" => ecdsa::keygen::run_keygen(&addr, &keysfile_path, &params),
                "eddsa" => eddsa::keygen::run_keygen(&addr, &keysfile_path, &params),
                _ => {}
            }

        }
        ("convert_curv_07_to_09", Some(sub_matches)) => {
            let source_path = sub_matches.value_of("input_file").unwrap_or("").to_string();
            let destination_path = sub_matches.value_of("output_file").unwrap_or("").to_string();

            ecdsa::curv7_conversion::convert_store_file(source_path, destination_path);
        }
        _ => {}
    }
}

