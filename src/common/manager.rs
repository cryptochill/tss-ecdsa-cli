use std::collections::HashMap;
use std::env;
//use std::fmt::Debug;
//use std::hash::Hash;
use std::sync::RwLock;
use std::time::SystemTime;

use rocket::{post, routes, State};
use rocket_contrib::json::Json;
use uuid::Uuid;

use crate::common::{Entry, EntryResponse, Index, Key, Params, PartySignup};

//pub fn print_map<K: Debug + Eq + Hash, V: Debug>(map: &HashMap<K, V>) {
//    for (k, v) in map.iter() {
//        println!("-----> {:?}: {:?}", k, v);
//    }
//}

pub fn run_manager() {
    //     let mut my_config = Config::development();
    //     my_config.set_port(18001);
    let db: HashMap<Key, String> = HashMap::new();
    let db_mtx = RwLock::new(db);
    //rocket::custom(my_config).mount("/", routes![get, set]).manage(db_mtx).launch();

    /////////////////////////////////////////////////////////////////
    //////////////////////////init signups://////////////////////////
    /////////////////////////////////////////////////////////////////

    let keygen_key = "signup-keygen".to_string();
    let sign_key = "signup-sign".to_string();

    let uuid_keygen = Uuid::new_v4().to_string();
    let uuid_sign = Uuid::new_v4().to_string();

    let party1 = 0;
    let party_signup_keygen = PartySignup {
        number: party1,
        uuid: uuid_keygen,
    };
    let party_signup_sign = PartySignup {
        number: party1,
        uuid: uuid_sign,
    };
    {
        let mut hm = db_mtx.write().unwrap();
        hm.insert(
            keygen_key,
            serde_json::to_string(&party_signup_keygen).unwrap(),
        );
        hm.insert(sign_key, serde_json::to_string(&party_signup_sign).unwrap());
    }
    /////////////////////////////////////////////////////////////////
    rocket::ignite()
        .mount("/", routes![get, set, signup_keygen, signup_sign])
        .manage(db_mtx)
        .launch();
}

#[post("/get", format = "json", data = "<request>")]
fn get(
    db_mtx: State<RwLock<HashMap<Key, String>>>,
    request: Json<Index>,
) -> Json<Result<EntryResponse, ()>> {
    let index: Index = request.0;
    let hm = db_mtx.read().unwrap();
    match hm.get(&index.key) {
        Some(v) => {
            let entry = EntryResponse {
                key: index.key,
                value: v.clone().to_string(),
                last_uuid: hm.get("last_uuid").unwrap().to_string(),
            };
            Json(Ok(entry))
        }
        None => {
            let entry = EntryResponse {
                key: "last_uuid".to_string(),
                value: "".to_string(),
                last_uuid: hm.get("last_uuid").unwrap().to_string(),
            };
            Json(Ok(entry))
        }
    }
}
//
//#[post("/cleanup", format = "json", data = "<request>")]
//fn cleanup(
//    db_mtx: State<RwLock<HashMap<Key, String>>>,
//    request: Json<PartySignupWithId>,
//) -> Json<Result<(), ()>> {
//    let mut hm = db_mtx.write().unwrap();
//    if request.action == 0 {
//        //        let busy_key = "busy".to_string();
//        //        hm.insert(busy_key, "1".to_string());
//    } else if request.action == 1 {
//        hm.insert("clean_db".to_string(), "1".to_string());
//        //        println!("Clean signer: {}", request.signer_id);
//        //        hm.remove(format!("signer_key:{}", request.signer_id).as_str());
//        //        let mut signers_cleaned: u16 = 1;
//        //        let signers_cl_key = "signers_cleaned".to_string();
//        //        if hm.contains_key(&signers_cl_key) {
//        //            let signers_cleaned: u16 = hm[&signers_cl_key].parse::<u16>().unwrap();
//        //            println!("signers_cleaned: {:?}", signers_cleaned);
//        //            hm.insert("clean_db".to_string(), "1".to_string());
//        //            if signers_cleaned == 2 {
//        //                //                hm.clear();
//        //                println!("clean HM");
//        //                let size = hm.keys().len();
//        //                println!("{} hm len", size);
//        //            }
//        //        } else {
//        //            signers_cleaned = signers_cleaned + 1;
//        //            hm.insert(signers_cl_key, format!("{}", signers_cleaned).to_string());
//        //        }
//    }
//    Json(Ok(()))
//}

#[post("/set", format = "json", data = "<request>")]
fn set(db_mtx: State<RwLock<HashMap<Key, String>>>, request: Json<Entry>) -> Json<Result<(), ()>> {
    let entry: Entry = request.0;
    let mut hm = db_mtx.write().unwrap();
    hm.insert(entry.key.clone(), entry.value.clone());
    Json(Ok(()))
}

#[post("/signupkeygen", format = "json", data = "<request>")]
fn signup_keygen(
    db_mtx: State<RwLock<HashMap<Key, String>>>,
    request: Json<Params>,
) -> Json<Result<PartySignup, ()>> {
    let parties = request.parties.parse::<u16>().unwrap();
    let key = "signup-keygen".to_string();

    let party_signup = {
        let hm = db_mtx.read().unwrap();
        let value = hm.get(&key).unwrap();
        let client_signup: PartySignup = serde_json::from_str(&value).unwrap();
        if client_signup.number < parties {
            PartySignup {
                number: client_signup.number + 1,
                uuid: client_signup.uuid,
            }
        } else {
            PartySignup {
                number: 1,
                uuid: Uuid::new_v4().to_string(),
            }
        }
    };

    let mut hm = db_mtx.write().unwrap();
    hm.insert(key, serde_json::to_string(&party_signup).unwrap());
    Json(Ok(party_signup))
}

#[post("/signupsign", format = "json", data = "<request>")]
fn signup_sign(
    db_mtx: State<RwLock<HashMap<Key, String>>>,
    request: Json<Params>,
) -> Json<Result<PartySignup, ()>> {
    let threshold = request.threshold.parse::<u16>().unwrap();
    let signer_id = request.signer_id.to_string();
    //    let party_num = signer_id
    //        .chars()
    //        .last()
    //        .unwrap()
    //        .to_string()
    //        .parse::<u16>()
    //        .unwrap();
    let key = "signup-sign".to_string();
    let last_uuid_key = "last_uuid".to_string();
    //    let busy_key = "busy".to_string();
    //    let signer_key = format!("signer_key:{}", signer_id);
    let mut hm = db_mtx.write().unwrap();
    let value = hm.get(&key).unwrap();
    let client_signup: PartySignup = serde_json::from_str(&value).unwrap();
    let mut clear: &str = "-----";
    //    if hm.contains_key("clean_db") {
    //        hm.clear();
    //        clear = "clear 0";
    //    }

    //    let mut signers_len: u16 = 0;
    //    let signers_len_key = "signers_len".to_string();
    //    if hm.contains_key(&signers_len_key) {
    //        signers_len = hm[&signers_len_key].parse::<u16>().unwrap();
    //        println!("signers_len: {:?}", signers_len);
    //    }

    //    signers_len = signers_len + 1;
    //    if signers_len > threshold + 1 {
    //        signers_len -= 1;
    //        hm.clear();
    //        println!("clean HM by signers_len: {}", signers_len);
    //    }

    //    hm.insert(
    //        signers_len_key.clone(),
    //        format!("{}", signers_len).to_string(),
    //    );

    //    if hm.contains_key(&busy_key) {
    //        return Json(Err(()));
    //    }

    let kind: &str;
    let party_signup = {
        //        if !hm.contains_key(&last_message_key) || hm[&last_message_key.clone()] != request.message {
        //            PartySignup {
        //                number: party_num,
        //                uuid: Uuid::new_v4().to_string(),
        //            }
        //        } else {
        //            PartySignup {
        //                number: party_num,
        //                uuid: client_signup.uuid,
        //            }
        //        }

        let join_party = client_signup.number < threshold + 1;
        //        let ex_party = hm.contains_key(&signer_key);
        //                if hm.contains_key(&busy_key) {
        //                    panic!("Signer is busy. Retry in a sec...");
        //            PartySignup {
        //                number: 0,
        //                uuid: "".to_string(),
        //            }
        //        } else
        //        if ex_party {
        //            let vj: PartySignup = serde_json::from_str(&hm[&signer_key]).unwrap();
        //            if vj.number == 1 {
        //                hm.clear();
        //                clear = "clear 1";
        //            }
        //            //            println!("########## CLEAR HM 2");
        //            hm.clear();
        //            clear = "clear";
        //            println!(
        //                "signer key already exists. Must replace. {:?} / {:?}",
        //                signer_key, hm[&signer_key]
        //            );
        //            let mut vjn: u16 = 0;
        //            for (k, v) in hm.iter() {
        //                if k == &key {
        //                    let vj: PartySignup = serde_json::from_str(&v).unwrap();
        //                    vjn = vj.number
        //                                println!("---> {:?}: {:?}", k, vj);
        //                }
        //            }
        //            kind = "ex  ";
        //            PartySignup {
        //                number: vj.number, // TODO:
        //                uuid: client_signup.uuid,
        //            }
        //        } else {
        if join_party {
            kind = "join";
            //                println!(
            //                    "Join party. {:?} < {:?} = {:?}",
            //                    client_signup.number,
            //                    threshold + 1,
            //                    join_party
            //                );
            PartySignup {
                number: client_signup.number + 1,
                uuid: client_signup.uuid,
            }
        } else {
            //                println!(
            //                    "New party. {:?} < {:?} = {:?}",
            //                    client_signup.number,
            //                    threshold + 1,
            //                    join_party
            //                );
            //            // Clear hm on new party
            kind = "new ";
            PartySignup {
                number: 1,
                uuid: Uuid::new_v4().to_string(),
            }
        }
    };

    if party_signup.number == 1 {
        clear = "clear 1";
        hm.clear()
    };

    println!(
        "[{:?}] {} Signup: {} - {} | No {} | {} | {}",
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap(),
        env::var("ROCKET_PORT").unwrap().as_str(),
        signer_id,
        party_signup.number,
        party_signup.uuid,
        kind,
        clear
    );

    //    print_map(&hm);
    hm.insert(key, serde_json::to_string(&party_signup).unwrap());
    //    hm.insert(signer_key, serde_json::to_string(&party_signup).unwrap());
    hm.insert(last_uuid_key, (&party_signup.uuid).to_string());
    Json(Ok(party_signup))
}
