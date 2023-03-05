use std::collections::HashMap;
use std::sync::RwLock;
use std::time::Duration;

use rocket::{Ignite, post, response, Rocket, routes, State};
use rocket::http::{ContentType, Status};
use rocket::request::Request;
use rocket::response::{Responder, Response};
use rocket::serde::json::Json;
use serde_json::{json, Value};

use ttlhashmap::TtlHashMap;

use uuid::Uuid;

use crate::common::{Entry, Index, Key, new_sign_party, Params, PartySignup, PartySignupRequestBody};

#[rocket::main]
pub async fn run_manager() -> Result<Rocket<Ignite>, rocket::Error> {
    //     let mut my_config = Config::development();
    //     my_config.set_port(18001);
    let ttl = std::env::var("TSS_CLI_MANAGER_TTL")
        .unwrap_or("30".to_string()).parse::<u64>().unwrap();
    let db: TtlHashMap<Key, String> = TtlHashMap::new(Duration::from_secs(ttl));
    let db_mtx = RwLock::new(db);
    //rocket::custom(my_config).mount("/", routes![get, set]).manage(db_mtx).launch();

    /////////////////////////////////////////////////////////////////
    //////////////////////////init signups://////////////////////////
    /////////////////////////////////////////////////////////////////

    let keygen_key = "signup-keygen".to_string();
    let sign_key = "signup-sign".to_string();

    let uuid_keygen = Uuid::new_v4().to_string();

    let party1 = 0;
    let party_signup_keygen = PartySignup {
        number: party1,
        uuid: uuid_keygen,
    };
    let party_signup_sign = new_sign_party();
    {
        let mut hm = db_mtx.write().unwrap();
        hm.insert(
            keygen_key,
            serde_json::to_string(&party_signup_keygen).unwrap(),
        );
        hm.insert(sign_key, serde_json::to_string(&party_signup_sign).unwrap());
    }
    /////////////////////////////////////////////////////////////////
    rocket::build()
        .mount("/", routes![get, set, signup_keygen, signup_sign])
        .manage(db_mtx)
        .launch()
        .await
}

fn default_sign_party() -> PartySignup {
    let uuid_sign = Uuid::new_v4().to_string();
    let party1 = 0;

    PartySignup {
        number: party1,
        uuid: uuid_sign,
    }
}

#[derive(Debug)]
struct ApiResponse {
    json: Value,
    status: Status,
}

impl<'r> Responder<'r, 'static> for ApiResponse {
    fn respond_to(self, req: &Request) -> response::Result<'static> {
        Response::build_from(self.json.respond_to(&req).unwrap())
            .status(self.status)
            .header(ContentType::JSON)
            .ok()
    }
}

#[post("/get", format = "json", data = "<request>")]
fn get(
    db_mtx: &State<RwLock<TtlHashMap<Key, String>>>,
    request: Json<Index>,
) -> Json<Result<Entry, ()>> {
    let index: Index = request.0;
    let mut hm = db_mtx.write().unwrap();
    println!("request to get {:?}", index.key);

    match hm.get(&index.key) {
        Some(v) => {
            let entry = Entry {
                key: index.key,
                value: v.clone().to_string(),
            };
            Json(Ok(entry))
        }
        None => Json(Err(())),
    }
}

#[post("/set", format = "json", data = "<request>")]
fn set(db_mtx: &State<RwLock<TtlHashMap<Key, String>>>, request: Json<Entry>) -> Json<Result<(), ()>> {
    let entry: Entry = request.0;
    let mut hm = db_mtx.write().unwrap();
    println!("request to set {:?} as {:?}", entry.key, entry.value);
    hm.insert(entry.key.clone(), entry.value.clone());
    Json(Ok(()))
}

#[post("/signupkeygen", format = "json", data = "<request>")]
fn signup_keygen(
    db_mtx: &State<RwLock<TtlHashMap<Key, String>>>,
    request: Json<Params>,
) -> Json<Result<PartySignup, ()>> {
    let parties = request.parties.parse::<u16>().unwrap();
    let key = "signup-keygen".to_string();

    let mut hm = db_mtx.write().unwrap();

    let party_signup = {
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

    if party_signup.number == parties {
        hm.insert(
            key,
            serde_json::to_string(&PartySignup {
                number: 0,
                uuid: Uuid::new_v4().to_string(),
            })
            .unwrap(),
        );
    } else {
        hm.insert(key, serde_json::to_string(&party_signup).unwrap());
    }
    Json(Ok(party_signup))
}

#[post("/signupsign", format = "json", data = "<request>")]
fn signup_sign(
    db_mtx: &State<RwLock<TtlHashMap<Key, String>>>,
    request: Json<PartySignupRequestBody>,
) -> Json<Result<PartySignup, ()>> {
    let threshold = request.clone().threshold;
    let mut key = "signup-sign-".to_owned();
    key.push_str(&request.room_id);
    println!("the key is: {}", key);

    let mut hm = db_mtx.write().unwrap();

    if !hm.contains_key(key.as_str()) {
        let default_value = serde_json::to_string(&new_sign_party()).unwrap();
        hm.insert(key.clone(), default_value);
    }

    let party_signup = {
        //let value = hm.get(&key).unwrap();
        let value = hm.get(key.as_str()).unwrap();
        /*let value = match hm.entry(key) {
            Entry::Occupied(o) => o.into_mut(),
            Entry::Vacant(v) => v.insert(default_sign_party()),
        };*/
        let client_signup: PartySignup = serde_json::from_str(&value).unwrap();
        if client_signup.number < threshold + 1 {
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
    if party_signup.number == threshold + 1 {
        hm.insert(
            key,
            serde_json::to_string(&new_sign_party())
            .unwrap(),
        );
    } else {
        hm.insert(key, serde_json::to_string(&party_signup).unwrap());
    }
    Json(Ok(party_signup))
}
