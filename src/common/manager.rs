use std::sync::RwLock;
use std::time::{Duration};

use rocket::{Ignite, post, Rocket, routes, State};
use rocket::serde::json::Json;
use serde_json::{json};

use ttlhashmap::TtlHashMap;

use uuid::Uuid;

use crate::common::{Entry, Index, Key, ManagerError, Params, PartySignup, PartySignupRequestBody, SigningPartySignup};
use crate::common::signing_room::SigningRoom;

#[rocket::main]
pub async fn run_manager() -> Result<(), rocket::Error> {
    //     let mut my_config = Config::development();
    //     my_config.set_port(18001);
    let ttl = std::env::var("TSS_CLI_MANAGER_TTL")
        .unwrap_or("300".to_string()).parse::<u64>().unwrap();
    let db: TtlHashMap<Key, String> = TtlHashMap::new(Duration::from_secs(ttl));
    let db_mtx = RwLock::new(db);
    //rocket::custom(my_config).mount("/", routes![get, set]).manage(db_mtx).launch();

    /////////////////////////////////////////////////////////////////
    rocket::build()
        .mount("/", routes![get, set, signup_keygen, signup_sign])
        .manage(db_mtx)
        .launch()
        .await
}

#[post("/get", format = "json", data = "<request>")]
fn get(
    db_mtx: &State<RwLock<TtlHashMap<Key, String>>>,
    request: Json<Index>,
) -> Json<Result<Entry, ManagerError>> {
    let index: Index = request.0;
    let mut hm = db_mtx.write().unwrap();

    match hm.get(&index.key) {
        Some(v) => {
            let entry = Entry {
                key: index.key,
                value: v.clone().to_string(),
            };
            Json(Ok(entry))
        }
        None => {
            Json(Err(ManagerError{
                error: "Key not found: ".to_string() + index.key.as_str()
            }))
        },
    }
}

#[post("/set", format = "json", data = "<request>")]
fn set(db_mtx: &State<RwLock<TtlHashMap<Key, String>>>, request: Json<Entry>) -> Json<Result<(), ()>> {
    let entry: Entry = request.0;
    let mut hm = db_mtx.write().unwrap();
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

    let client_signup = match hm.get(&key) {
        Some(o) => serde_json::from_str(o).unwrap(),
        None => PartySignup {
            number: 0,
            uuid: Uuid::new_v4().to_string(),
        },
    };

    let party_signup = {
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

    hm.insert(key, serde_json::to_string(&party_signup).unwrap());
    Json(Ok(party_signup))
}

#[post("/signupsign", format = "json", data = "<request>")]
fn signup_sign(
    db_mtx: &State<RwLock<TtlHashMap<Key, String>>>,
    request: Json<PartySignupRequestBody>,
) -> Json<Result<SigningPartySignup, ManagerError>> {
    let threshold = request.clone().threshold;
    let room_id = request.room_id.clone();
    let party_uuid = request.party_uuid.clone();
    let new_signup_request = party_uuid.is_empty();
    let party_number = request.party_number;
    let mut key = "signup-sign-".to_owned();
    key.push_str(&room_id);

    let mut hm = db_mtx.write().unwrap();

    let mut signing_room = match hm.get(&key) {
        Some(o) => serde_json::from_str(o).unwrap(),
        None => SigningRoom::new(room_id.clone(), threshold+1),
    };

    if signing_room.last_stage != "signup" {
        if signing_room.has_member(party_number, party_uuid.clone()) {
            return Json(Ok(signing_room.get_signup_info(party_number)));
        }

        if signing_room.are_all_members_inactive() {
            let debug = json!({
                "message": "All parties have been inactive. Renewed the room.",
                "room_id": room_id,
                "fragment.index": party_number,
            });
            println!("{}", serde_json::to_string_pretty(&debug).unwrap());
            signing_room = SigningRoom::new(room_id, threshold + 1)
        }
        else {
            return Json(Err(ManagerError{
                error: "Room signup phase is terminated".to_string()
            }));
        }
    }

    if signing_room.is_full() && signing_room.are_all_members_active() && new_signup_request {
        return Json(Err(ManagerError{
            error: "Room is full, all members active".to_string()
        }));
    }

    let party_signup = {
        if !new_signup_request {
            if !signing_room.has_member(party_number, party_uuid) {
                return Json(Err(ManagerError{
                    error: "No party found with the given uuid, probably replaced due to timeout".to_string()
                }));
            }
            //if signing_room.is_member_active(party_number) {
            signing_room.update_ping(party_number)
            //}
            //Else is handled in the next block
        } else if signing_room.member_info.contains_key(&party_number) {
            if signing_room.is_member_active(party_number) {
                return Json(Err(ManagerError{
                    error: "Received a re-signup request for an active party. Request ignored".to_string()
                }));
            }
            println!("Received a re-signup request for a timed-out party {:?}, thus UUID is renewed", party_number);
            signing_room.replace_party(party_number)
        }
        else {
            signing_room.add_party(party_number)
        }
    };

    hm.insert(key.clone(), serde_json::to_string(&signing_room).unwrap());
    Json(Ok(party_signup))
}
