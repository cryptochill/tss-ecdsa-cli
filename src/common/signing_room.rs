use std::collections::HashMap;
use std::convert::TryFrom;
use std::env;
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use crate::common::{SigningPartyInfo, SigningPartySignup};

pub const SIGNUP_TIMEOUT_ENV: &str = "TSS_MANAGER_SIGNUP_TIMEOUT";
pub const SIGNUP_TIMEOUT_DEFAULT: &str = "2";

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct SigningRoom {
    pub room_id: String, // ID set by clients/parties, used during signup
    pub room_uuid: String, // ID set by manager, used during the rounds
    pub room_size: u16,
    pub member_info: HashMap<u16, SigningPartyInfo>,
    pub last_stage: String
}

impl SigningRoom {

    pub fn new(room_id: String, size: u16) -> Self {
        SigningRoom {
            room_size: size,
            member_info: Default::default(),
            room_id,
            last_stage: "signup".to_string(),
            room_uuid: Uuid::new_v4().to_string(),
        }
    }

    fn new_sign_party(party_order: u16) -> SigningPartySignup {
        SigningPartySignup {
            party_order,
            room_uuid: "".to_string(),
            party_uuid: Uuid::new_v4().to_string(),
            total_joined: 0
        }
    }

    pub fn is_full(&self) -> bool {
        self.member_info.len() >= usize::from(self.room_size)
    }

    fn is_timeout(party: &SigningPartyInfo) -> bool {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let timeout = u64::from_str(
            env::var(SIGNUP_TIMEOUT_ENV).unwrap_or(SIGNUP_TIMEOUT_DEFAULT.to_string()).as_str()
        ).unwrap();

        party.last_ping < now - timeout
    }

    pub fn add_party(&mut self, party_number: u16) -> SigningPartySignup {
        let party_signup = SigningRoom::new_sign_party(
            u16::try_from(self.member_info.len()).unwrap() + 1,
        );
        self.member_info.insert(party_number, SigningPartyInfo{
            party_id: party_signup.party_uuid.clone(),
            party_order: party_signup.party_order,
            last_ping: SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs()
        });

        party_signup.clone()
    }

    pub fn replace_party(&mut self, party_number: u16) -> SigningPartySignup {
        let old_party = self.member_info.get(&party_number).unwrap();
        let party_signup= SigningRoom::new_sign_party(old_party.party_order);
        *self.member_info.get_mut(&party_number).unwrap() = SigningPartyInfo{
            party_id: party_signup.party_uuid.clone(),
            party_order: party_signup.party_order,
            last_ping: SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs()
        };

        party_signup.clone()
    }

    pub fn are_all_members_active(&self) -> bool {
        self.member_info.values().all(
            |x| !SigningRoom::is_timeout(x)
        )
    }

    pub fn are_all_members_inactive(&self) -> bool {
        self.is_full() && self.member_info.values().all(
            |x| SigningRoom::is_timeout(x)
        )
    }

    pub fn is_member_active(&self, party_number: u16) -> bool {
        let party_data = self.member_info.get(&party_number).unwrap();

        !SigningRoom::is_timeout(party_data)
    }

    pub fn update_ping(&mut self, party_number: u16) -> SigningPartySignup {
        let party_data = self.member_info.get_mut(&party_number).unwrap();
        party_data.last_ping = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();
        if self.is_full() && self.active_members().len() >= usize::from(self.room_size) {
            self.close_signup_window();
        }
        self.get_signup_info(party_number)
    }

    fn close_signup_window(&mut self){
        let active_members = self.active_members();
        if self.is_full() && active_members.len() >= usize::from(self.room_size) {
            self.last_stage = "terminated".to_string();
            let mut new_order = 1;
            for (key, value) in self.member_info.iter_mut() {
                if active_members.contains_key(&key) {
                    value.party_order = new_order;
                    new_order = new_order + 1;
                }
            }
        }
    }

    pub fn has_member(&self, party_number: u16, party_uuid: String) -> bool {
        self.member_info.contains_key(&party_number) &&
            self.member_info.get(&party_number).unwrap().party_id == party_uuid
    }

    fn active_members(&self) -> HashMap<u16, SigningPartyInfo> {
        self.member_info.clone().into_iter()
            .filter(|(_key, x)| !SigningRoom::is_timeout(x)).collect()
    }

    pub fn get_signup_info(&self, party_number: u16) -> SigningPartySignup {
        let member_info = self.member_info.get(&party_number).unwrap();
        let room_uuid = if self.last_stage == "signup" {
            "".to_string()
        }
        else {
            self.room_uuid.clone()
        };
        SigningPartySignup{
            party_order: member_info.party_order,
            party_uuid: member_info.party_id.clone(),
            room_uuid,
            total_joined: u16::try_from(self.active_members().len()).unwrap()
        }
    }
}
