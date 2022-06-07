use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Deserialize, Serialize, Debug)]
pub struct Sample {
    pub id: Uuid,
    pub string: String,
    pub number: i64,
    pub small_number: i8,
}

impl Sample {
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).expect("Was not able to serialize.")
    }
}