use serde_json;
use serde_json::json;
use qr_reader_phone;

pub fn get_packets_total(payload: String) -> String {
    match qr_reader_phone::get_length(payload.as_str(), false).map_err(|e| e.to_string()) {
        Ok(v) => json!({"status": "success", "value": v}),
        Err(e) => json!({"status": "failed", "reason": e}),
    }.to_string()
}

pub fn decode_sequence(payload: Vec<String>) -> String {
    match serde_json::to_string(&payload) {
        Ok(message) => {
            match qr_reader_phone::decode_sequence(message.as_str(), false) {
                Ok(v) => json!({"status": "success", "value": v}),
                Err(e) => json!({"status": "failed", "reason": e.to_string()}),
            }
        }
        Err(e) => json!({"status": "failed", "reason": e.to_string()})
    }.to_string()
}

