use signer::{qrparser_get_packets_total, qrparser_try_decode_qr_sequence};
use serde_json;
use serde_json::json;

pub fn get_packets_total(payload: String) -> String {
    match qrparser_get_packets_total(payload.as_str(), true).map_err(|e| e.to_string()) {
        Ok(v) => json!({"status": "success", "value": v}),
        Err(e) => json!({"status": "failed", "reason": e}),
    }.to_string()
}

pub fn decode_sequence(payload: Vec<String>) -> String {
    match {
        let message = serde_json::to_string(&payload).map_err(|e| e.to_string())?;
        qrparser_try_decode_qr_sequence(message.as_str(), true).map_err(|e| e.to_string())
    } {
        Ok(v) => json!({"status": "success", "value": v}),
        Err(e) => json!({"status": "failed", "reason": e}),
    }.to_string()
}

