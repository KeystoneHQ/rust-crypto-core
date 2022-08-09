use serde_json::{json, Value};

pub mod stake;
pub mod system;
pub mod token;
pub mod token_lending;
pub mod token_swap_v3;
pub mod vote;

fn template_instruction(
    program_name: &str,
    method_name: &str,
    details: Value,
    overview: Value,
) -> Value {
    json!({
        "program_name": program_name,
        "method_name": method_name,
        "details": details,
        "overview": overview,
    })
}
