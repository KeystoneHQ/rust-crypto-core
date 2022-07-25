use serde_json::{json, Value};

pub mod stake;
pub mod system;
pub mod token;
pub mod vote;
pub mod token_swap;

fn template_instruction(program_name: &str, method_name: &str, arguments: Value) -> Value {
    json!({
        "program_name": program_name,
        "method_name": method_name,
        "arguments": arguments
    })
}
