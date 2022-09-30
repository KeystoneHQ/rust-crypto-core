use crate::WrappedTransactionAction;

pub fn parse_transaction(transaction: String, db_name: String) -> String {
    WrappedTransactionAction {
        t: transaction_parsing::produce_output(transaction.as_str(), db_name.as_str())
    }.to_json().to_string()
}

