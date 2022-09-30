use serde_json::{json, Value};
use definitions::{navigation::Card, crypto::Encryption};
use crate::traits::ToJSON;

pub struct WrappedCard {
    pub c: Card,
}

impl ToJSON for WrappedCard {
    fn to_json(&self) -> Value{
        match &self.c {
            Card::AuthorCard { f } => {
                json!({
                    "type": "Author",
                    "value": json!({
                        "base58": f.base58,
                        "path": f.path,
                    })
                })
            }
            Card::AuthorPlainCard { f } => {
                json!({
                    "type": "AuthorPlain",
                    "value": f.base58
                })
            }
            Card::AuthorPublicKeyCard { f } => {
                json!({
                    "type": "AuthorPublicKey",
                    "value": f.public_key
                })
            }
            Card::BalanceCard { f } => {
                let value = format!("{} {}", f.amount, f.units);
                json!({
                    "type": "Balance",
                    "value": value,
                })
            }
            Card::BitVecCard { f } => {
                json!({
                    "type": "BitVec",
                    "value": f,
                })
            }
            Card::BlockHashCard { f } => {
                json!({
                    "type": "BlockHash",
                    "value": f
                })
            }
            Card::CallCard { f } => {
                json!({
                    "type": "Call",
                    "value": f.method_name
                })
            }
            Card::DefaultCard { f } => {
                json!({
                    "type": "Default",
                    "value": f
                })
            }
            Card::DerivationsCard { f } => {
                json!({
                    "type": "Derivations",
                    "value": f
                })
            }
            Card::EnumVariantNameCard { f } => {
                json!({
                    "type": "EnumVariantName",
                    "value": f.name,
                })
            }
            Card::EraImmortalCard => {
                json!({
                    "type": "Era",
                    "value": "Immortal"
                })
            }
            Card::EraMortalCard { f } => {
                json!({
                    "type": "Era",
                    "value": json!({
                        "phase": f.phase,
                        "period": f.period,
                    })
                })
            }
            Card::ErrorCard { f } => {
                json!({
                    "type": "Error",
                    "value": f
                })
            }
            Card::FieldNameCard { f } => {
                json!({
                    "type": "FieldName",
                    "value": f.name
                })
            }
            Card::FieldNumberCard { f } => {
                json!({
                    "type": "FieldNumber",
                    "value": f.number,
                })
            }
            Card::IdCard { f } => {
                json!({
                    "type": "Id",
                    "value": f.base58
                })
            }
            Card::IdentityFieldCard { f } => {
                json!({
                    "type": "IdentityField",
                    "value": f,
                })
            }
            Card::MetaCard { f } => {
                json!({
                    "type": "Meta",
                    "value": json!({
                        "specname": f.specname,
                        "specs_version": f.specs_version,
                        "meta_hash": f.meta_hash,    
                    })
                })
            }
            Card::NameVersionCard { f } => {
                json!({
                    "type": "NameVersion",
                    "value": json!({
                        "name": f.name,
                        "version": f.version,
                    })
                })
            }
            Card::NetworkGenesisHashCard { f } => {
                json!({
                    "type": "NetworkGenesisHash",
                    "value": f,
                })
            }
            Card::NetworkInfoCard { f } => {
                json!({
                    "type": "NetworkInfo",
                    "value": json!({
                        "network_title": f.network_title,
                    })
                })
            }
            Card::NetworkNameCard { f } => {
                json!({
                    "type": "NetworkName",
                    "value": f,
                })
            }
            Card::NewSpecsCard { f } => {
                let encryption = match f.encryption {
                    Encryption::Ed25519 => "ED25519",
                    Encryption::Sr25519 => "Sr25519",
                    Encryption::Ecdsa => "Ecdsa",
                };
                json!({
                    "type": "NetSpecs",
                    "value": json!({
                        "base58prefix": f.base58prefix,
                        "decimals": f.decimals,
                        "encryption": encryption,
                        "genesis_hahs": f.genesis_hash,
                        "name": f.name,
                        "title": f.title,
                        "unit": f.unit
                    })
                })
            }
            Card::NonceCard { f } => {
                json!({
                    "type": "Nonce",
                    "value": f,
                })
            }
            Card::NoneCard => {
                json!({
                    "type": "None"
                })
            }
            Card::PalletCard { f } => {
                json!({
                    "type": "Pallet",
                    "value": f,
                })
            }
            Card::TextCard { f } => {
                json!({
                    "type": "Text",
                    "value": f,
                })
            }
            Card::TipCard { f } => {
                json!({
                    "type": "Tip",
                    "value": json!({
                        "amount": f.amount,
                        "units": f.units,
                    })
                })
            }
            Card::TipPlainCard { f } => {
                json!({
                    "type": "TipPlain",
                    "value": f,
                })
            }
            Card::TxSpecCard { f } => {
                json!({
                    "type": "TxSpec",
                    "value": f,
                })
            }
            Card::TxSpecPlainCard { f } => {
                json!({
                    "type": "TxSpecPlain",
                    "value": json!({
                        "network_genesis_hash": f.network_genesis_hash,
                        "version": f.version,
                        "tx_version": f.tx_version,
                    })
                })
            }
            Card::TypesInfoCard { f } => {
                json!({
                    "type": "TypesInfo",
                    "value": json!({
                        "types_on_file": f.types_on_file,
                        "types_hash": f.types_hash,
                    })
                })
            }
            Card::VarNameCard { f } => {
                json!({
                    "type": "VarName",
                    "value": f,
                })
            }
            Card::VerifierCard { f } => {
                json!({
                    "type": "Verifier",
                    "value": json!({
                        "public_key": f.public_key,
                        "encryption": f.encryption,
                    })
                })
            }
            Card::WarningCard { f } => {
                json!({
                    "type": "Warning",
                    "value": f,
                })
            }
        }
    }
}