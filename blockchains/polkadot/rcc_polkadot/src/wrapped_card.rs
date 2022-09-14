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
                    "card": "Author",
                    "value": json!({
                        "base58": f.base58,
                        "path": f.path,
                    })
                })
            }
            Card::AuthorPlainCard { f } => {
                json!({
                    "card": "AuthorPlain",
                    "value": json!({
                        "base58": f.base58
                    })
                })
            }
            Card::AuthorPublicKeyCard { f } => {
                json!({
                    "card": "AuthorPublicKey",
                    "value": json!({
                        "public_key": f.public_key,
                    })
                })
            }
            Card::BalanceCard { f } => {
                json!({
                    "card": "Balance",
                    "value": json!({
                        "amount": f.amount,
                        "units": f.units,
                    })
                })
            }
            Card::BitVecCard { f } => {
                json!({
                    "card": "BitVec",
                    "value": f,
                })
            }
            Card::BlockHashCard { f } => {
                json!({
                    "card": "BlockHash",
                    "value": f
                })
            }
            Card::CallCard { f } => {
                json!({
                    "card": "Call",
                    "value": json!({
                        "method_name": f.method_name
                    })
                })
            }
            Card::DefaultCard { f } => {
                json!({
                    "card": "Default",
                    "value": f
                })
            }
            Card::DerivationsCard { f } => {
                json!({
                    "card": "Derivations",
                    "value": f
                })
            }
            Card::EnumVariantNameCard { f } => {
                json!({
                    "card": "EnumVariantName",
                    "value": json!({
                        "name": f.name
                    })
                })
            }
            Card::EraImmortalCard => {
                json!({
                    "card": "Era",
                    "value": "Immortal"
                })
            }
            Card::EraMortalCard { f } => {
                json!({
                    "card": "Era",
                    "value": json!({
                        "era": f.era,
                        "phase": f.phase,
                        "period": f.period,
                    })
                })
            }
            Card::ErrorCard { f } => {
                json!({
                    "card": "Error",
                    "value": f
                })
            }
            Card::FieldNameCard { f } => {
                json!({
                    "card": "FieldName",
                    "value": json!({
                        "name": f.name
                    })
                })
            }
            Card::FieldNumberCard { f } => {
                json!({
                    "card": "FieldNumber",
                    "value": json!({
                        "number": f.number,
                    })
                })
            }
            Card::IdCard { f } => {
                json!({
                    "card": "Id",
                    "value": json!({
                        "base58": f.base58,
                    })
                })
            }
            Card::IdentityFieldCard { f } => {
                json!({
                    "card": "IdentityField",
                    "value": f,
                })
            }
            Card::MetaCard { f } => {
                json!({
                    "card": "Meta",
                    "value": json!({
                        "specname": f.specname,
                        "specs_version": f.specs_version,
                        "meta_hash": f.meta_hash,    
                    })
                })
            }
            Card::NameVersionCard { f } => {
                json!({
                    "card": "NameVersion",
                    "value": json!({
                        "name": f.name,
                        "version": f.version,
                    })
                })
            }
            Card::NetworkGenesisHashCard { f } => {
                json!({
                    "card": "NetworkGenesisHash",
                    "value": f,
                })
            }
            Card::NetworkInfoCard { f } => {
                json!({
                    "card": "NetworkInfo",
                    "value": json!({
                        "network_title": f.network_title,
                    })
                })
            }
            Card::NetworkNameCard { f } => {
                json!({
                    "card": "NetworkName",
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
                    "card": "NetSpecs",
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
                    "card": "Nonce",
                    "value": f,
                })
            }
            Card::NoneCard => {
                json!({
                    "card": "None"
                })
            }
            Card::PalletCard { f } => {
                json!({
                    "card": "Pallet",
                    "value": f,
                })
            }
            Card::TextCard { f } => {
                json!({
                    "card": "Text",
                    "value": f,
                })
            }
            Card::TipCard { f } => {
                json!({
                    "card": "Tip",
                    "value": json!({
                        "amount": f.amount,
                        "units": f.units,
                    })
                })
            }
            Card::TipPlainCard { f } => {
                json!({
                    "card": "TipPlain",
                    "value": f,
                })
            }
            Card::TxSpecCard { f } => {
                json!({
                    "card": "TxSpec",
                    "value": f,
                })
            }
            Card::TxSpecPlainCard { f } => {
                json!({
                    "card": "TxSpecPlain",
                    "value": json!({
                        "network_genesis_hash": f.network_genesis_hash,
                        "version": f.version,
                        "tx_version": f.tx_version,
                    })
                })
            }
            Card::TypesInfoCard { f } => {
                json!({
                    "card": "TypesInfo",
                    "value": json!({
                        "types_on_file": f.types_on_file,
                        "types_hash": f.types_hash,
                    })
                })
            }
            Card::VarNameCard { f } => {
                json!({
                    "card": "VarName",
                    "value": f,
                })
            }
            Card::VerifierCard { f } => {
                json!({
                    "card": "Verifier",
                    "value": json!({
                        "public_key": f.public_key,
                        "encryption": f.encryption,
                    })
                })
            }
            Card::WarningCard { f } => {
                json!({
                    "card": "Warning",
                    "value": f,
                })
            }
        }
    }
}