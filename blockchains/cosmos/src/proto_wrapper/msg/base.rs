use serde::Serialize;
use crate::CosmosError;
use cosmos_sdk_proto as proto;


#[derive(Serialize)]
pub struct Coin {
    pub denom: String,
    pub amount: String,
}

impl TryFrom<&proto::cosmos::base::v1beta1::Coin> for Coin {
    type Error = CosmosError;

    fn try_from(proto: &proto::cosmos::base::v1beta1::Coin) -> Result<Coin, CosmosError> {
        Ok(Coin {
            denom: proto.denom.clone(),
            amount: proto.amount.clone(),
        })
    }
}


#[derive(Serialize)]
pub struct Any {
    /// A URL/resource name that uniquely identifies the type of the serialized
    /// protocol buffer message. This string must contain at least
    /// one "/" character. The last segment of the URL's path must represent
    /// the fully qualified name of the type (as in
    /// `path/google.protobuf.Duration`). The name should be in a canonical form
    /// (e.g., leading "." is not accepted).
    ///
    /// In practice, teams usually precompile into the binary all types that they
    /// expect it to use in the context of Any. However, for URLs which use the
    /// scheme `http`, `https`, or no scheme, one can optionally set up a type
    /// server that maps type URLs to message definitions as follows:
    ///
    /// * If no scheme is provided, `https` is assumed.
    /// * An HTTP GET on the URL must yield a \\[google.protobuf.Type\]\[\\]
    ///   value in binary format, or produce an error.
    /// * Applications are allowed to cache lookup results based on the
    ///   URL, or have them precompiled into a binary to avoid any
    ///   lookup. Therefore, binary compatibility needs to be preserved
    ///   on changes to types. (Use versioned type names to manage
    ///   breaking changes.)
    ///
    /// Note: this functionality is not currently available in the official
    /// protobuf release, and it is not used for type URLs beginning with
    /// type.googleapis.com.
    ///
    /// Schemes other than `http`, `https` (or the empty scheme) might be
    /// used with implementation specific semantics.
    pub type_url: String,
    /// Must be a valid serialized protocol buffer of the above specified type.
    pub value: Vec<u8>,
}