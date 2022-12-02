use crate::proto_wrapper::msg::base::Coin;
use cosmos_sdk_proto as proto;
use serde::Serialize;
use crate::CosmosError;


#[derive(Serialize)]
pub struct Fee {
    /// amount is the amount of coins to be paid as a fee
    pub amount: Vec<Coin>,
    /// gas_limit is the maximum gas that can be used in transaction processing
    /// before an out of gas error occurs
    #[serde(rename = "gas")]
    pub gas_limit: u64,
    /// if unset, the first signer is responsible for paying the fees. If set, the specified account must pay the fees.
    /// the payer must be a tx signer (and thus have signed this field in AuthInfo).
    /// setting this field does *not* change the ordering of required signers for the transaction.
    pub payer: String,
    /// if set, the fee payer (either the first signer or the value of the payer field) requests that a fee grant be used
    /// to pay fees instead of the fee payer's own balance. If an appropriate fee grant does not exist or the chain does
    /// not support fee grants, this will fail
    pub granter: String,
}

impl TryFrom<&proto::cosmos::tx::v1beta1::Fee> for Fee {
    type Error = CosmosError;

    fn try_from(proto: &proto::cosmos::tx::v1beta1::Fee) -> Result<Fee, CosmosError> {
        Ok(Fee {
            amount: proto
                .amount
                .iter()
                .map(TryFrom::try_from)
                .collect::<Result<_, _>>()?,
            gas_limit: proto.gas_limit,
            payer: proto.payer.clone(),
            granter: proto.granter.clone(),
        })
    }
}
