use ring::digest::{Context, SHA384};
use crate::types::transaction::DeepHashItem;

use crate::types::error::ArweaveError;

fn concat_u8_48(left: [u8; 48], right: [u8; 48]) -> Result<[u8; 96], ArweaveError> {
    let mut iter = left.into_iter().chain(right);
    let result = [(); 96].map(|_| iter.next().unwrap());
    Ok(result)
}

pub fn hash_sha384( message: &[u8]) -> Result<[u8; 48], ArweaveError> {
    let mut context = Context::new(&SHA384);
    context.update(message);
    let mut result: [u8; 48] = [0; 48];
    result.copy_from_slice(context.finish().as_ref());
    Ok(result)
}

pub fn hash_all_sha384(messages: Vec<&[u8]>) -> Result<[u8; 48], ArweaveError> {
    let hash: Vec<u8> = messages
        .into_iter()
        .map(|m| hash_sha384(m).unwrap())
        .into_iter()
        .flatten()
        .collect();
    let hash = hash_sha384(&hash)?;
    Ok(hash)
}

pub fn deep_hash(deep_hash_item: DeepHashItem) -> Result<[u8; 48], ArweaveError> {
    let hash = match deep_hash_item {
        DeepHashItem::Blob(blob) => {
            let blob_tag = format!("blob{}", blob.len());
            hash_all_sha384(vec![blob_tag.as_bytes(), &blob])?
        }
        DeepHashItem::List(list) => {
            let list_tag = format!("list{}", list.len());
            let mut hash = hash_sha384(list_tag.as_bytes())?;

            for child in list.into_iter() {
                let child_hash = deep_hash(child)?;
                hash = hash_sha384(&concat_u8_48(hash, child_hash)?)?;
            }
            hash
        }
    };
    Ok(hash)
}