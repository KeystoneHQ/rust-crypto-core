pub struct Polkadot {}

#[cfg(test)]
mod tests {
    use parity_scale_codec::Decode;
    use sp_core::{Bytes};
    use sp_core::bytes::from_hex;
    use sp_runtime::traits::{Block, Extrinsic};

    #[test]
    fn test() {
        let hex = "0x4d028400fe747dadf0f62c7d1bac6988a156fdd41cf2d14ccfdc15e289512a7073bbf26601dcf49243aff231fd749266480bf23324595c3969b3d205fb25deefade0711745ae66436d7795f6e3bbbd6c6be41a0219b7aea562c95e78203392fc61c0c97f81c5007e480300000400001850549beffb13c099820ede4a5724228681dd2f86747e82ef48d6b627483f17070010a5d4e8";
        let mut encoded = Bytes::from(from_hex(hex).unwrap());
        let result = Decode::decode(&mut &encoded[..]).unwrap();

    }
}