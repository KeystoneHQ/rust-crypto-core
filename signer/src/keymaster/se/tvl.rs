use bytes::{Buf, BufMut, Bytes, BytesMut};
use indexmap::IndexMap;
use std::convert::{TryFrom, TryInto};

use crate::error::KSError;
#[derive(Debug)]
pub struct Packet {
    pub stx: u8,
    pub encryption_flag: u8,
    pub length: u16,
    pub payloads: IndexMap<u16, TVL>,
    pub etx: u8,
    pub lrc: u8,
}

impl Packet {
    pub fn new(payloads: IndexMap<u16, TVL>) -> Self {
        let len: u16 = payloads.iter().fold(0, |len, (_, each_value)| {
            len + each_value.to_vec().len() as u16
        });

        let bytes = Self::combine_bytes(2, 0, len, &payloads, 3);
        let lrc_bit = lrc(&bytes);

        Self {
            stx: 2,
            encryption_flag: 0,
            length: len,
            payloads,
            etx: 3,
            lrc: lrc_bit,
        }
    }

    pub fn to_vec(&self) -> Vec<u8> {
        let mut bytes = Self::combine_bytes(
            self.stx,
            self.encryption_flag,
            self.length,
            &self.payloads,
            self.etx,
        );
        let lrc_bit = lrc(&bytes);
        bytes.put_u8(lrc_bit);
        bytes.freeze().to_vec()
    }

    fn combine_bytes(
        stx: u8,
        encryption_flag: u8,
        length: u16,
        payloads: &IndexMap<u16, TVL>,
        etx: u8,
    ) -> BytesMut {
        let mut mm = BytesMut::new();
        mm.put_u8(stx);
        mm.put_u8(encryption_flag);
        mm.put_u16(length);

        for (_key, value) in payloads.iter() {
            let tvl_vec: Vec<u8> = value.to_vec();
            mm.put_slice(tvl_vec.as_slice());
        }
        mm.put_u8(etx);
        mm
    }
}

impl TryFrom<Vec<u8>> for Packet {
    type Error = KSError;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        let caculate_lrc = lrc(&value);
        let mut mm = Bytes::from(value);
        let all_length = mm.len();

        if all_length < 6 {
            return Err(Self::Error::TVLError(
                "vector length is small than 6".to_string(),
            ));
        }

        let stx = mm.get_u8();
        if stx != 2 {
            return Err(Self::Error::TVLError("stx is not 2".to_string()));
        }
        let encryption_flag = mm.get_u8();
        let length = mm.get_u16();

        // if all_length != (length + 6).into() {
        //     return Err(Self::Error::TVLError("all length is invalid".to_string()));
        // }

        let mut payloads = IndexMap::new();

        while mm.remaining() > 2 {
            let tag = mm.get_u16();
            let length = mm.get_u16();
            let value = mm.copy_to_bytes(length.into());
            payloads.insert(tag, TVL::new(tag, length, value));
        }

        let etx = mm.get_u8();
        if etx != 3 {
            return Err(Self::Error::TVLError("etx is not 3".to_string()));
        }
        let lrc_bit = mm.get_u8();

        if caculate_lrc != 0 {
            return Err(Self::Error::TVLError("lrc is not matched".to_string()));
        };

        Ok(Self {
            stx,
            encryption_flag,
            length,
            payloads,
            etx,
            lrc: lrc_bit,
        })
    }
}

#[derive(Debug)]
pub struct TVL {
    pub tag: u16,
    pub length: u16,
    pub value: Bytes,
}

impl TVL {
    pub fn new(tag: u16, length: u16, value: Bytes) -> TVL {
        Self { tag, length, value }
    }

    pub fn to_vec(&self) -> Vec<u8> {
        let mut mm = BytesMut::new();
        mm.put_u16(self.tag);
        mm.put_u16(self.length);
        mm.put_slice(self.value.chunk());
        Vec::from(mm.chunk())
    }
}

impl TryFrom<Vec<u8>> for TVL {
    type Error = KSError;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        let mut mm = Bytes::from(value);

        if mm.len() < 4 {
            return Err(Self::Error::TVLError("value length is not fit".to_string()));
        }

        let tag = mm.get_u16();
        let length = mm.get_u16();
        let value = mm.copy_to_bytes(mm.chunk().len());

        if mm.has_remaining() {
            return Err(Self::Error::TVLError("".to_string()));
        }
        Ok(Self { tag, length, value })
    }
}

pub fn lrc<'a, T: IntoIterator<Item = &'a u8>>(bytes: T) -> u8 {
    let result: u8 = bytes.into_iter().fold(0, |result, i| result ^ i);
    result
}


#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;

    #[test]
    fn it_should_get_right_lrc() {
        let data: Vec<u8> = vec![0xff, 0xee, 0xcc, 0x00, 0xff, 0x11, 0x0c];
        assert_eq!(0x3f, lrc(&data));
        let data: Vec<u8> = vec![
            0x02, 0x00, 0x00, 0x12, 0x00, 0x01, 0x00, 0x02, 0x08, 0x01, 0x08, 0x01, 0x00, 0x08,
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x03,
        ];
        assert_eq!(0x18, lrc(&data));
    }

    #[test]
    fn it_should_construct_packet() {
        let version_sig: Vec<u8> = vec![00, 01, 00, 02, 01, 02];
        let tvl = TVL::try_from(version_sig).unwrap();

        let mut payloads: IndexMap<u16, TVL> = IndexMap::new();
        payloads.insert(1, tvl);

        let packet = Packet::new(payloads);
        assert_eq!(packet.to_vec(), vec![02, 00, 00, 06, 00, 01, 00, 02, 01, 02, 03, 07]);
    }

    #[test]
    fn it_should_contruct_tvl_struct() {
        let version_sig: Vec<u8> = vec![00, 01, 00, 02, 01, 02];
        let tvl = TVL::try_from(version_sig).unwrap();
        assert_eq!(tvl.tag, 1);
        assert_eq!(&tvl.value[..], &[1, 2]);
        assert_eq!(tvl.to_vec(), vec![00, 01, 00, 02, 01, 02])
    }

    #[test]
    fn it_should_return_error_tvl_struct() {
        let version_sig: Vec<u8> = vec![00];
        let tvl = TVL::try_from(version_sig);
        assert!(tvl.is_err());
    }

    #[test]
    fn it_should_retrun_package() {
        let response = hex::decode("0200000e0003000465727221000200020202034c").unwrap();
        let packet = Packet::try_from(response).unwrap();
        let tvl = packet.payloads.get(&3).unwrap();

        assert_eq!(tvl.value, &b"err!"[..]);
        let tvl = packet.payloads.get(&2).unwrap();
        assert_eq!(tvl.value, &b"\x02\x02"[..]);
        let restore = packet.to_vec();
        assert_eq!(
            restore,
            hex::decode("0200000e0003000465727221000200020202034c").unwrap()
        );
    }

    #[test]
    fn it_should_error_for_invalid_package() {
        let response = hex::decode("0200").unwrap();
        let packet = Packet::try_from(response);
        let error_message = packet.unwrap_err().to_string();
        assert_eq!(
            error_message,
            "TVLError:vector length is small than 6".to_string()
        );

        let response = hex::decode("010000000000").unwrap();
        let packet = Packet::try_from(response);
        let error_message = packet.unwrap_err().to_string();
        assert_eq!(error_message, "TVLError:stx is not 2".to_string());

        let response = hex::decode("02000000000000").unwrap();
        let packet = Packet::try_from(response);
        let error_message = packet.unwrap_err().to_string();
        assert_eq!(error_message, "TVLError:all length is invalid".to_string());

        let response = hex::decode("0200000e0003000465727221000200020202044c").unwrap();
        let packet = Packet::try_from(response);
        let error_message = packet.unwrap_err().to_string();
        assert_eq!(error_message, "TVLError:etx is not 3".to_string());

        let response = hex::decode("0200000e0003000465727221000200020202034d").unwrap();
        let packet = Packet::try_from(response);
        let error_message = packet.unwrap_err().to_string();
        assert_eq!(error_message, "TVLError:lrc is not matched".to_string());
    }
}
