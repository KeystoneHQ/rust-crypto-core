use bytes::{BufMut, BytesMut, Buf, Bytes};
use indexmap::IndexMap;

use super::tvl::{Packet, TVL};
use super::tags::{COMMAND_TAG, methods, RESPONSE_TAG};


#[derive(Default)]
pub struct CommandParams {
    pub wallet_id: Option<u8>,
    pub path: Option<String>,
    pub auth_token: Option<Vec<u8>>,
    pub password: Option<Vec<u8>>,
    pub curve: Option<u8>,
    pub hash: Option<[u8;128]>,
    pub is_master_seed: Option<bool>,
    pub is_rsa_secret: Option<bool>,
    pub secret: Option<Vec<u8>>,
}


pub trait CommandBuilder {
    fn build(params:Option<CommandParams>) -> Option<Command>;
}

pub(crate) struct GetFirmwareStatusCommand;

impl CommandBuilder for GetFirmwareStatusCommand {

    fn build(params:Option<CommandParams>) -> Option<Command> {
        let mut builder = PacketBuilder::new();
        builder.add_command_id(methods::GET_FIRMWARE_STATUS_TAG);
        let packet = builder.build();
        return Some(Command { packet, tag: methods::GET_FIRMWARE_STATUS_TAG })
    }   
}

pub struct GenerateEntropyCommand;

impl CommandBuilder for GenerateEntropyCommand {
    
    fn build(params:Option<CommandParams>) -> Option<Command> {
        let mut builder = PacketBuilder::new();
        builder.add_command_id(methods::GET_RANDOM_ENTROPY_TAG);
        builder.add_payload(methods::ENTROPY_TYPE_TAG, &[01,00]);
        builder.add_payload(methods::ENTROPY_CHECKSUM_TAG, &[00]);
        let packet = builder.build();
        return Some(Command { packet, tag: methods::GET_RANDOM_ENTROPY_TAG })    
    }
}

pub struct GETKeyCommand;

impl CommandBuilder for GETKeyCommand {

    fn build(params:Option<CommandParams>) -> Option<Command> {
        let params = params?;
        let id = params.wallet_id?;
        let path = params.path?;
        let curve = params.curve?;

        let mut builder = PacketBuilder::new();
        builder.add_command_id(methods::GET_KEY_TAG);
        builder.add_payload(methods::CURVE_TAG, &[curve]);
        builder.add_payload(methods::WALLET_FLAG_TAG, &[id]);
        let path_bytes = path.as_bytes();
        builder.add_payload(methods::PATH_TAG, path_bytes);
        match params.is_master_seed {
            Some(true) => builder.add_payload(methods::MASTER_SEED_FLAG_TAG, &[00]),
            _ => (),
        };

        match params.is_rsa_secret {
            Some(true) => builder.add_payload(methods::RSA_SECRET_FLAG_TAG, &[00]),
            _ => (),
        };
        match params.auth_token {
            Some(auth_token) => builder.add_payload(methods::AUTH_TOKEN_TAG, &auth_token),
            None => (),
        };
        
        let packet = builder.build();
        return Some(Command { packet, tag: methods::GET_KEY_TAG })
    }
}

pub struct SignTxCommand;

impl CommandBuilder for SignTxCommand {

    fn build(params:Option<CommandParams>) -> Option<Command> {
        let params = params?;
        let id = params.wallet_id?;
        let path = params.path?;
        let auth_token = params.auth_token?;
        let curve = params.curve?;
        let tx_hash = params.hash?;
    
        let mut builder = PacketBuilder::new();
        builder.add_command_id(methods::SIGN_TAG);
        let path_bytes = path.as_bytes();
        builder.add_payload(methods::PATH_TAG, path_bytes);
        builder.add_payload(methods::CURVE_TAG, &[00]);
        builder.add_payload(methods::WALLET_FLAG_TAG, &[00]);
        
        builder.add_payload(methods::AUTH_TOKEN_TAG, &auth_token);
        builder.add_payload(methods::TX_HASH_TAG, &tx_hash);
        let packet = builder.build();
        return Some(Command { packet, tag: methods::SIGN_TAG })
    }
}



pub struct GenerateTokenCommand;

impl CommandBuilder for GenerateTokenCommand {

    fn build(params:Option<CommandParams>) -> Option<Command> {
        let params = params?;
        let password = params.password?;
        let password_slices = password.as_slice();
        let mut builder = PacketBuilder::new();
        builder.add_command_id(methods::VERIFY_USER_PASSWORD);
        builder.add_payload(methods::CURRENT_PASSWORD, password_slices);
        builder.add_payload(methods::NEED_TOKEN_TAG, &[01]);
        let packet = builder.build();
        return Some(Command { packet, tag: methods::VERIFY_USER_PASSWORD })
    }
}


pub struct ClearTokenCommand;

impl CommandBuilder for ClearTokenCommand {
    
    fn build(params:Option<CommandParams>) -> Option<Command> {
        let mut builder = PacketBuilder::new();
        builder.add_command_id(methods::CLEAR_TOKEN_TAG);
        let packet = builder.build();
        return Some(Command { packet, tag: methods::CLEAR_TOKEN_TAG })
    }
}

pub struct SetSecretCommand;

impl CommandBuilder for SetSecretCommand {
    fn build(params: Option<CommandParams>) -> Option<Command> {
        let params = params?;
        let password = params.password?;
        let password_slices = password.as_slice();
        let secret = params.secret?;
        let secret_slices = secret.as_slice();
        let mut builder = PacketBuilder::new();
        builder.add_command_id(methods::SET_SECRET_TAG);
        builder.add_payload(methods::CURRENT_PASSWORD, password_slices);
        builder.add_payload(methods::WRITE_RSA_SECRET_FLAG, secret_slices);
        let packet = builder.build();
        return Some(Command { packet, tag: methods::SET_SECRET_TAG });
    }
}

fn build_packet(tag: u16) -> Packet {
    let mut mm = BytesMut::new();
    mm.put_u16(tag);
    let bytes = mm.freeze();
    let tvl = TVL::new(COMMAND_TAG, 2, bytes);
    let mut payloads: IndexMap<u16, TVL> = IndexMap::new();
    payloads.insert(1, tvl);
    Packet::new(payloads)
}

struct PacketBuilder {
    payloads: IndexMap<u16, TVL>
}

impl PacketBuilder {
    pub fn new() -> Self {
        Self { payloads: IndexMap::new() }
    }

    pub fn add_command_id(&mut self, tag: u16) {
        let mut mm = BytesMut::new();
        mm.put_u16(tag);
        let bytes = mm.freeze();
        let tvl = TVL::new(COMMAND_TAG, 2, bytes);
        self.payloads.insert(COMMAND_TAG, tvl);
    }

    pub fn add_payload(&mut self, tag: u16, value: &[u8]) {
        let mm = Bytes::copy_from_slice(value);
        let length = value.len() as u16;
        let tvl = TVL::new(tag, length, mm);
        self.payloads.insert(tag, tvl);
    }

    pub fn build(self) -> Packet {
        Packet::new(self.payloads)
    }
}

pub fn parse_result(packet: &Packet, request_tag: u16) -> bool {
    if let Some(tag) = packet.payloads.get(&COMMAND_TAG) {
        let mut tmp = Bytes::copy_from_slice(tag.value.chunk());
        if tmp.get_uint(tmp.len()) == request_tag.into() {
            if let Some(v) = packet.payloads.get(&RESPONSE_TAG) {
                let mut tmp = Bytes::copy_from_slice(v.value.chunk());
                if tmp.get_uint(tmp.len()) == 0 {
                    return true;
                }
            }
        }
    }        

    return false;
}


pub struct Command {
    packet: Packet,
    pub tag: u16,
}

impl Command {
    pub fn to_vec(&self) -> Vec<u8> {
        self.packet.to_vec()
    }
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;

    #[test]
    fn it_should_turn_right_get_firmware_command() {
        let command = GetFirmwareStatusCommand::build(None).unwrap();
        assert_eq!(
            command.to_vec(),
            vec![02, 00, 00, 06, 00, 01, 00, 02, 01, 02, 03, 07]
        )
    }

    #[test]
    fn it_should_turn_right_get_entropy_command() {
        let command = GenerateEntropyCommand::build(None).unwrap();
        assert_eq!(
            command.to_vec(),
            vec![2, 0, 0, 17, 0, 1, 0, 2, 3, 1, 2, 1, 0, 2, 1, 0, 3, 11, 0, 1, 0, 3, 24]
        )
    }
}
