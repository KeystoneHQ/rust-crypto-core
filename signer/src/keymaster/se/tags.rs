pub const COMMAND_TAG: u16 = 0x0001;
pub const RESPONSE_TAG:u16 = 0x0002;

pub mod methods {
    pub const GET_FIRMWARE_STATUS_TAG: u16 = 0x0102;
    pub const GET_RANDOM_ENTROPY_TAG: u16 = 0x0301;
    pub const ENTROPY_TYPE_TAG: u16 = 0x0201;
    pub const ENTROPY_CHECKSUM_TAG: u16 = 0x030b;
    // TBD
    pub const GET_KEY_TAG: u16 = 0x0305;
    pub const CLEAR_TOKEN_TAG:u16 = 0x0908;
    pub const SIGN_TAG:u16 = 0x0307;
    pub const SET_SECRET_TAG: u16 = 0x0302;

    pub const CURVE_TAG: u16 = 0x030D;
    pub const WALLET_FLAG_TAG: u16 = 0x0210;
    pub const PATH_TAG:u16 = 0x0207;
    pub const AUTH_TOKEN_TAG:u16 = 0x0404;
    pub const NEED_TOKEN_TAG: u16= 0x0405;
    pub const TX_HASH_TAG: u16= 0x0307;


    pub const VERIFY_USER_PASSWORD:u16 = 0x0903;
    pub const CURRENT_PASSWORD:u16 = 0x0402;
    pub const CURRENT_SECRET:u16 = 0x0218;
    // RSA TAG
    pub const RSA_SECRET_FLAG_TAG: u16= 0x0216;
    pub const MASTER_SEED_FLAG_TAG: u16= 0x0217;
    pub const WRITE_RSA_SECRET_FLAG: u16 = 0x0212;
}

pub mod result {
    pub const FIRMWARE_APP_VERSION: u16 = 0x0106;
    pub const ENTROPY: u16 = 0x0202;
    pub const EXT_KET: u16 = 0x020a;
    pub const EXT_MASTER_SEED: u16 = 0x0211;
    pub const EXT_RSA_SECRET: u16 = 0x0212;
    // pub const `KEY`: u16 = 0x0302;
    pub const AUTH_TOKEN: u16 = 0x0404;
    pub const SUCCEED: u16 = 0x0000;
}


