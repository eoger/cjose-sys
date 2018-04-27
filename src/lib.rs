#![allow(non_camel_case_types)]

pub const CJOSE_VERSION: &'static [u8; 6usize] = b"0.6.1\0";
pub const CJOSE_ERR_NONE: u32 = 0;
pub const CJOSE_ERR_INVALID_ARG: u32 = 1;
pub const CJOSE_ERR_INVALID_STATE: u32 = 2;
pub const CJOSE_ERR_NO_MEMORY: u32 = 3;
pub const CJOSE_ERR_CRYPTO: u32 = 4;
#[repr(C)]
pub struct cjose_err {
    pub code: u32,
    pub message: *const ::std::os::raw::c_char,
    pub function: *const ::std::os::raw::c_char,
    pub file: *const ::std::os::raw::c_char,
    pub line: ::std::os::raw::c_ulong,
}
extern "C" {
    pub fn cjose_err_message(code: u32) -> *const ::std::os::raw::c_char;
    pub static mut CJOSE_HDR_ALG: *const ::std::os::raw::c_char;
    pub static mut CJOSE_HDR_ENC: *const ::std::os::raw::c_char;
    pub static mut CJOSE_HDR_CTY: *const ::std::os::raw::c_char;
    pub static mut CJOSE_HDR_KID: *const ::std::os::raw::c_char;
    pub static mut CJOSE_HDR_EPK: *const ::std::os::raw::c_char;
    pub static mut CJOSE_HDR_APU: *const ::std::os::raw::c_char;
    pub static mut CJOSE_HDR_APV: *const ::std::os::raw::c_char;
    pub static mut CJOSE_HDR_ALG_NONE: *const ::std::os::raw::c_char;
    pub static mut CJOSE_HDR_ALG_ECDH_ES: *const ::std::os::raw::c_char;
    pub static mut CJOSE_HDR_ALG_RSA_OAEP: *const ::std::os::raw::c_char;
    pub static mut CJOSE_HDR_ALG_RSA1_5: *const ::std::os::raw::c_char;
    pub static mut CJOSE_HDR_ALG_A128KW: *const ::std::os::raw::c_char;
    pub static mut CJOSE_HDR_ALG_A192KW: *const ::std::os::raw::c_char;
    pub static mut CJOSE_HDR_ALG_A256KW: *const ::std::os::raw::c_char;
    pub static mut CJOSE_HDR_ALG_PS256: *const ::std::os::raw::c_char;
    pub static mut CJOSE_HDR_ALG_PS384: *const ::std::os::raw::c_char;
    pub static mut CJOSE_HDR_ALG_PS512: *const ::std::os::raw::c_char;
    pub static mut CJOSE_HDR_ALG_RS256: *const ::std::os::raw::c_char;
    pub static mut CJOSE_HDR_ALG_RS384: *const ::std::os::raw::c_char;
    pub static mut CJOSE_HDR_ALG_RS512: *const ::std::os::raw::c_char;
    pub static mut CJOSE_HDR_ALG_HS256: *const ::std::os::raw::c_char;
    pub static mut CJOSE_HDR_ALG_HS384: *const ::std::os::raw::c_char;
    pub static mut CJOSE_HDR_ALG_HS512: *const ::std::os::raw::c_char;
    pub static mut CJOSE_HDR_ALG_ES256: *const ::std::os::raw::c_char;
    pub static mut CJOSE_HDR_ALG_ES384: *const ::std::os::raw::c_char;
    pub static mut CJOSE_HDR_ALG_ES512: *const ::std::os::raw::c_char;
    pub static mut CJOSE_HDR_ALG_DIR: *const ::std::os::raw::c_char;
    pub static mut CJOSE_HDR_ENC_A256GCM: *const ::std::os::raw::c_char;
    pub static mut CJOSE_HDR_ENC_A128CBC_HS256: *const ::std::os::raw::c_char;
    pub static mut CJOSE_HDR_ENC_A192CBC_HS384: *const ::std::os::raw::c_char;
    pub static mut CJOSE_HDR_ENC_A256CBC_HS512: *const ::std::os::raw::c_char;
}
#[repr(C)]
pub struct cjose_header_t {
    _unused: [u8; 0],
}
extern "C" {
    pub fn cjose_header_new(err: *mut cjose_err) -> *mut cjose_header_t;
    pub fn cjose_header_retain(header: *mut cjose_header_t) -> *mut cjose_header_t;
    pub fn cjose_header_release(header: *mut cjose_header_t);
    pub fn cjose_header_set(
        header: *mut cjose_header_t,
        attr: *const ::std::os::raw::c_char,
        value: *const ::std::os::raw::c_char,
        err: *mut cjose_err,
    ) -> bool;
    pub fn cjose_header_get(
        header: *mut cjose_header_t,
        attr: *const ::std::os::raw::c_char,
        err: *mut cjose_err,
    ) -> *const ::std::os::raw::c_char;
    pub fn cjose_header_set_raw(
        header: *mut cjose_header_t,
        attr: *const ::std::os::raw::c_char,
        value: *const ::std::os::raw::c_char,
        err: *mut cjose_err,
    ) -> bool;
    pub fn cjose_header_get_raw(
        header: *mut cjose_header_t,
        attr: *const ::std::os::raw::c_char,
        err: *mut cjose_err,
    ) -> *mut ::std::os::raw::c_char;
}
pub const CJOSE_JWK_KTY_RSA: u32 = 1;
pub const CJOSE_JWK_KTY_EC: u32 = 2;
pub const CJOSE_JWK_KTY_OCT: u32 = 3;
extern "C" {
    pub fn cjose_jwk_name_for_kty(
        kty: u32,
        err: *mut cjose_err,
    ) -> *const ::std::os::raw::c_char;
}
#[repr(C)]
pub struct cjose_jwk_t {
    _unused: [u8; 0],
}
extern "C" {
    pub fn cjose_jwk_retain(jwk: *mut cjose_jwk_t, err: *mut cjose_err) -> *mut cjose_jwk_t;
    pub fn cjose_jwk_release(jwk: *mut cjose_jwk_t) -> bool;
    pub fn cjose_jwk_get_kty(jwk: *const cjose_jwk_t, err: *mut cjose_err) -> u32;
    pub fn cjose_jwk_get_keysize(jwk: *const cjose_jwk_t, err: *mut cjose_err) -> usize;
    pub fn cjose_jwk_get_keydata(
        jwk: *const cjose_jwk_t,
        err: *mut cjose_err,
    ) -> *mut ::std::os::raw::c_void;
    pub fn cjose_jwk_get_kid(
        jwk: *const cjose_jwk_t,
        err: *mut cjose_err,
    ) -> *const ::std::os::raw::c_char;
    pub fn cjose_jwk_set_kid(
        jwk: *mut cjose_jwk_t,
        kid: *const ::std::os::raw::c_char,
        len: usize,
        err: *mut cjose_err,
    ) -> bool;
    pub fn cjose_jwk_to_json(
        jwk: *const cjose_jwk_t,
        priv_: bool,
        err: *mut cjose_err,
    ) -> *mut ::std::os::raw::c_char;
}
#[repr(C)]
pub struct cjose_jwk_rsa_keyspec {
    pub e: *mut u8,
    pub elen: usize,
    pub n: *mut u8,
    pub nlen: usize,
    pub d: *mut u8,
    pub dlen: usize,
    pub p: *mut u8,
    pub plen: usize,
    pub q: *mut u8,
    pub qlen: usize,
    pub dp: *mut u8,
    pub dplen: usize,
    pub dq: *mut u8,
    pub dqlen: usize,
    pub qi: *mut u8,
    pub qilen: usize,
}
extern "C" {
    pub fn cjose_jwk_create_RSA_random(
        keysize: usize,
        e: *const u8,
        elen: usize,
        err: *mut cjose_err,
    ) -> *mut cjose_jwk_t;
    pub fn cjose_jwk_create_RSA_spec(
        spec: *const cjose_jwk_rsa_keyspec,
        err: *mut cjose_err,
    ) -> *mut cjose_jwk_t;
}
pub const CJOSE_JWK_EC_P_256: i32 = 415;
pub const CJOSE_JWK_EC_P_384: i32 = 715;
pub const CJOSE_JWK_EC_P_521: i32 = 716;
pub const CJOSE_JWK_EC_INVALID: i32 = -1;
#[repr(C)]
pub struct cjose_jwk_ec_keyspec {
    pub crv: i32,
    pub d: *mut u8,
    pub dlen: usize,
    pub x: *mut u8,
    pub xlen: usize,
    pub y: *mut u8,
    pub ylen: usize,
}
extern "C" {
    pub fn cjose_jwk_create_EC_random(
        crv: i32,
        err: *mut cjose_err,
    ) -> *mut cjose_jwk_t;
    pub fn cjose_jwk_create_EC_spec(
        spec: *const cjose_jwk_ec_keyspec,
        err: *mut cjose_err,
    ) -> *mut cjose_jwk_t;
    pub fn cjose_jwk_EC_get_curve(
        jwk: *const cjose_jwk_t,
        err: *mut cjose_err,
    ) -> i32;
    pub fn cjose_jwk_create_oct_random(size: usize, err: *mut cjose_err) -> *mut cjose_jwk_t;
    pub fn cjose_jwk_create_oct_spec(
        data: *const u8,
        len: usize,
        err: *mut cjose_err,
    ) -> *mut cjose_jwk_t;
    pub fn cjose_jwk_import(
        json: *const ::std::os::raw::c_char,
        len: usize,
        err: *mut cjose_err,
    ) -> *mut cjose_jwk_t;
    pub fn cjose_jwk_import_json(
        json: *mut cjose_header_t,
        err: *mut cjose_err,
    ) -> *mut cjose_jwk_t;
    pub fn cjose_jwk_derive_ecdh_ephemeral_key(
        jwk_self: *const cjose_jwk_t,
        jwk_peer: *const cjose_jwk_t,
        err: *mut cjose_err,
    ) -> *mut cjose_jwk_t;
    pub fn cjose_jwk_derive_ecdh_secret(
        jwk_self: *const cjose_jwk_t,
        jwk_peer: *const cjose_jwk_t,
        err: *mut cjose_err,
    ) -> *mut cjose_jwk_t;
}
#[repr(C)]
pub struct cjose_jwe_recipient_t {
    pub jwk: *const cjose_jwk_t,
    pub unprotected_header: *mut cjose_header_t,
}
#[repr(C)]
pub struct cjose_jwe_t {
    _unused: [u8; 0],
}
pub type cjose_key_locator = ::std::option::Option<
    unsafe extern "C" fn(
        jwe: *mut cjose_jwe_t,
        hdr: *mut cjose_header_t,
        arg1: *mut ::std::os::raw::c_void,
    ) -> *const cjose_jwk_t,
>;
extern "C" {
    pub fn cjose_jwe_encrypt(
        jwk: *const cjose_jwk_t,
        header: *mut cjose_header_t,
        plaintext: *const u8,
        plaintext_len: usize,
        err: *mut cjose_err,
    ) -> *mut cjose_jwe_t;
    pub fn cjose_jwe_encrypt_multi(
        recipients: *const cjose_jwe_recipient_t,
        recipient_count: usize,
        protected_header: *mut cjose_header_t,
        shared_unprotected_header: *mut cjose_header_t,
        plaintext: *const u8,
        plaintext_len: usize,
        err: *mut cjose_err,
    ) -> *mut cjose_jwe_t;
    pub fn cjose_jwe_export(
        jwe: *mut cjose_jwe_t,
        err: *mut cjose_err,
    ) -> *mut ::std::os::raw::c_char;
    pub fn cjose_jwe_export_json(
        jwe: *mut cjose_jwe_t,
        err: *mut cjose_err,
    ) -> *mut ::std::os::raw::c_char;
    pub fn cjose_jwe_import(
        compact: *const ::std::os::raw::c_char,
        compact_len: usize,
        err: *mut cjose_err,
    ) -> *mut cjose_jwe_t;
    pub fn cjose_jwe_import_json(
        json: *const ::std::os::raw::c_char,
        json_len: usize,
        err: *mut cjose_err,
    ) -> *mut cjose_jwe_t;
    pub fn cjose_jwe_decrypt(
        jwe: *mut cjose_jwe_t,
        jwk: *const cjose_jwk_t,
        content_len: *mut usize,
        err: *mut cjose_err,
    ) -> *mut u8;
    pub fn cjose_jwe_decrypt_multi(
        jwe: *mut cjose_jwe_t,
        key_locator: cjose_key_locator,
        data: *mut ::std::os::raw::c_void,
        content_len: *mut usize,
        err: *mut cjose_err,
    ) -> *mut u8;
}
extern "C" {
    pub fn cjose_jwe_get_protected(jwe: *mut cjose_jwe_t) -> *mut cjose_header_t;
    pub fn cjose_jwe_release(jwe: *mut cjose_jwe_t);
}
#[repr(C)]
pub struct cjose_jws_t {
    _unused: [u8; 0],
}
extern "C" {
    pub fn cjose_jws_sign(
        jwk: *const cjose_jwk_t,
        protected_header: *mut cjose_header_t,
        plaintext: *const u8,
        plaintext_len: usize,
        err: *mut cjose_err,
    ) -> *mut cjose_jws_t;
    pub fn cjose_jws_export(
        jws: *mut cjose_jws_t,
        ser: *mut *const ::std::os::raw::c_char,
        err: *mut cjose_err,
    ) -> bool;
    pub fn cjose_jws_import(
        compact: *const ::std::os::raw::c_char,
        compact_len: usize,
        err: *mut cjose_err,
    ) -> *mut cjose_jws_t;
    pub fn cjose_jws_verify(
        jws: *mut cjose_jws_t,
        jwk: *const cjose_jwk_t,
        err: *mut cjose_err,
    ) -> bool;
    pub fn cjose_jws_get_plaintext(
        jws: *const cjose_jws_t,
        plaintext: *mut *mut u8,
        plaintext_len: *mut usize,
        err: *mut cjose_err,
    ) -> bool;
    pub fn cjose_jws_get_protected(jws: *mut cjose_jws_t) -> *mut cjose_header_t;
    pub fn cjose_jws_release(jws: *mut cjose_jws_t);
    pub fn cjose_version() -> *const ::std::os::raw::c_char;
}
