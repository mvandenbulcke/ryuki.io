//! Ephemeral cryptographic fixtures backed by the same provider as production.

use aws_lc_rs::encoding::AsDer;
use aws_lc_rs::rsa::{KeyPair as RsaKeyPair, KeySize};
use aws_lc_rs::signature::KeyPair as _;
use base64::Engine;
use jsonwebtoken::{DecodingKey, EncodingKey};
use pkcs8::der::Decode;

pub(crate) struct TestRsaKeypair {
    pub(crate) encoding: EncodingKey,
    pub(crate) decoding: DecodingKey,
    pub(crate) public_der: Vec<u8>,
    pub(crate) modulus_b64: String,
    pub(crate) exponent_b64: String,
}

/// Generates a throwaway RSA-2048 fixture without the advisory-affected
/// RustCrypto `rsa` crate. The private key remains in process memory only.
pub(crate) fn make_rsa_keypair() -> TestRsaKeypair {
    let private = RsaKeyPair::generate(KeySize::Rsa2048).expect("AWS-LC RSA key generation");
    let private_der = private.as_der().expect("AWS-LC PKCS#8 serialization");
    let private_info =
        pkcs8::PrivateKeyInfo::from_der(private_der.as_ref()).expect("PKCS#8 test key structure");
    let public = private.public_key();

    let modulus_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(public.modulus().big_endian_without_leading_zero());
    let exponent_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(public.exponent().big_endian_without_leading_zero());
    let decoding = DecodingKey::from_rsa_components(&modulus_b64, &exponent_b64)
        .expect("AWS-LC RSA public components");

    TestRsaKeypair {
        encoding: EncodingKey::from_rsa_der(private_info.private_key),
        decoding,
        public_der: public.as_ref().to_vec(),
        modulus_b64,
        exponent_b64,
    }
}
