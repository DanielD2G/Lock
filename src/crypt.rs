//! Primitivas criptograficas de lock.
//!
//! - Cada entorno tiene una clave de datos aleatoria de 32 bytes.
//! - La clave de datos se envuelve para cada destinatario con ECDH P-256
//!   efimero + HKDF-SHA256 + AES-256-GCM.
//! - Cada valor se cifra con AES-256-GCM con una subclave propia (HKDF de la
//!   clave de datos, el entorno y el nombre), y entorno+nombre como datos
//!   asociados: un valor no puede moverse a otro nombre sin que se detecte.
//! - El archivo completo va firmado con ECDSA P-256 por quien lo escribio. La
//!   firma, y no la clave de datos, es lo que prueba el origen: cualquiera con
//!   tu clave publica puede cifrarte un archivo, pero solo un escritor de
//!   confianza puede firmarlo.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use hkdf::Hkdf;
use p256::ecdsa::signature::{Signer, Verifier};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use p256::{PublicKey, SecretKey};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::Error;

pub const KEY_SIZE: usize = 32;
const NONCE_SIZE: usize = 12;

const INFO_WRAP: &[u8] = b"lock/v1/wrap";
const INFO_VALUE: &str = "lock/v1/value";
const INFO_SIGNING: &[u8] = b"lock/v1/signing-key";

pub type Secret = Zeroizing<Vec<u8>>;

pub fn random_bytes(n: usize) -> Secret {
    let mut b = Zeroizing::new(vec![0u8; n]);
    getrandom::fill(&mut b).expect("system randomness source");
    b
}

pub fn new_data_key() -> Secret {
    random_bytes(KEY_SIZE)
}

/// Genera una clave privada P-256 de software.
pub fn new_secret_key() -> SecretKey {
    loop {
        // Practicamente cualquier valor de 32 bytes es un escalar valido.
        if let Ok(k) = SecretKey::from_slice(&random_bytes(KEY_SIZE)) {
            return k;
        }
    }
}

pub fn parse_public(sec1: &[u8]) -> Result<PublicKey, Error> {
    if sec1.len() != 65 {
        return Err(Error::msg("invalid public key (expected uncompressed P-256)"));
    }
    PublicKey::from_sec1_bytes(sec1).map_err(|_| Error::msg("invalid public key"))
}

/// Secreto ECDH crudo (coordenada x), igual al que devuelve el Secure Enclave.
pub fn ecdh(secret: &SecretKey, peer: &[u8]) -> Result<Secret, Error> {
    let peer = parse_public(peer)?;
    let shared = p256::ecdh::diffie_hellman(secret.to_nonzero_scalar(), peer.as_affine());
    Ok(Zeroizing::new(shared.raw_secret_bytes().to_vec()))
}

/// Clave publica sin comprimir (65 bytes), el formato que usa CryptoKit.
pub fn public_bytes(secret: &SecretKey) -> Vec<u8> {
    secret.public_key().to_sec1_bytes().to_vec()
}

/// Clave de firma de software derivada de la de cifrado: un solo secreto
/// (`LOCK_KEY`) alcanza, sin reutilizar el mismo escalar para ECDH y ECDSA.
pub fn signing_key_from(secret: &SecretKey) -> SigningKey {
    let ikm = Zeroizing::new(secret.to_bytes().to_vec());
    let mut counter = 0u8;
    loop {
        let mut out = Zeroizing::new(vec![0u8; KEY_SIZE]);
        Hkdf::<Sha256>::new(Some(&[counter]), &ikm)
            .expand(INFO_SIGNING, &mut out)
            .expect("32 bytes is a valid HKDF length");
        if let Ok(k) = SigningKey::from_slice(&out) {
            return k;
        }
        counter += 1;
    }
}

pub fn signing_public(key: &SigningKey) -> Vec<u8> {
    key.verifying_key().to_sec1_bytes().to_vec()
}

/// Firma ECDSA P-256/SHA-256 en formato r||s (64 bytes), igual que CryptoKit.
pub fn sign(key: &SigningKey, msg: &[u8]) -> Vec<u8> {
    let sig: Signature = key.sign(msg);
    sig.to_bytes().to_vec()
}

pub fn verify(public: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    let (Ok(vk), Ok(sig)) = (VerifyingKey::from_sec1_bytes(public), Signature::from_slice(sig)) else {
        return false;
    };
    // CryptoKit puede producir firmas con S alto; las normalizamos.
    let sig = sig.normalize_s();
    vk.verify(msg, &sig).is_ok()
}

/// Envuelve `data_key` para `recipient`. Devuelve (publica efimera, cifrado).
pub fn wrap(data_key: &[u8], recipient: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Error> {
    let eph = new_secret_key();
    let shared = ecdh(&eph, recipient)?;
    let eph_pub = public_bytes(&eph);
    let k = wrap_key(&shared, &eph_pub, recipient);
    Ok((eph_pub, seal(&k, data_key, b"")))
}

/// Recupera la clave de datos con el secreto ECDH entre la clave privada del
/// destinatario y `eph`.
pub fn unwrap(shared: &[u8], eph: &[u8], recipient: &[u8], sealed: &[u8]) -> Result<Secret, Error> {
    let k = wrap_key(shared, eph, recipient);
    open(&k, sealed, b"").map(Zeroizing::new)
}

fn wrap_key(shared: &[u8], eph: &[u8], recipient: &[u8]) -> Secret {
    let salt = [eph, recipient].concat();
    derive(Some(&salt), shared, INFO_WRAP)
}

pub fn seal_value(data_key: &[u8], env: &str, name: &str, plaintext: &[u8]) -> Vec<u8> {
    seal(&value_key(data_key, env, name), plaintext, &value_aad(env, name))
}

pub fn open_value(data_key: &[u8], env: &str, name: &str, sealed: &[u8]) -> Result<Secret, Error> {
    open(&value_key(data_key, env, name), sealed, &value_aad(env, name)).map(Zeroizing::new)
}

/// env y name estan validados (sin `|` ni espacios), asi que no hay ambiguedad.
fn value_aad(env: &str, name: &str) -> Vec<u8> {
    format!("{INFO_VALUE}|{env}|{name}").into_bytes()
}

fn value_key(data_key: &[u8], env: &str, name: &str) -> Secret {
    derive(None, data_key, &value_aad(env, name))
}

fn derive(salt: Option<&[u8]>, ikm: &[u8], info: &[u8]) -> Secret {
    let mut out = Zeroizing::new(vec![0u8; KEY_SIZE]);
    Hkdf::<Sha256>::new(salt, ikm)
        .expand(info, &mut out)
        .expect("32 bytes is a valid HKDF length");
    out
}

/// Devuelve nonce || cifrado.
fn seal(key: &[u8], plaintext: &[u8], aad: &[u8]) -> Vec<u8> {
    let cipher = Aes256Gcm::new_from_slice(key).expect("32-byte key");
    let nonce = random_bytes(NONCE_SIZE);
    let ct = cipher
        .encrypt(&Nonce::try_from(nonce.as_slice()).expect("12-byte nonce"), Payload { msg: plaintext, aad })
        .expect("AES-GCM does not fail when encrypting");
    [nonce.as_slice(), &ct].concat()
}

fn open(key: &[u8], sealed: &[u8], aad: &[u8]) -> Result<Vec<u8>, Error> {
    if sealed.len() < NONCE_SIZE {
        return Err(Error::Decrypt);
    }
    let cipher = Aes256Gcm::new_from_slice(key).expect("32-byte key");
    let (nonce, ct) = sealed.split_at(NONCE_SIZE);
    cipher
        .decrypt(&Nonce::try_from(nonce).expect("12-byte nonce"), Payload { msg: ct, aad })
        .map_err(|_| Error::Decrypt)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrap_roundtrip() {
        let dk = new_data_key();
        let sk = new_secret_key();
        let pubk = public_bytes(&sk);
        let (eph, sealed) = wrap(&dk, &pubk).unwrap();
        let shared = ecdh(&sk, &eph).unwrap();
        assert_eq!(unwrap(&shared, &eph, &pubk, &sealed).unwrap(), dk);

        let other = new_secret_key();
        let wrong = ecdh(&other, &eph).unwrap();
        assert!(unwrap(&wrong, &eph, &pubk, &sealed).is_err());
    }

    #[test]
    fn values_are_bound_to_name() {
        let dk = new_data_key();
        let sealed = seal_value(&dk, "Navis", "API_KEY", b"s3cret");
        assert_eq!(open_value(&dk, "Navis", "API_KEY", &sealed).unwrap().as_slice(), b"s3cret");
        assert!(open_value(&dk, "Navis", "OTHER", &sealed).is_err());
        assert!(open_value(&dk, "PcBuddy", "API_KEY", &sealed).is_err());
    }

    #[test]
    fn signatures() {
        let sk = new_secret_key();
        let signer = signing_key_from(&sk);
        assert_eq!(signing_public(&signer), signing_public(&signing_key_from(&sk)), "derivacion estable");
        assert_ne!(signing_public(&signer), public_bytes(&sk), "no reutiliza la clave de cifrado");
        let sig = sign(&signer, b"hola");
        assert!(verify(&signing_public(&signer), b"hola", &sig));
        assert!(!verify(&signing_public(&signer), b"hola!", &sig));
        let other = signing_key_from(&new_secret_key());
        assert!(!verify(&signing_public(&other), b"hola", &sig));
    }
}
