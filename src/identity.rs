//! Identidades: quien puede abrir entornos y quien puede firmarlos.
//!
//! Cada identidad tiene dos pares de claves P-256: uno de cifrado (ECDH, para
//! recibir la clave de datos) y uno de firma (ECDSA, para probar que un archivo
//! lo escribio alguien de confianza).
//!
//! - `p256-se`: ambas claves viven en el Secure Enclave del Mac. En disco solo
//!   hay blobs que unicamente ese chip puede usar, y cada uso pide Touch ID.
//! - `p256`: clave de software para servidores y CI. Un solo secreto
//!   (`lockkey1:...`); la clave de firma se deriva de el.
//!
//! La identidad publica se comparte como `lockid1:...` (tipo + ambas publicas).

use std::path::{Path, PathBuf};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use p256::SecretKey;
use zeroize::Zeroizing;

use crate::crypt::{self, Secret};
use crate::se::{self, KeyKind};
use crate::{Error, store};

pub const ENV_VAR: &str = "LOCK_KEY";
const ID_PREFIX: &str = "lockid1:";
const PUB_PREFIX: &str = "lockpub1:";
const PRIV_PREFIX: &str = "lockkey1:";
const PUBLIC_LEN: usize = 65;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    Software,
    Enclave,
}

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::Software => "p256",
            Kind::Enclave => "p256-se",
        }
    }

    pub fn parse(s: &str) -> Result<Kind, Error> {
        match s {
            "p256" => Ok(Kind::Software),
            "p256-se" => Ok(Kind::Enclave),
            _ => Err(Error::msg("tipo de clave desconocido")),
        }
    }

    fn byte(self) -> u8 {
        match self {
            Kind::Software => 1,
            Kind::Enclave => 2,
        }
    }
}

/// Parte publica de una identidad: lo que se comparte para dar acceso o confianza.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicId {
    pub kind: Kind,
    pub encryption: Vec<u8>,
    pub signing: Vec<u8>,
}

impl PublicId {
    pub fn encode(&self) -> String {
        let mut raw = vec![self.kind.byte()];
        raw.extend_from_slice(&self.encryption);
        raw.extend_from_slice(&self.signing);
        format!("{ID_PREFIX}{}", B64.encode(raw))
    }

    pub fn decode(s: &str) -> Result<PublicId, Error> {
        let bad = || Error::msg(format!("identidad publica invalida: debe ser {ID_PREFIX}... (la imprime `lock key`)"));
        let raw = B64.decode(s.trim().strip_prefix(ID_PREFIX).ok_or_else(bad)?).map_err(|_| bad())?;
        if raw.len() != 1 + 2 * PUBLIC_LEN {
            return Err(bad());
        }
        let kind = match raw[0] {
            1 => Kind::Software,
            2 => Kind::Enclave,
            _ => return Err(bad()),
        };
        let encryption = raw[1..1 + PUBLIC_LEN].to_vec();
        let signing = raw[1 + PUBLIC_LEN..].to_vec();
        crypt::parse_public(&encryption)?;
        crypt::parse_public(&signing)?;
        Ok(PublicId { kind, encryption, signing })
    }
}

pub fn encode_public(public: &[u8]) -> String {
    format!("{PUB_PREFIX}{}", B64.encode(public))
}

pub fn decode_public(s: &str) -> Result<Vec<u8>, Error> {
    let raw = s.strip_prefix(PUB_PREFIX).ok_or_else(|| Error::msg("clave publica invalida"))?;
    let raw = B64.decode(raw).map_err(|_| Error::msg("clave publica invalida"))?;
    crypt::parse_public(&raw)?;
    Ok(raw)
}

/// Un escritor cuya firma se acepta.
#[derive(Clone, Debug)]
pub struct Signer {
    pub name: String,
    pub public: Vec<u8>,
}

pub struct Identity {
    pub name: String,
    pub kind: Kind,
    pub public: PublicId,
    /// Archivo de origen, o `LOCK_KEY`.
    pub source: String,
    /// Firmantes de confianza que venian dentro de `LOCK_KEY`.
    pub embedded_trust: Vec<Vec<u8>>,
    /// Escalar P-256 (software) o blob del Secure Enclave.
    private: Secret,
    /// Blob de firma del Secure Enclave (vacio en software: se deriva).
    sign_private: Secret,
}

impl Identity {
    /// Secreto ECDH con `peer`. Con el Secure Enclave pide Touch ID mostrando `reason`.
    pub fn shared(&self, peer: &[u8], reason: &str) -> Result<Secret, Error> {
        match self.kind {
            Kind::Enclave => se::ecdh(&self.private, peer, reason).map(Zeroizing::new),
            Kind::Software => crypt::ecdh(&self.secret_key()?, peer),
        }
    }

    pub fn sign(&self, msg: &[u8], reason: &str) -> Result<Vec<u8>, Error> {
        match self.kind {
            Kind::Enclave => se::sign(&self.sign_private, msg, reason),
            Kind::Software => Ok(crypt::sign(&crypt::signing_key_from(&self.secret_key()?), msg)),
        }
    }

    fn secret_key(&self) -> Result<SecretKey, Error> {
        SecretKey::from_slice(&self.private).map_err(|_| Error::msg("clave privada invalida"))
    }

    pub fn new_software(name: &str) -> Identity {
        let sk = crypt::new_secret_key();
        Identity {
            name: name.to_string(),
            kind: Kind::Software,
            public: PublicId {
                kind: Kind::Software,
                encryption: crypt::public_bytes(&sk),
                signing: crypt::signing_public(&crypt::signing_key_from(&sk)),
            },
            source: String::new(),
            embedded_trust: vec![],
            private: Zeroizing::new(sk.to_bytes().to_vec()),
            sign_private: Zeroizing::new(vec![]),
        }
    }

    pub fn new_enclave(name: &str) -> Result<Identity, Error> {
        let (blob, encryption) = se::generate(KeyKind::Agreement)?;
        let (sign_blob, signing) = se::generate(KeyKind::Signing)?;
        Ok(Identity {
            name: name.to_string(),
            kind: Kind::Enclave,
            public: PublicId { kind: Kind::Enclave, encryption, signing },
            source: String::new(),
            embedded_trust: vec![],
            private: Zeroizing::new(blob),
            sign_private: Zeroizing::new(sign_blob),
        })
    }

    /// Clave privada `lockkey1:<escalar>[.<firmante de confianza>...]`.
    /// Solo existe para claves de software.
    pub fn private_string(&self, trust: &[Vec<u8>]) -> Option<Zeroizing<String>> {
        if self.kind != Kind::Software {
            return None;
        }
        let mut s = format!("{PRIV_PREFIX}{}", B64.encode(&*self.private));
        for t in trust {
            s.push('.');
            s.push_str(&B64.encode(t));
        }
        Some(Zeroizing::new(s))
    }

    pub fn parse_private(name: &str, s: &str) -> Result<Identity, Error> {
        let bad = || Error::msg(format!("clave privada invalida: debe empezar con {PRIV_PREFIX}"));
        let mut parts = s.trim().strip_prefix(PRIV_PREFIX).ok_or_else(bad)?.split('.');
        let raw = Zeroizing::new(B64.decode(parts.next().unwrap_or("")).map_err(|_| bad())?);
        let sk = SecretKey::from_slice(&raw).map_err(|_| bad())?;
        let mut embedded_trust = vec![];
        for p in parts {
            let public = B64.decode(p).map_err(|_| bad())?;
            crypt::parse_public(&public)?;
            embedded_trust.push(public);
        }
        Ok(Identity {
            name: name.to_string(),
            kind: Kind::Software,
            public: PublicId {
                kind: Kind::Software,
                encryption: crypt::public_bytes(&sk),
                signing: crypt::signing_public(&crypt::signing_key_from(&sk)),
            },
            source: String::new(),
            embedded_trust,
            private: raw,
            sign_private: Zeroizing::new(vec![]),
        })
    }

    /// Escribe `dir/<name>.key` con permisos 0600. Falla si ya existe.
    pub fn save(&mut self, dir: &Path) -> Result<PathBuf, Error> {
        store::ensure_private_dir(dir)?;
        let path = dir.join(format!("{}.key", self.name));
        let mut text = String::from("# Identidad de lock. No compartir ni comitear.\n");
        text += &format!("name {}\nkind {}\npublic {}\n", self.name, self.kind.as_str(), self.public.encode());
        match self.kind {
            Kind::Software => text += &format!("private {}\n", *self.private_string(&[]).unwrap()),
            Kind::Enclave => {
                text += &format!("private {}\n", B64.encode(&*self.private));
                text += &format!("sign-private {}\n", B64.encode(&*self.sign_private));
            }
        }
        store::create_new_private(&path, text.as_bytes())?;
        self.source = path.display().to_string();
        Ok(path)
    }

    fn load_file(path: &Path) -> Result<Identity, Error> {
        let text = Zeroizing::new(store::read_limited(path, 64 * 1024)?);
        let name_from_file = path.file_stem().and_then(|s| s.to_str()).unwrap_or("local").to_string();
        // Formato compacto: el archivo contiene solo `lockkey1:...` (salida de `lock init --print`).
        if text.trim_start().starts_with(PRIV_PREFIX) {
            let mut id = Identity::parse_private(&name_from_file, &text)?;
            id.source = path.display().to_string();
            return Ok(id);
        }
        let field = |key: &str| -> Result<String, Error> {
            text.lines()
                .filter_map(|l| l.trim().split_once(' '))
                .find(|(k, _)| *k == key)
                .map(|(_, v)| v.trim().to_string())
                .ok_or_else(|| Error::msg(format!("falta el campo {key}")))
        };
        let name = field("name")?;
        let mut id = match Kind::parse(&field("kind")?)? {
            Kind::Software => Identity::parse_private(&name, &field("private")?)?,
            Kind::Enclave => {
                let public = PublicId::decode(&field("public")?)?;
                let blob = |k: &str| -> Result<Secret, Error> {
                    Ok(Zeroizing::new(B64.decode(field(k)?).map_err(|_| Error::msg("blob invalido"))?))
                };
                Identity {
                    name,
                    kind: Kind::Enclave,
                    public,
                    source: String::new(),
                    embedded_trust: vec![],
                    private: blob("private")?,
                    sign_private: blob("sign-private")?,
                }
            }
        };
        id.source = path.display().to_string();
        Ok(id)
    }
}

/// `LOCK_NO_ENCLAVE` lo desactiva (tests, o Macs donde se prefiere no usarlo).
/// Solo puede quitar proteccion a claves nuevas: no da acceso a nada existente.
pub fn enclave_available() -> bool {
    std::env::var_os("LOCK_NO_ENCLAVE").is_none() && se::available()
}

/// Carga las identidades de `LOCK_KEY` y de `dir`. Las del Secure Enclave van
/// primero porque son las preferidas en el Mac.
pub fn load_all(dir: &Path) -> Result<Vec<Identity>, Error> {
    let mut ids = Vec::new();
    if let Ok(v) = std::env::var(ENV_VAR) {
        let v = Zeroizing::new(v);
        let parts = v.split([',', '\n', ' ']).filter(|p| !p.trim().is_empty());
        for (i, part) in parts.enumerate() {
            let name = if i == 0 { ENV_VAR.to_string() } else { format!("{ENV_VAR}#{}", i + 1) };
            let mut id = Identity::parse_private(&name, part).map_err(|e| Error::msg(format!("{ENV_VAR}: {e}")))?;
            id.source = ENV_VAR.to_string();
            ids.push(id);
        }
    }
    for p in store::list_dir(dir, "key")? {
        ids.push(Identity::load_file(&p).map_err(|e| Error::msg(format!("{}: {e}", p.display())))?);
    }
    ids.sort_by_key(|id| id.kind != Kind::Enclave);
    Ok(ids)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn software_save_and_load() {
        let dir = tempfile::tempdir().unwrap();
        let mut id = Identity::new_software("server");
        id.save(dir.path()).unwrap();
        let loaded = load_all(dir.path()).unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].public, id.public);
        assert!(id.save(dir.path()).is_err(), "no debe pisar una clave existente");
    }

    #[test]
    fn compact_key_file_and_embedded_trust() {
        let dir = tempfile::tempdir().unwrap();
        let id = Identity::new_software("prod");
        let trusted = Identity::new_software("mac");
        let s = id.private_string(std::slice::from_ref(&trusted.public.signing)).unwrap();
        fs::write(dir.path().join("prod.key"), format!("{}\n", *s)).unwrap();
        let loaded = load_all(dir.path()).unwrap();
        assert_eq!(loaded[0].public, id.public);
        assert_eq!(loaded[0].embedded_trust, vec![trusted.public.signing.clone()]);
    }

    #[test]
    fn public_id_roundtrip() {
        let id = Identity::new_software("x");
        assert_eq!(PublicId::decode(&id.public.encode()).unwrap(), id.public);
        assert!(PublicId::decode("lockid1:AAAA").is_err());
    }
}
