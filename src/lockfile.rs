//! Formato del archivo `.lock`. Es texto plano y amigable con git: los nombres
//! de los secretos se ven (para listar y validar sin descifrar), los valores no.
//!
//! ```text
//! # Cifrado con lock: no editar a mano. Los nombres son publicos; los valores no.
//! @lock v1
//! @env Navis
//! @version 3
//! @recipient mac-daniel p256-se lockpub1:... <efimera>.<clave envuelta>
//! API_KEY=lock1:<nonce+cifrado>
//! @signature mac-daniel lockpub1:<publica de firma> <firma>
//! ```
//!
//! La firma cubre todo lo anterior. Un archivo solo se usa (para listar, copiar
//! o descifrar) si lo firmo alguien de confianza en esta maquina.

use std::collections::HashSet;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::crypt::{self, Secret};
use crate::identity::{self, Identity, Signer};
use crate::Error;

const HEADER: &str = "# Cifrado con lock: no editar a mano. Los nombres son publicos; los valores no.";
const VALUE_PREFIX: &str = "lock1:";
const MAX_ENTRIES: usize = 10_000;
const MAX_RECIPIENTS: usize = 256;
const MAX_NAME: usize = 128;

#[derive(Clone, Debug, PartialEq)]
pub struct Recipient {
    pub name: String,
    pub kind: String,
    pub public: Vec<u8>,
    eph: Vec<u8>,
    wrapped: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct SignatureLine {
    pub signer: String,
    pub public: Vec<u8>,
    sig: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct LockFile {
    pub env: String,
    pub version: u64,
    pub recipients: Vec<Recipient>,
    /// Ordenados por nombre para que los diffs sean estables.
    entries: Vec<(String, Vec<u8>)>,
    pub signature: Option<SignatureLine>,
}

/// Un entorno abierto: tiene la clave de datos en memoria.
pub struct Unlocked {
    file: LockFile,
    data_key: Secret,
}

pub type Value = Zeroizing<String>;

fn valid_name(s: &str, extra: &str) -> bool {
    let mut chars = s.chars();
    !s.is_empty()
        && s.len() <= MAX_NAME
        && chars.next().is_some_and(|c| c.is_ascii_alphanumeric() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || extra.contains(c))
}

pub fn valid_env_name(s: &str) -> bool {
    valid_name(s, ".-") && !s.starts_with('_')
}

/// Nombres de identidades y destinatarios.
pub fn valid_id_name(s: &str) -> bool {
    valid_name(s, ".-#")
}

pub fn valid_key_name(s: &str) -> bool {
    valid_name(s, "") && !s.starts_with(|c: char| c.is_ascii_digit())
}

impl LockFile {
    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.entries.iter().map(|(n, _)| n.as_str())
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn contains(&self, name: &str) -> bool {
        self.entries.iter().any(|(n, _)| n == name)
    }

    /// Huella del contenido, para detectar dos versiones distintas con el mismo numero.
    pub fn digest(&self) -> String {
        let h = Sha256::digest(self.serialize().as_bytes());
        h.iter().take(16).map(|b| format!("{b:02x}")).collect()
    }

    /// Interpreta el archivo de forma estricta. Los errores citan el numero de
    /// linea pero nunca su contenido, por si alguien pego un secreto en claro.
    pub fn parse(text: &str) -> Result<LockFile, Error> {
        let mut f = LockFile { env: String::new(), version: 0, recipients: vec![], entries: vec![], signature: None };
        let (mut magic, mut has_version) = (false, false);
        let mut names = HashSet::new();
        for (i, raw) in text.lines().enumerate() {
            let bad = |why: &str| Error::msg(format!("archivo lock invalido (linea {}): {why}", i + 1));
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if f.signature.is_some() {
                return Err(bad("contenido despues de la firma"));
            }
            if let Some(rest) = line.strip_prefix('@') {
                let (tag, val) = rest.split_once(' ').ok_or_else(|| bad("linea incompleta"))?;
                match tag {
                    "lock" if magic => return Err(bad("@lock repetido")),
                    "lock" if val == "v1" => magic = true,
                    "lock" => return Err(bad("version de formato no soportada")),
                    "env" if !f.env.is_empty() => return Err(bad("@env repetido")),
                    "env" if valid_env_name(val) => f.env = val.to_string(),
                    "env" => return Err(bad("nombre de entorno invalido")),
                    "version" if has_version => return Err(bad("@version repetido")),
                    "version" => {
                        f.version = val.parse().map_err(|_| bad("version invalida"))?;
                        has_version = true;
                    }
                    "recipient" => {
                        let p: Vec<&str> = val.split(' ').collect();
                        let [name, kind, public, wrap] = p[..] else { return Err(bad("destinatario mal formado")) };
                        if !valid_id_name(name) || identity::Kind::parse(kind).is_err() {
                            return Err(bad("destinatario invalido"));
                        }
                        let (eph, wrapped) = wrap.split_once('.').ok_or_else(|| bad("destinatario mal formado"))?;
                        let public = identity::decode_public(public).map_err(|_| bad("clave publica invalida"))?;
                        if f.recipients.iter().any(|r| r.name == name || r.public == public) {
                            return Err(bad("destinatario repetido"));
                        }
                        f.recipients.push(Recipient {
                            name: name.into(),
                            kind: kind.into(),
                            public,
                            eph: B64.decode(eph).map_err(|_| bad("base64 invalido"))?,
                            wrapped: B64.decode(wrapped).map_err(|_| bad("base64 invalido"))?,
                        });
                    }
                    "signature" => {
                        let p: Vec<&str> = val.split(' ').collect();
                        let [signer, public, sig] = p[..] else { return Err(bad("firma mal formada")) };
                        if !valid_id_name(signer) {
                            return Err(bad("firmante invalido"));
                        }
                        f.signature = Some(SignatureLine {
                            signer: signer.into(),
                            public: identity::decode_public(public).map_err(|_| bad("clave de firma invalida"))?,
                            sig: B64.decode(sig).map_err(|_| bad("base64 invalido"))?,
                        });
                    }
                    _ => return Err(bad("etiqueta desconocida")),
                }
                continue;
            }
            let (name, val) = line.split_once('=').ok_or_else(|| bad("se esperaba NOMBRE=lock1:..."))?;
            if !valid_key_name(name) {
                return Err(bad("nombre de variable invalido"));
            }
            if !names.insert(name.to_string()) {
                return Err(bad("variable repetida"));
            }
            let sealed = val.strip_prefix(VALUE_PREFIX).ok_or_else(|| bad("valor sin cifrar o corrupto"))?;
            f.entries.push((name.to_string(), B64.decode(sealed).map_err(|_| bad("base64 invalido"))?));
        }
        if !magic || f.env.is_empty() || !has_version {
            return Err(Error::msg("no es un archivo de lock (falta @lock, @env o @version)"));
        }
        if f.recipients.is_empty() || f.recipients.len() > MAX_RECIPIENTS || f.entries.len() > MAX_ENTRIES {
            return Err(Error::msg("archivo lock invalido: cantidad de destinatarios o variables fuera de rango"));
        }
        if f.signature.is_none() {
            return Err(Error::msg("archivo lock sin firma"));
        }
        if f.entries.windows(2).any(|w| w[0].0 >= w[1].0) {
            return Err(Error::msg("archivo lock invalido: variables fuera de orden"));
        }
        Ok(f)
    }

    /// Todo menos comentarios y la firma: es lo que se firma.
    fn canonical(&self) -> String {
        let mut s = format!("@lock v1\n@env {}\n@version {}\n", self.env, self.version);
        for r in &self.recipients {
            s += &format!(
                "@recipient {} {} {} {}.{}\n",
                r.name,
                r.kind,
                identity::encode_public(&r.public),
                B64.encode(&r.eph),
                B64.encode(&r.wrapped)
            );
        }
        for (name, sealed) in &self.entries {
            s += &format!("{name}={VALUE_PREFIX}{}\n", B64.encode(sealed));
        }
        s
    }

    pub fn serialize(&self) -> String {
        let mut s = format!("{HEADER}\n{}", self.canonical());
        if let Some(sig) = &self.signature {
            s += &format!(
                "@signature {} {} {}\n",
                sig.signer,
                identity::encode_public(&sig.public),
                B64.encode(&sig.sig)
            );
        }
        s
    }

    /// Verifica que la firma sea valida y de un firmante de confianza.
    /// Devuelve el nombre local de ese firmante.
    pub fn verify<'a>(&self, trusted: &'a [Signer]) -> Result<&'a str, Error> {
        let sig = self.signature.as_ref().ok_or_else(|| Error::msg("archivo sin firma"))?;
        if !crypt::verify(&sig.public, self.canonical().as_bytes(), &sig.sig) {
            return Err(Error::msg(format!("{}: la firma no es valida; el archivo fue alterado", self.env)));
        }
        trusted.iter().find(|t| t.public == sig.public).map(|t| t.name.as_str()).ok_or_else(|| {
            Error::msg(format!(
                "{} v{} lo firmo \"{}\", que no es de confianza en este equipo. \
                 Si es una identidad tuya, agregala con `lock trust add <nombre> <lockid1:...>`.",
                self.env, self.version, sig.signer
            ))
        })
    }

    /// Crea un entorno vacio con los destinatarios dados.
    pub fn create(env: &str, recipients: &[(String, identity::PublicId)]) -> Result<Unlocked, Error> {
        if !valid_env_name(env) {
            return Err(Error::msg("nombre de entorno invalido"));
        }
        let mut u = Unlocked {
            file: LockFile { env: env.into(), version: 0, recipients: vec![], entries: vec![], signature: None },
            data_key: crypt::new_data_key(),
        };
        for (name, id) in recipients {
            u.add_recipient(name, id)?;
        }
        Ok(u)
    }

    /// Verifica la firma y abre el entorno con la primera identidad local que
    /// sea destinataria. Si una identidad falla (por ejemplo, un blob del
    /// Secure Enclave de otro Mac), prueba la siguiente; si el usuario cancela
    /// Touch ID, se detiene.
    pub fn unlock(&self, ids: &[Identity], trusted: &[Signer], reason: &str) -> Result<Unlocked, Error> {
        self.verify(trusted)?;
        let mut last_err = None;
        for id in ids {
            let Some(r) = self.recipients.iter().find(|r| r.public == id.public.encryption) else { continue };
            let attempt = id
                .shared(&r.eph, reason)
                .and_then(|shared| crypt::unwrap(&shared, &r.eph, &r.public, &r.wrapped));
            match attempt {
                Ok(data_key) => return Ok(Unlocked { file: self.clone(), data_key }),
                Err(e) if e.to_string().contains("cancelado") => return Err(e),
                Err(e) => last_err = Some(Error::msg(format!("{}: {e}", id.name))),
            }
        }
        if let Some(e) = last_err {
            return Err(e);
        }
        let names: Vec<&str> = self.recipients.iter().map(|r| r.name.as_str()).collect();
        Err(Error::msg(format!(
            "ninguna de tus claves puede abrir {} (destinatarios: {}). `lock key` muestra tu identidad para que te agreguen.",
            self.env,
            names.join(", ")
        )))
    }
}

impl Unlocked {
    pub fn get(&self, name: &str) -> Result<Option<Value>, Error> {
        let Some((_, sealed)) = self.file.entries.iter().find(|(n, _)| n == name) else { return Ok(None) };
        let raw = crypt::open_value(&self.data_key, &self.file.env, name, sealed)?;
        let s = std::str::from_utf8(&raw).map_err(|_| Error::msg("valor no es UTF-8"))?;
        Ok(Some(Zeroizing::new(s.to_string())))
    }

    pub fn all(&self) -> Result<Vec<(String, Value)>, Error> {
        self.file
            .entries
            .iter()
            .map(|(n, _)| Ok((n.clone(), self.get(n)?.unwrap_or_default())))
            .collect()
    }

    pub fn set(&mut self, name: &str, value: &str) -> Result<(), Error> {
        if !valid_key_name(name) {
            return Err(Error::msg(format!("nombre invalido: {name} (usa letras, numeros y _)")));
        }
        let sealed = crypt::seal_value(&self.data_key, &self.file.env, name, value.as_bytes());
        match self.file.entries.iter_mut().find(|(n, _)| n == name) {
            Some(e) => e.1 = sealed,
            None => {
                self.file.entries.push((name.to_string(), sealed));
                self.file.entries.sort_by(|a, b| a.0.cmp(&b.0));
            }
        }
        Ok(())
    }

    pub fn remove(&mut self, name: &str) -> bool {
        let before = self.file.entries.len();
        self.file.entries.retain(|(n, _)| n != name);
        before != self.file.entries.len()
    }

    pub fn add_recipient(&mut self, name: &str, id: &identity::PublicId) -> Result<(), Error> {
        if !valid_id_name(name) {
            return Err(Error::msg(format!("nombre de destinatario invalido: {name}")));
        }
        if self.file.recipients.iter().any(|r| r.name == name || r.public == id.encryption) {
            return Err(Error::msg(format!("{name} ya es destinatario (o su clave ya esta agregada)")));
        }
        let (eph, wrapped) = crypt::wrap(&self.data_key, &id.encryption)?;
        self.file.recipients.push(Recipient {
            name: name.into(),
            kind: id.kind.as_str().into(),
            public: id.encryption.clone(),
            eph,
            wrapped,
        });
        Ok(())
    }

    /// Quita un destinatario y rota la clave de datos: lo que esa clave haya
    /// visto antes sigue comprometido, pero no podra abrir versiones nuevas.
    pub fn remove_recipient(&mut self, name: &str) -> Result<(), Error> {
        if !self.file.recipients.iter().any(|r| r.name == name) {
            return Err(Error::msg(format!("{name} no es destinatario de {}", self.file.env)));
        }
        if self.file.recipients.len() == 1 {
            return Err(Error::msg("no se puede quitar el ultimo destinatario"));
        }
        let values = self.all()?;
        let keep: Vec<Recipient> = self.file.recipients.drain(..).filter(|r| r.name != name).collect();
        self.data_key = crypt::new_data_key();
        self.file.entries.clear();
        for r in keep {
            let (eph, wrapped) = crypt::wrap(&self.data_key, &r.public)?;
            self.file.recipients.push(Recipient { eph, wrapped, ..r });
        }
        for (n, v) in values {
            self.set(&n, &v)?;
        }
        Ok(())
    }

    /// Cierra el entorno: sube la version y lo firma con `signer`.
    pub fn seal(mut self, signer: &Identity, reason: &str) -> Result<LockFile, Error> {
        self.file.version += 1;
        let sig = signer.sign(self.file.canonical().as_bytes(), reason)?;
        self.file.signature =
            Some(SignatureLine { signer: signer.name.clone(), public: signer.public.signing.clone(), sig });
        // Lo que firmamos tiene que poder volver a leerse.
        LockFile::parse(&self.file.serialize())?;
        Ok(self.file)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn me() -> Identity {
        Identity::new_software("me")
    }

    fn trust(ids: &[&Identity]) -> Vec<Signer> {
        ids.iter().map(|i| Signer { name: i.name.clone(), public: i.public.signing.clone() }).collect()
    }

    fn create(env: &str, id: &Identity) -> Unlocked {
        LockFile::create(env, &[(id.name.clone(), id.public.clone())]).unwrap()
    }

    #[test]
    fn roundtrip_through_text() {
        let id = me();
        let mut u = create("Navis", &id);
        u.set("B_KEY", "dos").unwrap();
        u.set("A_KEY", "uno=con=igual\ny salto").unwrap();
        let text = u.seal(&id, "t").unwrap().serialize();
        assert!(text.find("A_KEY").unwrap() < text.find("B_KEY").unwrap());
        assert!(!text.contains("uno"));

        let f = LockFile::parse(&text).unwrap();
        assert_eq!(f.version, 1);
        assert_eq!(f.names().collect::<Vec<_>>(), ["A_KEY", "B_KEY"]);
        let u = f.unlock(std::slice::from_ref(&id), &trust(&[&id]), "t").unwrap();
        assert_eq!(u.get("A_KEY").unwrap().as_deref().map(String::as_str), Some("uno=con=igual\ny salto"));
    }

    #[test]
    fn forged_file_is_rejected() {
        // El atacante conoce la publica de la victima y arma su propio archivo, firmado con su clave.
        let victim = me();
        let attacker = Identity::new_software("attacker");
        let mut u = create("Navis", &victim);
        u.set("DB_URL", "postgres://evil").unwrap();
        let forged = LockFile::parse(&u.seal(&attacker, "t").unwrap().serialize()).unwrap();
        let err = forged.unlock(std::slice::from_ref(&victim), &trust(&[&victim]), "t").err().unwrap();
        assert!(err.to_string().contains("no es de confianza"), "{err}");
    }

    #[test]
    fn tampering_is_detected() {
        let id = me();
        let mut u = create("Navis", &id);
        u.set("A", "1").unwrap();
        u.set("B", "2").unwrap();
        let text = u.seal(&id, "t").unwrap().serialize();
        for edit in [
            text.lines().filter(|l| !l.starts_with("B=")).map(|l| format!("{l}\n")).collect::<String>(),
            text.replace("@version 1", "@version 99"),
            text.replace("@env Navis", "@env Prod"),
        ] {
            let f = LockFile::parse(&edit).unwrap();
            assert!(f.verify(&trust(&[&id])).is_err());
        }
    }

    #[test]
    fn strict_parsing() {
        let id = me();
        let mut u = create("Navis", &id);
        u.set("A", "1").unwrap();
        let text = u.seal(&id, "t").unwrap().serialize();
        let sig_line = text.lines().last().unwrap();
        for bad in [
            text.replace("A=lock1:", "z; touch /tmp/x #=lock1:"),
            text.replace("@env Navis", "@env Navis\n@env Prod"),
            text.replace(sig_line, &format!("A=lock1:AAAA\n{sig_line}")),
            text.replace("A=lock1:", "A=plaintext-secret"),
            text.lines().filter(|l| !l.starts_with("@recipient")).map(|l| format!("{l}\n")).collect(),
            text.lines().filter(|l| !l.starts_with("@signature")).map(|l| format!("{l}\n")).collect(),
            "@lock v1\n@env Demo\n".into(),
        ] {
            let err = LockFile::parse(&bad).expect_err("debe fallar");
            assert!(!err.to_string().contains("plaintext-secret"), "no debe filtrar contenido");
        }
    }

    #[test]
    fn other_identity_cannot_open() {
        let id = me();
        let f = create("Navis", &id).seal(&id, "t").unwrap();
        let other = Identity::new_software("otro");
        assert!(f.unlock(&[other], &trust(&[&id]), "t").is_err());
    }

    #[test]
    fn remove_recipient_rotates_key() {
        let (a, b) = (me(), Identity::new_software("server"));
        let t = trust(&[&a]);
        let mut u = create("Navis", &a);
        u.add_recipient("server", &b.public).unwrap();
        u.set("X", "secreto").unwrap();
        let f = u.seal(&a, "t").unwrap();
        assert!(f.unlock(std::slice::from_ref(&b), &t, "t").is_ok());

        let mut u = f.unlock(std::slice::from_ref(&a), &t, "t").unwrap();
        u.remove_recipient("server").unwrap();
        let f = u.seal(&a, "t").unwrap();
        assert!(f.unlock(std::slice::from_ref(&b), &t, "t").is_err());
        let u = f.unlock(std::slice::from_ref(&a), &t, "t").unwrap();
        assert_eq!(u.get("X").unwrap().as_deref().map(String::as_str), Some("secreto"));
    }
}
