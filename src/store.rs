//! Donde viven las cosas, y como se leen y escriben sin sorpresas.
//!
//! - Boveda local: `~/.lock/envs/<Env>.lock` (o `$LOCK_HOME`). En el Mac es la
//!   fuente de verdad.
//! - Claves: `~/.lock/keys/*.key`.
//! - `~/.lock/trusted`: otras identidades cuya firma se acepta.
//! - `~/.lock/recipients`: destinatarios que se agregan a todo entorno nuevo
//!   (por ejemplo, una clave de respaldo guardada offline).
//! - `~/.lock/seen`: version mas alta vista por entorno, contra rollbacks.
//! - Repo: `.env.lock` en la raiz. Copia comiteada del entorno; la usan los
//!   worktrees y los servidores.
//!
//! Todo lo que viene del repo se trata como hostil: se lee sin seguir symlinks,
//! con limite de tamano, y se escribe via temporal exclusivo + rename.

use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use crate::Error;
use crate::lockfile::{self, LockFile};

pub const REPO_FILE: &str = ".env.lock";
/// Variable para indicar explicitamente que archivo usar (por ejemplo en un deploy sin .git).
pub const FILE_VAR: &str = "LOCK_FILE";
pub const MAX_LOCK_FILE: u64 = 1024 * 1024;

pub struct Store {
    pub home: PathBuf,
}

impl Store {
    pub fn open() -> Result<Store, Error> {
        let home = match std::env::var_os("LOCK_HOME") {
            Some(h) => PathBuf::from(h),
            None => {
                let h = std::env::var_os("HOME").ok_or_else(|| Error::msg("HOME no esta definido"))?;
                PathBuf::from(h).join(".lock")
            }
        };
        Ok(Store { home })
    }

    pub fn keys_dir(&self) -> PathBuf {
        self.home.join("keys")
    }

    fn envs_dir(&self) -> PathBuf {
        self.home.join("envs")
    }

    pub fn env_path(&self, env: &str) -> Result<PathBuf, Error> {
        if !lockfile::valid_env_name(env) {
            return Err(Error::msg("nombre de entorno invalido (usa letras, numeros, . _ -)"));
        }
        Ok(self.envs_dir().join(format!("{env}.lock")))
    }

    pub fn list(&self) -> Result<Vec<String>, Error> {
        let mut names: Vec<String> = list_dir(&self.envs_dir(), "lock")?
            .iter()
            .filter_map(|p| p.file_stem()?.to_str().map(String::from))
            .filter(|n| lockfile::valid_env_name(n))
            .collect();
        names.sort_by_key(|n| n.to_lowercase());
        Ok(names)
    }

    pub fn exists(&self, env: &str) -> bool {
        self.env_path(env).is_ok_and(|p| p.exists())
    }

    pub fn load(&self, env: &str) -> Result<Option<LockFile>, Error> {
        let path = self.env_path(env)?;
        match read_lockfile(&path) {
            Ok(f) => Ok(Some(f)),
            Err(e) if is_not_found(&e) => Ok(None),
            Err(e) => Err(e),
        }
    }

    pub fn save(&self, file: &LockFile) -> Result<(), Error> {
        ensure_private_dir(&self.home)?;
        ensure_private_dir(&self.envs_dir())?;
        let path = self.env_path(&file.env)?;
        write_atomic(&path, file.serialize().as_bytes(), 0o600)?;
        self.record_seen(file)
    }

    /// Guarda una copia `<Env>.lock.bak` antes de reemplazar con algo externo.
    pub fn backup(&self, env: &str) -> Result<(), Error> {
        let path = self.env_path(env)?;
        if let Ok(text) = read_limited(&path, MAX_LOCK_FILE) {
            write_atomic(&path.with_extension("lock.bak"), text.as_bytes(), 0o600)?;
        }
        Ok(())
    }

    pub fn delete(&self, env: &str) -> Result<bool, Error> {
        let path = self.env_path(env)?;
        match fs::remove_file(path) {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e.into()),
        }
    }

    /// Bloqueo exclusivo del entorno mientras dura lectura-modificacion-escritura.
    pub fn lock_env(&self, env: &str) -> Result<EnvLock, Error> {
        ensure_private_dir(&self.home)?;
        ensure_private_dir(&self.envs_dir())?;
        let path = self.envs_dir().join(format!(".{env}.lck"));
        let f = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&path)?;
        if unsafe { libc::flock(std::os::fd::AsRawFd::as_raw_fd(&f), libc::LOCK_EX) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(EnvLock { _file: f })
    }

    // --- listas nombre -> identidad publica (trusted, recipients) ---

    pub fn named_list(&self, file: &str) -> Result<Vec<(String, String)>, Error> {
        let path = self.home.join(file);
        let text = match read_limited(&path, 256 * 1024) {
            Ok(t) => t,
            Err(e) if is_not_found(&e) => return Ok(vec![]),
            Err(e) => return Err(e),
        };
        Ok(text
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .filter_map(|l| l.split_once(' ').map(|(a, b)| (a.to_string(), b.trim().to_string())))
            .collect())
    }

    pub fn save_named_list(&self, file: &str, items: &[(String, String)]) -> Result<(), Error> {
        ensure_private_dir(&self.home)?;
        let body: String = items.iter().map(|(n, v)| format!("{n} {v}\n")).collect();
        write_atomic(&self.home.join(file), body.as_bytes(), 0o600)
    }

    // --- proteccion contra rollback ---

    /// Rechaza un archivo con version menor a la mas alta vista para su
    /// entorno, o con la misma version y distinto contenido.
    pub fn check_seen(&self, file: &LockFile) -> Result<(), Error> {
        if std::env::var_os("LOCK_ALLOW_ROLLBACK").is_some() {
            return Ok(());
        }
        let Some((_, seen)) = self.named_list("seen")?.into_iter().find(|(e, _)| *e == file.env) else {
            return Ok(());
        };
        let (version, digest) = seen.split_once(' ').unwrap_or((&seen, ""));
        let version: u64 = version.parse().unwrap_or(0);
        if file.version < version {
            return Err(Error::msg(format!(
                "{} v{} es mas viejo que la v{version} que este equipo ya vio (posible rollback). \
                 Si es intencional: LOCK_ALLOW_ROLLBACK=1",
                file.env, file.version
            )));
        }
        if file.version == version && !digest.is_empty() && digest != file.digest() {
            return Err(Error::msg(format!(
                "{} v{} no coincide con la v{version} que este equipo ya vio: hay dos versiones distintas con el mismo numero (conflicto)",
                file.env, file.version
            )));
        }
        Ok(())
    }

    pub fn record_seen(&self, file: &LockFile) -> Result<(), Error> {
        let mut seen = self.named_list("seen")?;
        let entry = format!("{} {}", file.version, file.digest());
        match seen.iter_mut().find(|(e, _)| *e == file.env) {
            Some((_, v)) => {
                let current: u64 = v.split(' ').next().and_then(|n| n.parse().ok()).unwrap_or(0);
                if file.version < current {
                    return Ok(());
                }
                *v = entry;
            }
            None => seen.push((file.env.clone(), entry)),
        }
        self.save_named_list("seen", &seen)
    }
}

pub struct EnvLock {
    _file: File,
}

fn is_not_found(e: &Error) -> bool {
    matches!(e, Error::Io(io) if io.kind() == ErrorKind::NotFound)
}

/// Crea el directorio con 0700, sin depender del umask.
pub fn ensure_private_dir(dir: &Path) -> Result<(), Error> {
    match fs::symlink_metadata(dir) {
        Ok(m) if m.is_dir() => {
            if m.mode() & 0o077 != 0 && m.uid() == unsafe { libc::getuid() } {
                fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
            }
            Ok(())
        }
        Ok(_) => Err(Error::msg(format!("{} existe y no es un directorio", dir.display()))),
        Err(_) => {
            fs::DirBuilder::new().recursive(true).mode(0o700).create(dir)?;
            Ok(())
        }
    }
}

/// Archivos `*.ext` de `dir`. Un directorio inexistente es una lista vacia; otros errores se propagan.
pub fn list_dir(dir: &Path, ext: &str) -> Result<Vec<PathBuf>, Error> {
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(vec![]),
        Err(e) => return Err(Error::msg(format!("{}: {e}", dir.display()))),
    };
    let mut paths = vec![];
    for e in entries {
        let p = e?.path();
        if p.extension().is_some_and(|x| x == ext) {
            paths.push(p);
        }
    }
    paths.sort();
    Ok(paths)
}

/// Lee un archivo regular sin seguir symlinks y con limite de tamano.
pub fn read_limited(path: &Path, max: u64) -> Result<String, Error> {
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|e| match e.raw_os_error() {
            Some(libc::ELOOP) => Error::msg(format!("{}: es un symlink; lock no los sigue", path.display())),
            _ => Error::Io(e),
        })?;
    let meta = f.metadata()?;
    if !meta.is_file() {
        return Err(Error::msg(format!("{}: no es un archivo regular", path.display())));
    }
    if meta.len() > max {
        return Err(Error::msg(format!("{}: demasiado grande ({} bytes)", path.display(), meta.len())));
    }
    let mut buf = Vec::new();
    f.take(max + 1).read_to_end(&mut buf)?;
    String::from_utf8(buf).map_err(|_| Error::msg(format!("{}: no es texto UTF-8", path.display())))
}

pub fn read_lockfile(path: &Path) -> Result<LockFile, Error> {
    let text = read_limited(path, MAX_LOCK_FILE)?;
    LockFile::parse(&text).map_err(|e| Error::msg(format!("{}: {e}", path.display())))
}

/// Crea un archivo nuevo 0600; falla si ya existe (incluido un symlink).
pub fn create_new_private(path: &Path, content: &[u8]) -> Result<(), Error> {
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|e| Error::msg(format!("{}: {e}", path.display())))?;
    f.write_all(content)?;
    f.sync_all()?;
    Ok(())
}

/// Escribe via temporal aleatorio exclusivo (O_EXCL|O_NOFOLLOW) + rename, y
/// sincroniza el directorio. Si `path` es un symlink, se reemplaza el enlace,
/// nunca el destino.
pub fn write_atomic(path: &Path, content: &[u8], mode: u32) -> Result<(), Error> {
    let dir = path.parent().filter(|d| !d.as_os_str().is_empty()).unwrap_or(Path::new("."));
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("lock");
    let suffix: String = crate::crypt::random_bytes(8).iter().map(|b| format!("{b:02x}")).collect();
    let tmp = dir.join(format!(".{name}.{suffix}.tmp"));
    let result = (|| -> Result<(), Error> {
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&tmp)?;
        f.write_all(content)?;
        f.set_permissions(fs::Permissions::from_mode(mode))?;
        f.sync_all()?;
        fs::rename(&tmp, path)?;
        if let Ok(d) = File::open(dir) {
            let _ = d.sync_all();
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result.map_err(|e| Error::msg(format!("{}: {e}", path.display())))
}

/// Raiz del repositorio git que contiene `start`, si la hay.
pub fn repo_root(start: &Path) -> Option<PathBuf> {
    start.ancestors().find(|d| d.join(".git").exists()).map(Path::to_path_buf)
}

/// `.env.lock` a usar: `$LOCK_FILE` si esta definido; si no, el de la raiz
/// del repo git; fuera de un repo, solo el del directorio actual.
pub fn find_repo_file(cwd: &Path) -> Option<PathBuf> {
    if let Some(p) = std::env::var_os(FILE_VAR) {
        return Some(PathBuf::from(p));
    }
    let candidate = repo_root(cwd).unwrap_or_else(|| cwd.to_path_buf()).join(REPO_FILE);
    fs::symlink_metadata(&candidate).is_ok().then_some(candidate)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    #[test]
    fn write_atomic_never_follows_symlinks() {
        let dir = tempfile::tempdir().unwrap();
        let victim = dir.path().join("victim.txt");
        fs::write(&victim, "intacto").unwrap();
        let target = dir.path().join(".env.lock");
        symlink(&victim, &target).unwrap();
        // Un temporal "predecible" sembrado por el repo tampoco sirve.
        symlink(&victim, dir.path().join(".env.lock.tmp")).unwrap();

        write_atomic(&target, b"nuevo", 0o600).unwrap();
        assert_eq!(fs::read_to_string(&victim).unwrap(), "intacto");
        assert!(!fs::symlink_metadata(&target).unwrap().file_type().is_symlink());
        assert_eq!(fs::read_to_string(&target).unwrap(), "nuevo");
    }

    #[test]
    fn read_limited_rejects_symlinks_and_big_files() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real");
        fs::write(&real, "x".repeat(100)).unwrap();
        symlink(&real, dir.path().join("link")).unwrap();
        assert!(read_limited(&dir.path().join("link"), 1000).is_err());
        assert!(read_limited(&real, 10).is_err());
        assert_eq!(read_limited(&real, 1000).unwrap().len(), 100);
    }

    #[test]
    fn private_dirs_are_0700() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path().join("a/b");
        ensure_private_dir(&d).unwrap();
        assert_eq!(fs::metadata(&d).unwrap().mode() & 0o777, 0o700);
    }
}
