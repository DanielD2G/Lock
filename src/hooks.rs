//! Hooks de git (`lock hooks install`, tambien los instala `lock link`):
//! - pre-commit: `lock dump --stage` copia el entorno de la boveda a `.env.lock`
//!   (solo si esta firmado por alguien de confianza) y lo agrega al commit. No
//!   descifra nada, asi que no pide Touch ID.
//! - pre-push: `lock check --pre-push` revisa los commits que se van a subir y
//!   frena si usan variables que no estan en su `.env.lock`.
//!
//! Si el hook ya existe se inserta un bloque marcado despues del shebang. Solo
//! se tocan hooks de shell que sean archivos regulares; cualquier otra cosa
//! (symlink, Python, binario) se rechaza con instrucciones para hacerlo a mano.

use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::{Error, store};

const BEGIN: &str = "# >>> lock >>>";
const END: &str = "# <<< lock <<<";
pub const HOOKS: [(&str, &str); 2] = [("pre-commit", "lock dump --stage"), ("pre-push", "lock check --pre-push")];

fn block(cmd: &str) -> String {
    format!(
        "{BEGIN}\nif command -v lock >/dev/null 2>&1; then\n  {cmd} || exit 1\nelse\n  echo \"lock: no esta instalado; se omite '{cmd}'\" >&2\nfi\n{END}\n"
    )
}

fn git_path(root: &Path, what: &str) -> Result<PathBuf, Error> {
    let out = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["rev-parse", "--path-format=absolute", what])
        .output()?;
    if !out.status.success() {
        return Err(Error::msg("no es un repositorio git"));
    }
    Ok(PathBuf::from(String::from_utf8_lossy(&out.stdout).trim()))
}

fn hooks_dir(root: &Path) -> Result<PathBuf, Error> {
    let out = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["rev-parse", "--path-format=absolute", "--git-path", "hooks"])
        .output()?;
    if !out.status.success() {
        return Err(Error::msg("no es un repositorio git"));
    }
    Ok(PathBuf::from(String::from_utf8_lossy(&out.stdout).trim()))
}

/// Instala los hooks pedidos (`which` son nombres de HOOKS).
pub fn install(root: &Path, which: &[&str]) -> Result<Vec<PathBuf>, Error> {
    let dir = hooks_dir(root)?;
    let common = git_path(root, "--git-common-dir")?;
    if !dir.starts_with(&common) {
        eprintln!(
            "lock: aviso: core.hooksPath apunta a {}; los hooks se instalan ahi y pueden afectar a otros repos",
            dir.display()
        );
    }
    fs::create_dir_all(&dir)?;

    // Primero validar ambos, para no dejar uno instalado y el otro no.
    let mut plans = vec![];
    for (hook, cmd) in HOOKS.iter().filter(|(h, _)| which.contains(h)) {
        let path = dir.join(hook);
        let current = read_hook(&path).map_err(|e| {
            Error::msg(format!("{e}\nAgrega a mano en {}: {cmd}", path.display()))
        })?;
        plans.push((path, with_block(&current, &block(cmd))));
    }
    let mut written = vec![];
    for (path, content) in plans {
        store::write_atomic(&path, content.as_bytes(), 0o755)?;
        written.push(path);
    }
    Ok(written)
}

/// Contenido actual del hook, o vacio si no existe. Rechaza lo que no es un
/// script de shell regular.
fn read_hook(path: &Path) -> Result<String, Error> {
    match fs::symlink_metadata(path) {
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(String::new()),
        Err(e) => return Err(e.into()),
        Ok(m) if !m.file_type().is_file() => {
            return Err(Error::msg(format!("{} no es un archivo regular (symlink?); no lo toco", path.display())));
        }
        Ok(_) => {}
    }
    let text = store::read_limited(path, 1024 * 1024)?;
    let shebang = text.lines().next().unwrap_or("");
    if let Some(interp) = shebang.strip_prefix("#!")
        && !["sh", "bash", "zsh", "dash", "ksh"].iter().any(|s| interp.split(['/', ' ']).any(|w| w == *s))
    {
        return Err(Error::msg(format!("{} no es un script de shell; no lo toco", path.display())));
    }
    Ok(text)
}

/// Quita el bloque de lock de cada hook. Si no queda nada mas que el shebang,
/// borra el archivo. Devuelve los hooks que tocaron.
pub fn uninstall(root: &Path) -> Result<Vec<PathBuf>, Error> {
    let dir = hooks_dir(root)?;
    let mut touched = vec![];
    for (hook, _) in HOOKS {
        let path = dir.join(hook);
        let current = read_hook(&path)?;
        let Some(rest) = without_block(&current) else { continue };
        if rest.lines().all(|l| l.trim().is_empty() || l.starts_with("#!")) {
            fs::remove_file(&path)?;
        } else {
            store::write_atomic(&path, rest.as_bytes(), 0o755)?;
        }
        touched.push(path);
    }
    Ok(touched)
}

/// Estado de cada hook: (nombre, ruta, instalado).
pub fn status(root: &Path) -> Result<Vec<(&'static str, PathBuf, bool)>, Error> {
    let dir = hooks_dir(root)?;
    Ok(HOOKS
        .iter()
        .map(|(hook, _)| {
            let path = dir.join(hook);
            let installed = read_hook(&path).is_ok_and(|t| t.contains(BEGIN));
            (*hook, path, installed)
        })
        .collect())
}

fn without_block(current: &str) -> Option<String> {
    let start = current.find(BEGIN)?;
    let end = current.find(END)?;
    let end = end + END.len() + usize::from(current[end + END.len()..].starts_with('\n'));
    Some(format!("{}{}", &current[..start], &current[end..]))
}

fn with_block(current: &str, block: &str) -> String {
    if let (Some(start), Some(end)) = (current.find(BEGIN), current.find(END)) {
        let end = end + END.len() + usize::from(current[end + END.len()..].starts_with('\n'));
        return format!("{}{block}{}", &current[..start], &current[end..]);
    }
    if current.trim().is_empty() {
        return format!("#!/bin/sh\n{block}");
    }
    match current.strip_prefix("#!") {
        Some(_) => {
            let nl = current.find('\n').map_or(current.len(), |i| i + 1);
            format!("{}{block}{}", &current[..nl], &current[nl..])
        }
        None => format!("{block}{current}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inserts_after_shebang_and_is_idempotent() {
        let b = block("lock check");
        let once = with_block("#!/bin/sh\nnpm test\nexec foo\n", &b);
        assert!(once.starts_with("#!/bin/sh\n# >>> lock >>>"));
        assert!(once.ends_with("npm test\nexec foo\n"));
        assert_eq!(with_block(&once, &b), once);
        assert_eq!(with_block("", &b), format!("#!/bin/sh\n{b}"));
    }

    #[test]
    fn uninstall_restores_original() {
        let original = "#!/bin/sh\nnpm test\n";
        let with = with_block(original, &block("lock check"));
        assert_eq!(without_block(&with).as_deref(), Some(original));
        assert_eq!(without_block(original), None);
    }

    #[test]
    fn refuses_non_shell_and_symlinks() {
        let dir = tempfile::tempdir().unwrap();
        let py = dir.path().join("py");
        fs::write(&py, "#!/usr/bin/env python3\nprint(1)\n").unwrap();
        assert!(read_hook(&py).is_err());
        let sh = dir.path().join("sh");
        fs::write(&sh, "#!/usr/bin/env bash\necho\n").unwrap();
        assert!(read_hook(&sh).is_ok());
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&sh, &link).unwrap();
        assert!(read_hook(&link).is_err());
    }
}
