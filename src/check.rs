//! `lock check`: busca las variables de entorno que usa el codigo y verifica
//! que esten en el lock. Es un lint orientativo (regex por lenguaje), no una
//! prueba completa: no ve variables construidas dinamicamente ni las de shell o
//! YAML.
//!
//! Con `--pre-push` revisa el contenido de los commits que se van a subir (lo
//! que lee git por stdin), no el arbol de trabajo.

use std::collections::BTreeMap;
use std::io::{BufRead, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use regex::Regex;

use crate::{Error, store};

pub const IGNORE_FILE: &str = ".lockignore";
const MAX_FILE: u64 = 2 * 1024 * 1024;

/// Variables que pone el sistema, el runtime o la plataforma.
const BUILTIN: &[&str] = &[
    "PATH", "HOME", "USER", "SHELL", "PWD", "TERM", "LANG", "TZ", "TMPDIR", "HOSTNAME", "CI", "DEBUG",
    "NODE_ENV", "PORT", "HOST", "MODE", "DEV", "PROD", "SSR", "BASE_URL", "RUST_LOG", "RUST_BACKTRACE",
    "PYTHONPATH", "VIRTUAL_ENV", "GOPATH", "LOCK_KEY", "LOCK_HOME", "LOCK_FILE", "EDITOR", "XDG_CONFIG_HOME",
];
const BUILTIN_PREFIXES: &[&str] = &["npm_", "VERCEL_", "GITHUB_", "RUNNER_", "CARGO_", "NEXT_RUNTIME", "LC_"];

const CODE_EXT: &[&str] = &[
    "js", "jsx", "ts", "tsx", "mjs", "cjs", "mts", "cts", "vue", "svelte", "astro", "py", "go", "rb", "php",
    "rs", "java", "kt", "cs", "ex", "exs", "swift", "dart",
];
const SKIP_DIRS: &[&str] = &[
    "node_modules", ".git", "vendor", "dist", "build", "target", ".next", ".nuxt", ".svelte-kit", "coverage",
    ".venv", "venv", "__pycache__", ".turbo", ".output",
];
const EXAMPLE_FILES: &[&str] = &[".env.example", ".env.sample", ".env.template", ".env.dist", ".env.defaults"];

const NAME: &str = r"([A-Z][A-Z0-9_]*)";

pub struct Reference {
    pub file: PathBuf,
    pub line: usize,
}

/// Archivos relevantes para el escaneo: (ruta relativa, contenido).
pub type Files = Vec<(PathBuf, String)>;

fn relevant(path: &Path) -> bool {
    if path.components().any(|c| SKIP_DIRS.contains(&c.as_os_str().to_str().unwrap_or(""))) {
        return false;
    }
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
    EXAMPLE_FILES.contains(&name) || CODE_EXT.contains(&ext) || path == Path::new(IGNORE_FILE)
}

fn patterns() -> Vec<Regex> {
    let q = r#"['"`]"#;
    [
        format!(r"process\.env\.{NAME}"),
        format!(r"process\.env\[\s*{q}{NAME}{q}\s*\]"),
        format!(r"import\.meta\.env\.{NAME}"),
        format!(r"Bun\.env\.{NAME}"),
        format!(r"Deno\.env\.get\(\s*{q}{NAME}{q}"),
        format!(r#"os\.(?:Getenv|LookupEnv)\(\s*"{NAME}""#),
        format!(r"os\.(?:getenv|environ\.get)\(\s*{q}{NAME}{q}"),
        format!(r"os\.environ\[\s*{q}{NAME}{q}\s*\]"),
        format!(r"ENV(?:\.fetch)?[\[\(]\s*{q}{NAME}{q}"),
        format!(r"\b(?:env|getenv)\(\s*{q}{NAME}{q}"),
        format!(r#"env::var(?:_os)?\(\s*"{NAME}""#),
        format!(r#"env!\(\s*"{NAME}""#),
        format!(r#"System\.getenv\(\s*"{NAME}""#),
        format!(r#"Environment\.GetEnvironmentVariable\(\s*"{NAME}""#),
        format!(r#"System\.(?:get_env|fetch_env!?)\(\s*"{NAME}""#),
        format!(r#"ProcessInfo\.processInfo\.environment\[\s*"{NAME}"\s*\]"#),
    ]
    .iter()
    .map(|p| Regex::new(p).expect("regex valida"))
    .collect()
}

fn is_builtin(name: &str) -> bool {
    BUILTIN.contains(&name) || BUILTIN_PREFIXES.iter().any(|p| name.starts_with(p))
}

/// `.lockignore`: un nombre por linea; `PREFIJO_*` ignora por prefijo. Un `*`
/// solo (que ignoraria todo) se rechaza.
fn parse_ignore(text: &str) -> Result<Vec<String>, Error> {
    let mut out = vec![];
    for (i, l) in text.lines().enumerate() {
        let l = l.split('#').next().unwrap_or("").trim();
        if l.is_empty() {
            continue;
        }
        let base = l.strip_suffix('*').unwrap_or(l);
        if base.len() < 2 || !base.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            return Err(Error::msg(format!("{IGNORE_FILE} linea {}: patron invalido (minimo 2 caracteres antes de *)", i + 1)));
        }
        out.push(l.to_string());
    }
    Ok(out)
}

fn ignored(name: &str, ignore: &[String]) -> bool {
    is_builtin(name)
        || ignore.iter().any(|p| match p.strip_suffix('*') {
            Some(prefix) => name.starts_with(prefix),
            None => p == name,
        })
}

/// Variables referenciadas, con su primera aparicion.
pub fn scan(files: &Files) -> Result<BTreeMap<String, Reference>, Error> {
    let patterns = patterns();
    let destructure = Regex::new(r"\{([^}]*)\}\s*=\s*(?:process\.env|import\.meta\.env|Bun\.env)\b").unwrap();
    let ignore = match files.iter().find(|(p, _)| p == Path::new(IGNORE_FILE)) {
        Some((_, text)) => parse_ignore(text)?,
        None => vec![],
    };
    let mut found: BTreeMap<String, Reference> = BTreeMap::new();
    let mut add = |name: &str, file: &Path, line: usize| {
        if !ignored(name, &ignore) {
            found.entry(name.to_string()).or_insert(Reference { file: file.to_path_buf(), line });
        }
    };

    for (rel, text) in files {
        let fname = rel.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if rel == Path::new(IGNORE_FILE) {
            continue;
        }
        let is_example = EXAMPLE_FILES.contains(&fname);
        for (i, line) in text.lines().enumerate() {
            if is_example {
                let l = line.trim();
                let l = l.strip_prefix("export ").unwrap_or(l);
                if let Some((k, _)) = l.split_once('=')
                    && !l.starts_with('#')
                    && crate::lockfile::valid_key_name(k.trim())
                {
                    add(k.trim(), rel, i + 1);
                }
                continue;
            }
            for re in &patterns {
                for c in re.captures_iter(line) {
                    add(&c[1], rel, i + 1);
                }
            }
            for c in destructure.captures_iter(line) {
                for part in c[1].split(',') {
                    let name = part.split([':', '=']).next().unwrap_or("").trim();
                    if crate::lockfile::valid_key_name(name) && name.chars().all(|c| !c.is_ascii_lowercase()) {
                        add(name, rel, i + 1);
                    }
                }
            }
        }
    }
    Ok(found)
}

/// Archivos relevantes del arbol de trabajo (trackeados y nuevos no ignorados).
/// Sin git, recorre el arbol. Nunca sigue symlinks ni lee archivos enormes.
pub fn worktree_files(root: &Path) -> Result<Files, Error> {
    let out = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["ls-files", "-z", "--cached", "--others", "--exclude-standard"])
        .output();
    let paths: Vec<PathBuf> = match out {
        Ok(out) if out.status.success() => out
            .stdout
            .split(|b| *b == 0)
            .filter(|s| !s.is_empty())
            .map(|s| PathBuf::from(String::from_utf8_lossy(s).into_owned()))
            .collect(),
        _ => {
            let mut v = vec![];
            walk(root, Path::new(""), &mut v)?;
            v
        }
    };
    Ok(paths
        .into_iter()
        .filter(|p| relevant(p))
        .filter_map(|p| store::read_limited(&root.join(&p), MAX_FILE).ok().map(|t| (p, t)))
        .collect())
}

fn walk(root: &Path, rel: &Path, out: &mut Vec<PathBuf>) -> Result<(), Error> {
    for entry in std::fs::read_dir(root.join(rel))? {
        let entry = entry?;
        let name = entry.file_name();
        let rel = rel.join(&name);
        let ft = entry.file_type()?;
        if ft.is_dir() && !SKIP_DIRS.contains(&name.to_str().unwrap_or("")) {
            walk(root, &rel, out)?;
        } else if ft.is_file() {
            out.push(rel);
        }
    }
    Ok(())
}

/// Archivos relevantes tal como estan en el commit `sha`, mas su `.env.lock`.
pub fn commit_files(root: &Path, sha: &str) -> Result<(Files, Option<String>), Error> {
    let out = Command::new("git").arg("-C").arg(root).args(["ls-tree", "-r", "-z", "--long", sha]).output()?;
    if !out.status.success() {
        return Err(Error::msg(format!("git ls-tree {sha} fallo")));
    }
    // Formato: "<modo> <tipo> <objeto> <tamano>\t<ruta>\0"
    let mut wanted: Vec<(PathBuf, String)> = vec![];
    for rec in out.stdout.split(|b| *b == 0).filter(|r| !r.is_empty()) {
        let rec = String::from_utf8_lossy(rec);
        let Some((meta, path)) = rec.split_once('\t') else { continue };
        let f: Vec<&str> = meta.split_whitespace().collect();
        let [mode, kind, object, size] = f[..] else { continue };
        let path = PathBuf::from(path);
        let is_lock = path == Path::new(store::REPO_FILE);
        if kind != "blob" || !(mode == "100644" || mode == "100755") || !(is_lock || relevant(&path)) {
            continue;
        }
        if size.parse::<u64>().unwrap_or(u64::MAX) > MAX_FILE {
            continue;
        }
        wanted.push((path, object.to_string()));
    }

    let contents = cat_blobs(root, wanted.iter().map(|(_, o)| o.as_str()))?;
    let mut files = vec![];
    let mut lock = None;
    for ((path, _), content) in wanted.into_iter().zip(contents) {
        let Some(text) = content else { continue };
        if path == Path::new(store::REPO_FILE) {
            lock = Some(text);
        } else {
            files.push((path, text));
        }
    }
    Ok((files, lock))
}

/// Lee varios blobs con un solo `git cat-file --batch`.
fn cat_blobs<'a>(root: &Path, objects: impl Iterator<Item = &'a str>) -> Result<Vec<Option<String>>, Error> {
    let objects: Vec<&str> = objects.collect();
    if objects.is_empty() {
        return Ok(vec![]);
    }
    let mut child = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["cat-file", "--batch"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()?;
    let mut stdin = child.stdin.take().unwrap();
    let input: String = objects.iter().map(|o| format!("{o}\n")).collect();
    let writer = std::thread::spawn(move || stdin.write_all(input.as_bytes()));
    let mut reader = std::io::BufReader::new(child.stdout.take().unwrap());
    let mut out = vec![];
    for _ in &objects {
        let mut header = String::new();
        reader.read_line(&mut header)?;
        let size: usize = header.split_whitespace().nth(2).and_then(|s| s.parse().ok()).unwrap_or(0);
        let mut buf = vec![0u8; size + 1]; // contenido + '\n'
        reader.read_exact(&mut buf)?;
        buf.pop();
        out.push(String::from_utf8(buf).ok());
    }
    let _ = writer.join();
    child.wait()?;
    Ok(out)
}

/// Lee de stdin las referencias que git va a subir y devuelve los commits locales.
pub fn pre_push_commits() -> Result<Vec<String>, Error> {
    let mut shas = vec![];
    for line in std::io::stdin().lock().lines() {
        let line = line?;
        let f: Vec<&str> = line.split_whitespace().collect();
        if let [_, local_sha, _, _] = f[..]
            && !local_sha.chars().all(|c| c == '0')
            && !shas.iter().any(|s| s == local_sha)
        {
            shas.push(local_sha.to_string());
        }
    }
    Ok(shas)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn files(list: &[(&str, &str)]) -> Files {
        list.iter().map(|(p, t)| (PathBuf::from(p), t.to_string())).collect()
    }

    #[test]
    fn finds_references_across_languages() {
        let f = files(&[
            ("app.ts", "const a = process.env.API_KEY;\nconst { DB_URL, REDIS_URL: r } = process.env;\nimport.meta.env.VITE_X\nprocess.env.NODE_ENV"),
            ("main.go", r#"os.Getenv("GO_SECRET")"#),
            ("app.py", "os.environ['PY_SECRET']\nos.getenv(\"PY_OTHER\")"),
            ("src/lib.rs", r#"std::env::var("RS_SECRET")"#),
            (".env.example", "# comentario\nEXAMPLE_ONLY=\nexport ALSO=1\n"),
            (".lockignore", "VITE_*\n"),
        ]);
        let found = scan(&f).unwrap();
        let names: Vec<&str> = found.keys().map(String::as_str).collect();
        assert_eq!(
            names,
            ["ALSO", "API_KEY", "DB_URL", "EXAMPLE_ONLY", "GO_SECRET", "PY_OTHER", "PY_SECRET", "REDIS_URL", "RS_SECRET"]
        );
        assert_eq!(found["DB_URL"].line, 2);
    }

    #[test]
    fn wildcard_ignore_is_rejected() {
        for bad in ["*\n", "A*\n", "../x\n"] {
            assert!(scan(&files(&[("a.js", "process.env.X"), (".lockignore", bad)])).is_err(), "{bad}");
        }
    }

    #[test]
    fn skips_vendored_dirs() {
        assert!(!relevant(Path::new("node_modules/x/index.js")));
        assert!(relevant(Path::new("src/index.js")));
    }
}
