//! Lectura de archivos `.env` (para `lock import`) y comillas para shell.
//!
//! Soporta `KEY=valor`, `export KEY=valor`, comentarios `#`, comillas simples
//! (literales, pueden abarcar varias lineas) y dobles (escapes \n \t \r \" \\
//! \$, pueden abarcar varias lineas). Lo que no entiende lo rechaza en vez de
//! adivinar. Los errores citan el numero de linea, nunca el contenido.

use crate::Error;
use crate::lockfile::valid_key_name;

pub fn parse(text: &str) -> Result<Vec<(String, String)>, Error> {
    let text = text.replace("\r\n", "\n");
    let mut out: Vec<(String, String)> = Vec::new();
    let mut lines = text.split('\n').enumerate().peekable();
    while let Some((i, raw)) = lines.next() {
        let bad = |why: &str| Error::msg(format!("line {}: {why}", i + 1));
        let line = raw.trim_start();
        if line.trim().is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").map(str::trim_start).unwrap_or(line);
        let (key, rest) = line.split_once('=').ok_or_else(|| bad("missing '='"))?;
        let key = key.trim();
        if !valid_key_name(key) {
            return Err(bad("invalid variable name"));
        }
        let rest = rest.trim_start();

        let value = match rest.chars().next() {
            Some(q @ ('"' | '\'')) => {
                // Juntar lineas hasta encontrar la comilla de cierre.
                let mut body = rest[1..].to_string();
                let (value, after) = loop {
                    if let Some(r) = close_quote(&body, q) {
                        break r;
                    }
                    match lines.next() {
                        Some((_, next)) => {
                            body.push('\n');
                            body.push_str(next);
                        }
                        None => return Err(bad("unclosed quote")),
                    }
                };
                let after = after.trim();
                if !after.is_empty() && !after.starts_with('#') {
                    return Err(bad("text after the quotes"));
                }
                value
            }
            _ => {
                let v = match rest.find(" #") {
                    Some(i) => &rest[..i],
                    None => rest,
                };
                v.trim_end().to_string()
            }
        };
        match out.iter_mut().find(|(k, _)| k == key) {
            Some(e) => e.1 = value,
            None => out.push((key.to_string(), value)),
        }
    }
    Ok(out)
}

/// Busca la comilla de cierre en `s`. Devuelve (valor ya interpretado, resto).
fn close_quote(s: &str, q: char) -> Option<(String, &str)> {
    let mut out = String::new();
    let mut chars = s.char_indices();
    while let Some((i, c)) = chars.next() {
        if c == q {
            return Some((out, &s[i + 1..]));
        }
        if c == '\\' && q == '"' {
            match chars.next() {
                Some((_, 'n')) => out.push('\n'),
                Some((_, 't')) => out.push('\t'),
                Some((_, 'r')) => out.push('\r'),
                Some((_, e @ ('"' | '\\' | '$'))) => out.push(e),
                Some((_, other)) => {
                    out.push('\\');
                    out.push(other);
                }
                None => return None,
            }
            continue;
        }
        out.push(c);
    }
    None
}

/// Comillas simples para shell POSIX: seguro con cualquier contenido.
pub fn shell_quote(v: &str) -> String {
    format!("'{}'", v.replace('\'', r"'\''"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kv(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs.iter().map(|(a, b)| (a.to_string(), b.to_string())).collect()
    }

    #[test]
    fn parses_common_forms() {
        let got = parse(
            "# c\r\nA=1\nexport B=\"x\\ny\"\nC='a b # no'\nD=plain # comentario\nE=\"abc\" # ok\nF=\"\\q\"\nG=\nH=a=b\n\n",
        )
        .unwrap();
        assert_eq!(
            got,
            kv(&[
                ("A", "1"),
                ("B", "x\ny"),
                ("C", "a b # no"),
                ("D", "plain"),
                ("E", "abc"),
                ("F", "\\q"),
                ("G", ""),
                ("H", "a=b"),
            ])
        );
    }

    #[test]
    fn multiline_values() {
        let got = parse("KEY=\"-----BEGIN\nabc\n-----END\"\nNEXT='a\nb'\n").unwrap();
        assert_eq!(got, kv(&[("KEY", "-----BEGIN\nabc\n-----END"), ("NEXT", "a\nb")]));
    }

    #[test]
    fn rejects_without_leaking() {
        for bad in ["A=\"abc", "A=\"abc\" basura", "mi secreto sin igual", "1A=x"] {
            let err = parse(bad).expect_err("must fail").to_string();
            assert!(!err.contains("abc") && !err.contains("secreto"), "{err}");
        }
    }

    #[test]
    fn quotes_for_shell() {
        assert_eq!(shell_quote("it's"), r"'it'\''s'");
    }
}
