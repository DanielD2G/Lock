//! Reemplaza valores secretos por `[lock:NOMBRE]` en un flujo de salida.
//!
//! Es higiene, no una barrera: evita que un valor aparezca por accidente en
//! logs o en el contexto de un agente, pero un proceso que quiera filtrar un
//! secreto puede transformarlo (base64, al reves, por partes) o escribirlo en
//! un archivo. La barrera real es el Touch ID que autoriza cada `lock run`.
//!
//! Solo se retiene el final del bloque que todavia podria ser el comienzo de un
//! secreto; todo lo demas se emite enseguida, asi un programa interactivo no
//! queda esperando.

use std::io::{self, Read, Write};

use zeroize::Zeroizing;

/// Valores mas cortos que esto no se redactan: generarian reemplazos en todos
/// lados ("1", "true") y no protegen nada real.
pub const MIN_LEN: usize = 4;

pub struct Redactor {
    secrets: Vec<(Zeroizing<Vec<u8>>, Vec<u8>)>,
}

impl Redactor {
    pub fn new<V: AsRef<str>>(values: &[(String, V)]) -> Redactor {
        let mut secrets: Vec<(Zeroizing<Vec<u8>>, Vec<u8>)> = values
            .iter()
            .filter(|(_, v)| v.as_ref().len() >= MIN_LEN)
            .map(|(n, v)| (Zeroizing::new(v.as_ref().as_bytes().to_vec()), format!("[lock:{n}]").into_bytes()))
            .collect();
        // Los mas largos primero: si uno contiene a otro, gana el largo.
        secrets.sort_by_key(|s| std::cmp::Reverse(s.0.len()));
        Redactor { secrets }
    }

    pub fn is_empty(&self) -> bool {
        self.secrets.is_empty()
    }

    /// Procesa `buf`. Devuelve la salida lista y cuantos bytes consumio; lo no
    /// consumido es un posible comienzo de secreto que hay que esperar.
    fn process(&self, buf: &[u8], at_eof: bool) -> (Vec<u8>, usize) {
        let mut out = Vec::with_capacity(buf.len());
        let mut i = 0;
        'outer: while i < buf.len() {
            let rest = &buf[i..];
            for (secret, label) in &self.secrets {
                if rest.starts_with(secret) {
                    out.extend_from_slice(label);
                    i += secret.len();
                    continue 'outer;
                }
                // Lo que queda podria completarse con un secreto (mas largo que
                // cualquier coincidencia completa, por el orden): esperar.
                if !at_eof && secret.starts_with(rest) {
                    return (out, i);
                }
            }
            out.push(buf[i]);
            i += 1;
        }
        (out, i)
    }

    /// Copia `r` en `w` redactando, hasta EOF.
    pub fn copy(&self, mut r: impl Read, mut w: impl Write) -> io::Result<()> {
        let mut pending: Vec<u8> = Vec::new();
        let mut chunk = [0u8; 8192];
        loop {
            let n = match r.read(&mut chunk) {
                Ok(n) => n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            };
            pending.extend_from_slice(&chunk[..n]);
            let (out, used) = self.process(&pending, n == 0);
            pending.drain(..used);
            w.write_all(&out)?;
            w.flush()?;
            if n == 0 {
                return Ok(());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Lector que entrega de a `n` bytes, para simular secretos partidos.
    struct Drip<'a>(&'a [u8], usize);
    impl Read for Drip<'_> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let n = self.1.min(self.0.len()).min(buf.len());
            buf[..n].copy_from_slice(&self.0[..n]);
            self.0 = &self.0[n..];
            Ok(n)
        }
    }

    fn run(values: &[(&str, &str)], input: &str, drip: usize) -> String {
        let values: Vec<(String, String)> = values.iter().map(|(a, b)| (a.to_string(), b.to_string())).collect();
        let mut out = Vec::new();
        Redactor::new(&values).copy(Drip(input.as_bytes(), drip), &mut out).unwrap();
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn redacts_across_chunk_boundaries() {
        let input = "token=sk_live_abcdef y otra vez sk_live_abcdef\n";
        for drip in 1..12 {
            assert_eq!(
                run(&[("STRIPE", "sk_live_abcdef")], input, drip),
                "token=[lock:STRIPE] y otra vez [lock:STRIPE]\n",
                "drip={drip}"
            );
        }
    }

    #[test]
    fn longest_secret_wins_and_short_ones_are_skipped() {
        for drip in 1..6 {
            let got = run(&[("A", "abcd"), ("B", "abcdefgh"), ("C", "xy")], "abcdefgh abcdef xy", drip);
            assert_eq!(got, "[lock:B] [lock:A]ef xy", "drip={drip}");
        }
    }

    #[test]
    fn overlapping_secrets() {
        // "cd" es comienzo de otro secreto, pero "abcd" ya esta completo.
        let got = run(&[("A", "abcd"), ("B", "cdxx")], "abcdz", 1);
        assert_eq!(got, "[lock:A]z");
    }

    #[test]
    fn does_not_hold_unrelated_output() {
        let r = Redactor::new(&[("A".to_string(), "x".repeat(100))]);
        let (out, used) = r.process(b"Ready\n", false);
        assert_eq!((out.as_slice(), used), (&b"Ready\n"[..], 6));
        // Solo se retiene un posible comienzo del secreto.
        let (out, used) = r.process(b"Ready xxx", false);
        assert_eq!((out.as_slice(), used), (&b"Ready "[..], 6));
    }
}
