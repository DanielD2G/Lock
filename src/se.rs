//! Secure Enclave de macOS. La implementacion vive en native/se.swift, que
//! build.rs compila como libreria estatica y enlaza en el binario.

#[derive(Clone, Copy)]
pub enum KeyKind {
    Agreement = 0,
    Signing = 1,
}

#[cfg(target_os = "macos")]
mod imp {
    use std::ffi::{CStr, CString, c_char, c_long, c_uchar};

    use super::KeyKind;
    use crate::Error;

    unsafe extern "C" {
        fn lockse_available() -> i32;
        fn lockse_generate(
            kind: i32,
            key: *mut *mut c_uchar,
            key_len: *mut c_long,
            public: *mut *mut c_uchar,
            public_len: *mut c_long,
            err: *mut *mut c_char,
        ) -> i32;
        fn lockse_ecdh(
            key: *const c_uchar,
            key_len: c_long,
            peer: *const c_uchar,
            peer_len: c_long,
            reason: *const c_char,
            out: *mut c_uchar,
            err: *mut *mut c_char,
        ) -> i32;
        fn lockse_sign(
            key: *const c_uchar,
            key_len: c_long,
            msg: *const c_uchar,
            msg_len: c_long,
            reason: *const c_char,
            out: *mut c_uchar,
            err: *mut *mut c_char,
        ) -> i32;
    }

    pub fn available() -> bool {
        unsafe { lockse_available() == 1 }
    }

    /// Crea una clave P-256 dentro del Secure Enclave. Devuelve el blob opaco
    /// (solo usable por este chip) y la clave publica sin comprimir.
    pub fn generate(kind: KeyKind) -> Result<(Vec<u8>, Vec<u8>), Error> {
        let (mut k, mut kl, mut p, mut pl, mut err) =
            (std::ptr::null_mut(), 0, std::ptr::null_mut(), 0, std::ptr::null_mut());
        unsafe {
            if lockse_generate(kind as i32, &mut k, &mut kl, &mut p, &mut pl, &mut err) != 0 {
                return Err(take_error(err));
            }
            let blob = take_bytes(k, kl);
            let public = take_bytes(p, pl);
            Ok((blob, public))
        }
    }

    /// Secreto ECDH con `peer`. Pide Touch ID mostrando `reason`.
    pub fn ecdh(blob: &[u8], peer: &[u8], reason: &str) -> Result<Vec<u8>, Error> {
        let reason = c_reason(reason);
        let mut out = vec![0u8; 32];
        let mut err = std::ptr::null_mut();
        let rc = unsafe {
            lockse_ecdh(
                blob.as_ptr(),
                blob.len() as c_long,
                peer.as_ptr(),
                peer.len() as c_long,
                reason.as_ptr(),
                out.as_mut_ptr(),
                &mut err,
            )
        };
        if rc != 0 {
            return Err(unsafe { take_error(err) });
        }
        Ok(out)
    }

    /// Firma ECDSA (r||s, 64 bytes). Pide Touch ID salvo que este proceso ya lo haya pedido.
    pub fn sign(blob: &[u8], msg: &[u8], reason: &str) -> Result<Vec<u8>, Error> {
        let reason = c_reason(reason);
        let mut out = vec![0u8; 64];
        let mut err = std::ptr::null_mut();
        let rc = unsafe {
            lockse_sign(
                blob.as_ptr(),
                blob.len() as c_long,
                msg.as_ptr(),
                msg.len() as c_long,
                reason.as_ptr(),
                out.as_mut_ptr(),
                &mut err,
            )
        };
        if rc != 0 {
            return Err(unsafe { take_error(err) });
        }
        Ok(out)
    }

    fn c_reason(reason: &str) -> CString {
        CString::new(reason.replace('\0', " ")).expect("no NUL")
    }

    unsafe fn take_bytes(ptr: *mut c_uchar, len: c_long) -> Vec<u8> {
        let v = unsafe { std::slice::from_raw_parts(ptr, len as usize) }.to_vec();
        unsafe { libc::free(ptr.cast()) };
        v
    }

    unsafe fn take_error(err: *mut c_char) -> Error {
        if err.is_null() {
            return Error::msg("secure enclave: unknown error");
        }
        let msg = unsafe { CStr::from_ptr(err) }.to_string_lossy().into_owned();
        unsafe { libc::free(err.cast()) };
        if msg.contains("-128") || msg.contains("Canceled") || msg.contains("cancel") {
            return Error::msg("Touch ID cancelled");
        }
        Error::msg(format!("secure enclave: {msg}"))
    }
}

#[cfg(not(target_os = "macos"))]
mod imp {
    use super::KeyKind;
    use crate::Error;

    const UNAVAILABLE: &str = "secure enclave: only available on macOS";

    pub fn available() -> bool {
        false
    }

    pub fn generate(_kind: KeyKind) -> Result<(Vec<u8>, Vec<u8>), Error> {
        Err(Error::msg(UNAVAILABLE))
    }

    pub fn ecdh(_blob: &[u8], _peer: &[u8], _reason: &str) -> Result<Vec<u8>, Error> {
        Err(Error::msg(UNAVAILABLE))
    }

    pub fn sign(_blob: &[u8], _msg: &[u8], _reason: &str) -> Result<Vec<u8>, Error> {
        Err(Error::msg(UNAVAILABLE))
    }
}

pub use imp::*;
