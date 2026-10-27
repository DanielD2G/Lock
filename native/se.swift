// Puente C para el Secure Enclave de macOS. build.rs lo compila como libreria
// estatica y lo enlaza en el binario de Rust.
//
// Las claves privadas nunca salen del Secure Enclave: en disco solo guardamos
// su dataRepresentation, un blob cifrado por el propio chip que solo sirve en
// este Mac. Cada uso pide Touch ID (o la contrasena del usuario).
//
// Todas las operaciones de un mismo proceso comparten un LAContext, asi que un
// comando que descifra y firma pide Touch ID una sola vez. Cada invocacion de
// `lock` es un proceso nuevo y vuelve a pedirlo.

import CryptoKit
import Foundation
import LocalAuthentication
import Security

nonisolated(unsafe) private var context = LAContext()

private func setError(_ out: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>, _ message: String) {
    out.pointee = strdup(message)
}

private func copyOut(_ data: Data, _ ptr: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>, _ len: UnsafeMutablePointer<Int>) {
    let buf = malloc(data.count)!.assumingMemoryBound(to: UInt8.self)
    data.copyBytes(to: buf, count: data.count)
    ptr.pointee = buf
    len.pointee = data.count
}

private func accessControl() throws -> SecAccessControl {
    var cfErr: Unmanaged<CFError>?
    guard let access = SecAccessControlCreateWithFlags(
        nil,
        kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        [.privateKeyUsage, .userPresence],
        &cfErr
    ) else {
        throw NSError(domain: "lock", code: 1, userInfo: [
            NSLocalizedDescriptionKey: "access control: \(String(describing: cfErr?.takeRetainedValue()))",
        ])
    }
    return access
}

@_cdecl("lockse_available")
public func lockseAvailable() -> Int32 {
    SecureEnclave.isAvailable ? 1 : 0
}

/// kind 0 = acuerdo de claves (ECDH), 1 = firma (ECDSA).
@_cdecl("lockse_generate")
public func lockseGenerate(
    _ kind: Int32,
    _ outKey: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>,
    _ outKeyLen: UnsafeMutablePointer<Int>,
    _ outPub: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>,
    _ outPubLen: UnsafeMutablePointer<Int>,
    _ outErr: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>
) -> Int32 {
    do {
        let access = try accessControl()
        if kind == 0 {
            let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: access)
            copyOut(key.dataRepresentation, outKey, outKeyLen)
            copyOut(key.publicKey.x963Representation, outPub, outPubLen)
        } else {
            let key = try SecureEnclave.P256.Signing.PrivateKey(accessControl: access)
            copyOut(key.dataRepresentation, outKey, outKeyLen)
            copyOut(key.publicKey.x963Representation, outPub, outPubLen)
        }
        return 0
    } catch {
        setError(outErr, "\(error)")
        return 1
    }
}

@_cdecl("lockse_ecdh")
public func lockseECDH(
    _ key: UnsafePointer<UInt8>, _ keyLen: Int,
    _ peer: UnsafePointer<UInt8>, _ peerLen: Int,
    _ reason: UnsafePointer<CChar>,
    _ out: UnsafeMutablePointer<UInt8>,
    _ outErr: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>
) -> Int32 {
    do {
        context.localizedReason = String(cString: reason)
        let priv = try SecureEnclave.P256.KeyAgreement.PrivateKey(
            dataRepresentation: Data(bytes: key, count: keyLen),
            authenticationContext: context
        )
        let pub = try P256.KeyAgreement.PublicKey(x963Representation: Data(bytes: peer, count: peerLen))
        let secret = try priv.sharedSecretFromKeyAgreement(with: pub)
        secret.withUnsafeBytes { raw in
            _ = memcpy(out, raw.baseAddress!, 32)
        }
        return 0
    } catch {
        setError(outErr, "\(error)")
        return 1
    }
}

/// Firma ECDSA P-256/SHA-256; escribe r||s (64 bytes) en out.
@_cdecl("lockse_sign")
public func lockseSign(
    _ key: UnsafePointer<UInt8>, _ keyLen: Int,
    _ msg: UnsafePointer<UInt8>, _ msgLen: Int,
    _ reason: UnsafePointer<CChar>,
    _ out: UnsafeMutablePointer<UInt8>,
    _ outErr: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>
) -> Int32 {
    do {
        context.localizedReason = String(cString: reason)
        let priv = try SecureEnclave.P256.Signing.PrivateKey(
            dataRepresentation: Data(bytes: key, count: keyLen),
            authenticationContext: context
        )
        let sig = try priv.signature(for: Data(bytes: msg, count: msgLen))
        sig.rawRepresentation.copyBytes(to: out, count: 64)
        return 0
    } catch {
        setError(outErr, "\(error)")
        return 1
    }
}
