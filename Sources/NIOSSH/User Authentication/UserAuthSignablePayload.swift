//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftNIO open source project
//
// Copyright (c) 2020 Apple Inc. and the SwiftNIO project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftNIO project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import NIOCore

/// A `UserAuthSignablePayload` represents the data that needs to be signed as part
/// of key-based user authentication.
///
/// The data is:
///
///     string    session identifier
///     byte      SSH_MSG_USERAUTH_REQUEST
///     string    user name
///     string    service name
///     string    "publickey"
///     boolean   TRUE
///     string    public key algorithm name
///     string    public key to be used for authentication
///
/// This object produces that data and can then be signed or verified.
internal struct UserAuthSignablePayload {
    private(set) var bytes: ByteBuffer

    /// The RFC 8332 algorithm named in the payload. Set exactly when the key is an RSA key.
    let rsaSignatureAlgorithm: NIOSSHPrivateKey.RSASignatureAlgorithm?

    init(
        sessionIdentifier: ByteBuffer,
        userName: String,
        serviceName: String,
        publicKey: NIOSSHPublicKey,
        rsaSignatureAlgorithm: NIOSSHPrivateKey.RSASignatureAlgorithm? = nil
    ) {
        // For RSA keys the algorithm name differs from the key format name, and the bare key format name would
        // mean SHA-1. Requiring the algorithm keeps that name out of every signed payload.
        let isRSAKey: Bool
        if case .rsa = publicKey.backingKey {
            isRSAKey = true
        } else {
            isRSAKey = false
        }
        precondition(isRSAKey == (rsaSignatureAlgorithm != nil), "RSA payloads need exactly one RSA algorithm")
        self.rsaSignatureAlgorithm = rsaSignatureAlgorithm

        // We use the session identifier as the base buffer and just append to it. We ask for 1kB because it's likely
        // enough for this data.
        var sessionIdentifier = sessionIdentifier
        var newBuffer = sessionIdentifier
        newBuffer.clear(minimumCapacity: 1024)

        newBuffer.writeSSHString(&sessionIdentifier)
        newBuffer.writeInteger(SSHMessage.UserAuthRequestMessage.id)
        newBuffer.writeSSHString(userName.utf8)
        newBuffer.writeSSHString(serviceName.utf8)
        newBuffer.writeSSHString("publickey".utf8)
        newBuffer.writeSSHBoolean(true)
        newBuffer.writeSSHString(rsaSignatureAlgorithm?.wireName ?? publicKey.keyPrefix)
        newBuffer.writeCompositeSSHString { buffer in
            buffer.writeSSHHostKey(publicKey)
        }

        self.bytes = newBuffer
    }
}
