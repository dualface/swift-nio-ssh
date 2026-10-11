//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftNIO open source project
//
// Copyright (c) 2026 Apple Inc. and the SwiftNIO project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftNIO project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import NIOCore
import _CryptoExtras

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

extension NIOSSHPrivateKey {
    /// The RFC 8332 signature algorithms that an RSA key can use for user authentication.
    ///
    /// RSA keys always use the `ssh-rsa` public key format, but the signature algorithm is negotiated separately.
    /// Only the SHA-2 variants are offered: the SHA-1 based `ssh-rsa` signature algorithm is deliberately not
    /// representable, so NIOSSH never produces or accepts SHA-1 RSA signatures.
    public struct RSASignatureAlgorithm: Hashable, Sendable, CustomStringConvertible {
        internal enum Base: Hashable, Sendable {
            case sha256
            case sha512
        }

        internal var base: Base

        private init(_ base: Base) {
            self.base = base
        }

        /// `rsa-sha2-256`: RSASSA-PKCS1-v1_5 with SHA-256.
        public static let sha256 = RSASignatureAlgorithm(.sha256)

        /// `rsa-sha2-512`: RSASSA-PKCS1-v1_5 with SHA-512.
        public static let sha512 = RSASignatureAlgorithm(.sha512)

        internal static let sha256WireName = "rsa-sha2-256".utf8
        internal static let sha512WireName = "rsa-sha2-512".utf8

        /// The algorithm name used on the wire, both in the user auth request and in the signature blob.
        internal var wireName: String.UTF8View {
            switch self.base {
            case .sha256:
                return Self.sha256WireName
            case .sha512:
                return Self.sha512WireName
            }
        }

        internal init?<Bytes: Collection>(wireName: Bytes) where Bytes.Element == UInt8 {
            if wireName.elementsEqual(Self.sha256WireName) {
                self = .sha256
            } else if wireName.elementsEqual(Self.sha512WireName) {
                self = .sha512
            } else {
                return nil
            }
        }

        public var description: String {
            String(self.wireName)
        }
    }
}

/// Bounds applied to every RSA key NIOSSH accepts.
///
/// The bounds keep the cost of parsing and verifying attacker-supplied keys predictable. The modulus range covers
/// every key size OpenSSH generates by default and the common larger sizes; the exponent bound matches what
/// BoringSSL accepts for verification.
internal enum RSAKeyLimits {
    static let minimumModulusBits = 2048
    static let maximumModulusBits = 8192
    static let maximumModulusBytes = maximumModulusBits / 8
    static let maximumPublicExponentBytes = 4

    static func validateModulusBits(_ bits: Int) throws {
        guard bits >= Self.minimumModulusBits, bits <= Self.maximumModulusBits else {
            throw NIOSSHError.invalidKeySize
        }
    }

    /// Validates big-endian integer bytes without leading zeros, as produced by `_RSA` primitives and by
    /// ``ByteBuffer/readRSAPositiveMPInt(maximumBytes:)``.
    static func validate(
        modulus: some BidirectionalCollection<UInt8>,
        publicExponent: some BidirectionalCollection<UInt8>
    ) throws {
        guard let lastModulusByte = modulus.last, lastModulusByte & 1 == 1 else {
            throw NIOSSHError.invalidSSHMessage(reason: "RSA modulus must be odd")
        }
        guard let firstModulusByte = modulus.first else {
            throw NIOSSHError.invalidSSHMessage(reason: "RSA modulus is empty")
        }
        let modulusBits = (modulus.count - 1) * 8 + (8 - firstModulusByte.leadingZeroBitCount)
        try Self.validateModulusBits(modulusBits)

        guard publicExponent.count <= Self.maximumPublicExponentBytes,
            let lastExponentByte = publicExponent.last, lastExponentByte & 1 == 1
        else {
            throw NIOSSHError.invalidSSHMessage(reason: "RSA public exponent out of range")
        }
        guard publicExponent.count > 1 || lastExponentByte >= 3 else {
            throw NIOSSHError.invalidSSHMessage(reason: "RSA public exponent out of range")
        }
    }

    static func validate(_ key: _RSA.Signing.PublicKey) throws {
        let primitives = try key.getKeyPrimitives()
        try Self.validate(
            modulus: primitives.modulus.drop(while: { $0 == 0 }),
            publicExponent: primitives.publicExponent.drop(while: { $0 == 0 })
        )
    }
}

extension ByteBuffer {
    /// Reads a strictly encoded, positive SSH `mpint` and returns its magnitude without the sign byte.
    ///
    /// RFC 4251 § 5 requires the shortest two's complement encoding. Negative values, zero, non-minimal leading
    /// zero bytes and magnitudes longer than `maximumBytes` are rejected. Returns `nil` when the buffer is short.
    mutating func readRSAPositiveMPInt(maximumBytes: Int) throws -> ByteBufferView? {
        guard let encoded = self.readSSHString() else {
            return nil
        }

        var magnitude = encoded.readableBytesView
        guard let first = magnitude.first else {
            throw NIOSSHError.invalidSSHMessage(reason: "RSA integer must be positive")
        }
        if first == 0 {
            magnitude = magnitude.dropFirst()
            guard let next = magnitude.first, next & 0x80 == 0x80 else {
                throw NIOSSHError.invalidSSHMessage(reason: "RSA integer is not minimally encoded")
            }
        } else if first & 0x80 == 0x80 {
            throw NIOSSHError.invalidSSHMessage(reason: "RSA integer must be positive")
        }

        guard magnitude.count <= maximumBytes else {
            throw NIOSSHError.invalidSSHMessage(reason: "RSA integer too large")
        }
        return magnitude
    }
}
