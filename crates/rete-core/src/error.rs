//! Error types for rete-core.

/// All errors that can occur in packet parsing or crypto operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Packet is shorter than the minimum valid length.
    PacketTooShort,
    /// Packet exceeds the MTU (500 bytes).
    PacketTooLong,
    /// Caller-supplied output buffer is too small.
    BufferTooSmall,
    /// Payload exceeds the MDU for this packet/destination type.
    PayloadTooLarge,
    /// Flags byte contains an unrecognised packet type value.
    UnknownPacketType(u8),
    /// Flags byte contains an unrecognised destination type value.
    UnknownDestType(u8),
    /// A cryptographic operation failed.
    CryptoError,
    /// Private key material is invalid or the wrong length.
    InvalidKey,
    /// Ed25519 signature verification failed.
    InvalidSignature,
    /// PKCS#7 padding on decrypted plaintext is malformed.
    InvalidPadding,
    /// A required field was not provided to the packet builder.
    MissingField(&'static str),
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::PacketTooShort          => write!(f, "packet too short"),
            Error::PacketTooLong           => write!(f, "packet exceeds MTU of 500 bytes"),
            Error::BufferTooSmall          => write!(f, "output buffer too small"),
            Error::PayloadTooLarge         => write!(f, "payload exceeds MDU"),
            Error::UnknownPacketType(v)    => write!(f, "unknown packet type: {v:#04x}"),
            Error::UnknownDestType(v)      => write!(f, "unknown destination type: {v:#04x}"),
            Error::CryptoError             => write!(f, "cryptographic operation failed"),
            Error::InvalidKey              => write!(f, "invalid key material"),
            Error::InvalidSignature        => write!(f, "Ed25519 signature verification failed"),
            Error::InvalidPadding          => write!(f, "invalid PKCS#7 padding"),
            Error::MissingField(field)     => write!(f, "missing required field: {field}"),
        }
    }
}
