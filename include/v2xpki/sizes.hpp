#pragma once

// Compile-time constants, strong types, and curve descriptors.

#include <cstddef>
#include <cstdint>

namespace v2xpki {

// --- Cryptographic sizes (P-256 / SHA-256 / AES-128-CCM) ---

inline constexpr std::size_t kHashedId8Len = 8;
inline constexpr std::size_t kP256ScalarLen = 32; // private key / sig component / coordinate
inline constexpr std::size_t kP256PublicKeyLen = 65; // 0x04 || X || Y
inline constexpr std::size_t kP256CompressedLen = 33; // 0x02|0x03 || X
inline constexpr std::size_t kSha256Len = 32;
inline constexpr std::size_t kAesKeyLen = 16;
inline constexpr std::size_t kAesCcmNonceLen = 12;
inline constexpr std::size_t kAesCcmTagLen = 16;

// --- P-384 sizes ---
inline constexpr std::size_t kP384ScalarLen = 48;
inline constexpr std::size_t kP384PublicKeyLen = 97; // 0x04 || X(48) || Y(48)
inline constexpr std::size_t kP384CompressedLen = 49; // 0x02|0x03 || X(48)
inline constexpr std::size_t kSha384Len = 48;

// --- Curve identifier (static dispatch, no virtual) ---
enum class Curve : uint8_t {
    NistP256,
    BrainpoolP256r1,
    NistP384,
    BrainpoolP384r1,
};

constexpr const char* to_string(Curve c) noexcept {
    switch (c) {
        case Curve::NistP256: return "nist-p256";
        case Curve::BrainpoolP256r1: return "brainpool-p256r1";
        case Curve::NistP384: return "nist-p384";
        case Curve::BrainpoolP384r1: return "brainpool-p384r1";
    }
    return "unknown";
}

constexpr std::size_t scalar_len(Curve c) noexcept {
    switch (c) {
        case Curve::NistP256: return kP256ScalarLen;
        case Curve::BrainpoolP256r1: return kP256ScalarLen;
        case Curve::NistP384: return kP384ScalarLen;
        case Curve::BrainpoolP384r1: return kP384ScalarLen;
    }
    return kP256ScalarLen;
}

constexpr std::size_t pubkey_len(Curve c) noexcept {
    switch (c) {
        case Curve::NistP256: return kP256PublicKeyLen;
        case Curve::BrainpoolP256r1: return kP256PublicKeyLen;
        case Curve::NistP384: return kP384PublicKeyLen;
        case Curve::BrainpoolP384r1: return kP384PublicKeyLen;
    }
    return kP256PublicKeyLen;
}

constexpr std::size_t compressed_len(Curve c) noexcept {
    switch (c) {
        case Curve::NistP256: return kP256CompressedLen;
        case Curve::BrainpoolP256r1: return kP256CompressedLen;
        case Curve::NistP384: return kP384CompressedLen;
        case Curve::BrainpoolP384r1: return kP384CompressedLen;
    }
    return kP256CompressedLen;
}

constexpr std::size_t hash_len(Curve c) noexcept {
    switch (c) {
        case Curve::NistP256: return kSha256Len;
        case Curve::BrainpoolP256r1: return kSha256Len;
        case Curve::NistP384: return kSha384Len;
        case Curve::BrainpoolP384r1: return kSha384Len;
    }
    return kSha256Len;
}

constexpr bool is_p256_size(Curve c) noexcept {
    return c == Curve::NistP256 || c == Curve::BrainpoolP256r1;
}

// --- Protocol constants ---

// TAI epoch: 2004-01-01T00:00:00Z (IEEE 1609.2 / ETSI TS 103 097)
inline constexpr std::int64_t kTaiEpochUnix = 1072915200;

// TS 102 941 v2 PSID for Secured Certificate Request (SCR) = 623 (0x26F)
inline constexpr std::int64_t kPsidScr = 623;

// IEEE 1609.2 protocol version
inline constexpr long kIeee1609Dot2Version = 3;

// --- Response codes (TS 102 941 §6.2.3) — two distinct enums per the schema ---

// EtsiTs102941TypesEnrolment.EnrolmentResponseCode (0..13)
enum class EnrolmentResponseCode : int {
    Ok = 0,
    CantParse,
    BadContentType,
    ImNotTheRecipient,
    UnknownEncryptionAlgorithm,
    DecryptionFailed,
    UnknownIts,
    InvalidSignature,
    InvalidEncryptionKey,
    BadItsStatus,
    IncompleteRequest,
    DeniedPermissions,
    InvalidKeys,
    DeniedRequest,
};

constexpr const char* to_string(EnrolmentResponseCode c) noexcept {
    switch (c) {
        case EnrolmentResponseCode::Ok: return "ok";
        case EnrolmentResponseCode::CantParse: return "cantparse";
        case EnrolmentResponseCode::BadContentType: return "badcontenttype";
        case EnrolmentResponseCode::ImNotTheRecipient: return "imnottherecipient";
        case EnrolmentResponseCode::UnknownEncryptionAlgorithm: return "unknownencryptionalgorithm";
        case EnrolmentResponseCode::DecryptionFailed: return "decryptionfailed";
        case EnrolmentResponseCode::UnknownIts: return "unknownits";
        case EnrolmentResponseCode::InvalidSignature: return "invalidsignature";
        case EnrolmentResponseCode::InvalidEncryptionKey: return "invalidencryptionkey";
        case EnrolmentResponseCode::BadItsStatus: return "baditsstatus";
        case EnrolmentResponseCode::IncompleteRequest: return "incompleterequest";
        case EnrolmentResponseCode::DeniedPermissions: return "deniedpermissions";
        case EnrolmentResponseCode::InvalidKeys: return "invalidkeys";
        case EnrolmentResponseCode::DeniedRequest: return "deniedrequest";
    }
    return "unknown";
}

// EtsiTs102941TypesAuthorization.AuthorizationResponseCode (0..19)
enum class AuthorizationResponseCode : int {
    Ok = 0,
    ItsAaCantParse,
    ItsAaBadContentType,
    ItsAaImNotTheRecipient,
    ItsAaUnknownEncryptionAlgorithm,
    ItsAaDecryptionFailed,
    ItsAaKeysDontMatch,
    ItsAaIncompleteRequest,
    ItsAaInvalidEncryptionKey,
    ItsAaOutOfSyncRequest,
    ItsAaUnknownEa,
    ItsAaInvalidEa,
    ItsAaDeniedPermissions,
    AaEaCantReachEa,
    EaAaCantParse,
    EaAaBadContentType,
    EaAaImNotTheRecipient,
    EaAaUnknownEncryptionAlgorithm,
    EaAaDecryptionFailed,
    InvalidAa,
};

constexpr const char* to_string(AuthorizationResponseCode c) noexcept {
    switch (c) {
        case AuthorizationResponseCode::Ok: return "ok";
        case AuthorizationResponseCode::ItsAaCantParse: return "its-aa-cantparse";
        case AuthorizationResponseCode::ItsAaBadContentType: return "its-aa-badcontenttype";
        case AuthorizationResponseCode::ItsAaImNotTheRecipient: return "its-aa-imnottherecipient";
        case AuthorizationResponseCode::ItsAaUnknownEncryptionAlgorithm:
            return "its-aa-unknownencryptionalgorithm";
        case AuthorizationResponseCode::ItsAaDecryptionFailed: return "its-aa-decryptionfailed";
        case AuthorizationResponseCode::ItsAaKeysDontMatch: return "its-aa-keysdontmatch";
        case AuthorizationResponseCode::ItsAaIncompleteRequest: return "its-aa-incompleterequest";
        case AuthorizationResponseCode::ItsAaInvalidEncryptionKey:
            return "its-aa-invalidencryptionkey";
        case AuthorizationResponseCode::ItsAaOutOfSyncRequest: return "its-aa-outofsyncrequest";
        case AuthorizationResponseCode::ItsAaUnknownEa: return "its-aa-unknownea";
        case AuthorizationResponseCode::ItsAaInvalidEa: return "its-aa-invalidea";
        case AuthorizationResponseCode::ItsAaDeniedPermissions: return "its-aa-deniedpermissions";
        case AuthorizationResponseCode::AaEaCantReachEa: return "aa-ea-cantreachea";
        case AuthorizationResponseCode::EaAaCantParse: return "ea-aa-cantparse";
        case AuthorizationResponseCode::EaAaBadContentType: return "ea-aa-badcontenttype";
        case AuthorizationResponseCode::EaAaImNotTheRecipient: return "ea-aa-imnottherecipient";
        case AuthorizationResponseCode::EaAaUnknownEncryptionAlgorithm:
            return "ea-aa-unknownencryptionalgorithm";
        case AuthorizationResponseCode::EaAaDecryptionFailed: return "ea-aa-decryptionfailed";
        case AuthorizationResponseCode::InvalidAa: return "invalidaa";
    }
    return "unknown";
}

// Compile-time proof
static_assert(kP256PublicKeyLen == 65);
static_assert(kP256ScalarLen + kP256ScalarLen + 1 == kP256PublicKeyLen);
static_assert(kP384PublicKeyLen == 97);
static_assert(kP384ScalarLen + kP384ScalarLen + 1 == kP384PublicKeyLen);
static_assert(kTaiEpochUnix == 1072915200);

} // namespace v2xpki
