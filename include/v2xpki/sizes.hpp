#pragma once

// Compile-time constants and strong types.

#include <cstddef>
#include <cstdint>

namespace v2xpki {

// --- Cryptographic sizes (P-256 / SHA-256 / AES-128-CCM) ---

inline constexpr std::size_t kHashedId8Len      = 8;
inline constexpr std::size_t kP256ScalarLen     = 32;   // private key / sig component / coordinate
inline constexpr std::size_t kP256PublicKeyLen  = 65;   // 0x04 || X || Y
inline constexpr std::size_t kP256CompressedLen = 33;   // 0x02|0x03 || X
inline constexpr std::size_t kSha256Len         = 32;
inline constexpr std::size_t kAesKeyLen         = 16;
inline constexpr std::size_t kAesCcmNonceLen    = 12;
inline constexpr std::size_t kAesCcmTagLen      = 16;

// --- Protocol constants ---

// TAI epoch: 2004-01-01T00:00:00Z (IEEE 1609.2 / ETSI TS 103 097)
inline constexpr std::int64_t kTaiEpochUnix     = 1072915200;

// TS 102 941 v2 PSID for Secured Certificate Request (SCR) = 623 (0x26F)
inline constexpr std::int64_t kPsidScr          = 623;

// IEEE 1609.2 protocol version
inline constexpr long kIeee1609Dot2Version      = 3;

// --- ResponseCode (TS 102 941 §6.2.3) ---
// Shared by EnrolmentResponseCode and AuthorizationResponseCode (0..8).

enum class ResponseCode : int {
    Ok                   = 0,
    CantParse            = 1,
    BadContentType       = 2,
    ImNotTheRecipient    = 3,
    UnknownIts           = 4,
    BadItsStatus         = 5,
    IncompleteRequest    = 6,
    DeniedPermissions    = 7,
    InvalidEncryptionKey = 8,
};

inline constexpr const char* to_string(ResponseCode c) noexcept {
    switch (c) {
        case ResponseCode::Ok:                   return "ok";
        case ResponseCode::CantParse:            return "cantparse";
        case ResponseCode::BadContentType:       return "badcontenttype";
        case ResponseCode::ImNotTheRecipient:    return "imnottherecipient";
        case ResponseCode::UnknownIts:           return "unknownits";
        case ResponseCode::BadItsStatus:         return "baditsstatus";
        case ResponseCode::IncompleteRequest:    return "incompleterequest";
        case ResponseCode::DeniedPermissions:    return "deniedpermissions";
        case ResponseCode::InvalidEncryptionKey: return "invalidencryptionkey";
    }
    return "unknown";
}

// Compile-time proof
static_assert(kP256PublicKeyLen == 65);
static_assert(kP256ScalarLen + kP256ScalarLen + 1 == kP256PublicKeyLen);
static_assert(kTaiEpochUnix == 1072915200);

}  // namespace v2xpki
