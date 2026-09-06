#pragma once

// AT (Authorization Ticket) request.
// Per TS 102 941 §6.2.3.3 (InnerAtRequest).

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "v2xpki/key_store.hpp"
#include "v2xpki/result.hpp"
#include "v2xpki/sizes.hpp"
#include "v2xpki/static_bytes.hpp"
#include "v2xpki/trust_chain.hpp"

namespace v2xpki {

// --- Record ---
struct AtRecord {
    StaticBytes<kP384PublicKeyLen> at_public_key; // uncompressed (65B P-256, 97B P-384)
    std::array<uint8_t, 8> aa_hashed_id_8; // target AA
    std::array<uint8_t, 8> ea_hashed_id_8; // EA that issued EC
    std::vector<int64_t> requested_psids; // requested appPermissions
    int64_t validity_period_hours = 24;
    Curve curve = Curve::NistP256;
};

// --- Validator ---
bool validate_at_record(const AtRecord& rec, std::string* err = nullptr);

// --- Assembler ---
struct AtRequestDescription {
    StaticBytes<kP384PublicKeyLen> verification_key; // AT verification key (65B or 97B)
    std::vector<int64_t> psids;
    uint32_t validity_start;
    uint16_t validity_duration_hours;
    std::array<uint8_t, 8> aa_hid8;
    std::array<uint8_t, 8> ea_hid8;
    StaticBytes<32> hmac_key; // random, InnerAtRequest.hmacKey SIZE(32)
    StaticBytes<16> key_tag; // HMAC-SHA256 tag over shared request, SharedAtRequest.keyTag
    Curve curve = Curve::NistP256;
};

AtRequestDescription assemble_at_request(const AtRecord& rec,
                                         std::chrono::system_clock::time_point now);

// --- Encoder ---
struct AtRequestResult {
    StaticBytes<kMaxCoerMessageLen> encoded; // COER bytes for POST
    StaticBytes<kAesKeyLen> request_aes_key; // symmetric key for response decryption (PSK)
};

// Returns encoded request + AES key needed for response decryption.
// at_private_key: private key for the NEW AT verification key (signs outer PoP).
// ec_private_key: private key for the EC (signs ecSignature).
Result<AtRequestResult> encode_at_request(const AtRequestDescription& desc, const CertInfo& aa_cert,
                                          const CertInfo& ea_cert, const CertInfo& ec_cert,
                                          const std::vector<uint8_t>& ec_private_key,
                                          const std::vector<uint8_t>& at_private_key);

// --- Response decoder ---
struct AtResponse {
    AuthorizationResponseCode response_code;
    StaticBytes<16> request_hash; // InnerAtResponse.requestHash OCTET STRING(SIZE(16))
    std::optional<CertInfo> certificate;
};

// Decode AT response. request_aes_key is the 16B key from encode_at_request
// (used for PSK-based response decryption per TS 102 941 §6.2.3.2.2).
// request_bytes are the exact encoded request bytes POSTed; requestHash is checked against them.
Result<AtResponse> decode_at_response(const std::vector<uint8_t>& response_bytes,
                                      const std::vector<uint8_t>& recipient_private_key,
                                      const std::vector<uint8_t>& request_aes_key,
                                      const std::vector<uint8_t>& request_bytes,
                                      const CertInfo& signer_cert);

} // namespace v2xpki
