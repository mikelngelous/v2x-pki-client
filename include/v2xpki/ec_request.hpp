#pragma once

// EC (Enrolment Credential) request.
// Per TS 102 941 §6.2.3.2 (InnerEcRequest).

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
struct EcRecord {
    StaticBytes<kP384PublicKeyLen> canonical_public_key; // uncompressed (65B P-256, 97B P-384)
    std::array<uint8_t, 8> ea_hashed_id_8; // target EA
    std::vector<int64_t> requested_psids; // requested appPermissions
    int64_t validity_period_days = 30;
    Curve curve = Curve::NistP256;
    std::string its_id = "v2xpki-its-s"; // ITS-S canonical identifier (1-64 bytes)
};

// --- Validator ---
bool validate_ec_record(const EcRecord& rec, std::string* err = nullptr);

// --- Assembler ---
// Intermediate representation post-assembly, pre-encode
struct EcRequestDescription {
    std::string its_id; // ITS-S identifier
    StaticBytes<kP384PublicKeyLen> verification_key; // uncompressed (65B or 97B)
    std::vector<int64_t> psids;
    uint32_t validity_start; // TAI epoch seconds
    uint16_t validity_duration_hours;
    std::array<uint8_t, 8> ea_hid8;
    Curve curve = Curve::NistP256;
};

EcRequestDescription assemble_ec_request(const EcRecord& rec,
                                         std::chrono::system_clock::time_point now);

// --- Encoder ---
struct EcRequestResult {
    StaticBytes<kMaxCoerMessageLen> encoded; // COER bytes for POST
    StaticBytes<kAesKeyLen> request_aes_key; // symmetric key for response decryption (PSK)
};

// Returns encoded request + AES key needed for response decryption
Result<EcRequestResult> encode_ec_request(const EcRequestDescription& desc, const CertInfo& ea_cert,
                                          const std::vector<uint8_t>& canonical_private_key);

// --- Response decoder ---
struct EcResponse {
    EnrolmentResponseCode response_code;
    StaticBytes<16> request_hash; // InnerEcResponse.requestHash OCTET STRING(SIZE(16))
    std::optional<CertInfo> certificate;
};

// Decode EC response. request_aes_key is the 16B key from encode_ec_request
// (used for PSK-based response decryption per TS 102 941 §6.2.3.2.2).
// request_bytes are the exact encoded request bytes POSTed; requestHash is checked against them.
Result<EcResponse> decode_ec_response(const std::vector<uint8_t>& response_bytes,
                                      const std::vector<uint8_t>& recipient_private_key,
                                      const std::vector<uint8_t>& request_aes_key,
                                      const std::vector<uint8_t>& request_bytes,
                                      const CertInfo& signer_cert);

} // namespace v2xpki
