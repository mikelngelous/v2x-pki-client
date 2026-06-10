#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "v2xpki/result.hpp"
#include "v2xpki/trust_chain.hpp"

namespace v2xpki {

struct EaInfo {
    CertInfo cert;
    std::string aa_access_point;
    std::string its_access_point;
};

struct AaInfo {
    CertInfo cert;
    std::string access_point;
};

struct DcInfo {
    std::string url;
    std::vector<std::array<uint8_t, 8>> serves;
};

struct TrustTopology {
    std::optional<CertInfo> tlm;
    std::vector<CertInfo> rcas;
    std::vector<EaInfo> eas;
    std::vector<AaInfo> aas;
    std::vector<DcInfo> dcs;
    bool ectl_signature_verified = false;
    bool ctl_signature_verified = false;
};

// Verifies the TLM signature when tlm_pubkey/tlm_cert_coer are given.
Result<TrustTopology> decode_ectl(
    const std::vector<uint8_t>& coer,
    const std::vector<uint8_t>& tlm_pubkey = {},
    const std::vector<uint8_t>& tlm_cert_coer = {});

// Verifies the RCA signature when rca_pubkey/rca_cert_coer are given.
Result<TrustTopology> decode_rca_ctl(
    const std::vector<uint8_t>& coer,
    const std::vector<uint8_t>& rca_pubkey = {},
    const std::vector<uint8_t>& rca_cert_coer = {});

std::string hid8_hex_upper(const std::array<uint8_t, 8>& hid8);

// 16 hex chars, case-insensitive.
std::optional<std::array<uint8_t, 8>> parse_hid8_hex(const std::string& hex);

}  // namespace v2xpki
