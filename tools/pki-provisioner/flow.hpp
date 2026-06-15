// Provisioning flow: CCMS trust discovery, EC enrolment, AT rotation.

#pragma once

#include "v2xpki/http_client.hpp"
#include "v2xpki/key_store.hpp"
#include "v2xpki/trust_chain.hpp"

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace provisioning {

struct TrustAnchors {
    v2xpki::CertInfo ea;
    v2xpki::CertInfo aa;
    v2xpki::CertInfo rca;
    std::string ec_url; // EA itsAccessPoint
    std::string at_url; // AA accessPoint
};

// CCMS discovery (TS 102 941 Annex D + CPOC v3.2): TLM -> ECTL -> CTL, signatures verified.
// Empty tlm_hid8 bootstraps the TLM via the /tlm shortcut (testbed convenience).
// work_dir backs the underlying PkiClient keystore (unused by discovery, must exist).
std::optional<TrustAnchors> discover(const std::string& base_url, const std::string& tlm_hid8,
                                     const std::string& work_dir);

bool write_anchors(const TrustAnchors& ta, const std::string& output_dir);

struct EnrolledEc {
    v2xpki::CertInfo cert;
    v2xpki::KeyPair canonical_kp;
};

std::optional<EnrolledEc> enrol_ec(v2xpki::HttpClient& http, const TrustAnchors& ta,
                                   const std::vector<int64_t>& psids, int64_t validity_days);

std::optional<std::array<uint8_t, 8>> rotate_at(v2xpki::HttpClient& http, const TrustAnchors& ta,
                                                const EnrolledEc& ec,
                                                const std::vector<int64_t>& psids,
                                                int64_t validity_hours,
                                                const std::string& output_dir);

} // namespace provisioning
