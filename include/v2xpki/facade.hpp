#pragma once

#include <array>
#include <chrono>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "v2xpki/at_request.hpp"
#include "v2xpki/ec_request.hpp"
#include "v2xpki/http_client.hpp"
#include "v2xpki/key_store.hpp"
#include "v2xpki/result.hpp"
#include "v2xpki/trust_chain.hpp"
#include "v2xpki/trust_list.hpp"

namespace v2xpki {

struct PkiClientConfig {
    std::string ea_url;
    std::string aa_url;
    std::string tlm_url;
    std::string ma_url;              // TODO: misbehaviour reporting (TS 103 759)
    std::string ca_bundle_path;
    std::string trust_dir;
    std::string keystore_dir;
    std::string tlm_hid8;            // pinned TLM HashedId8 (uppercase hex)
    std::chrono::seconds timeout{30};
    bool verify_tls = true;
};

class PkiClient {
public:
    explicit PkiClient(const PkiClientConfig& cfg);
    ~PkiClient();

    PkiClient(const PkiClient&) = delete;
    PkiClient& operator=(const PkiClient&) = delete;

    // --- PKI operations ---

    // Request Enrolment Credential (EC) from EA
    Result<CertInfo> request_enrolment_credential(
        const KeyHandle& canonical,
        const EcRecord& rec);

    // Request Authorization Ticket (AT) from AA.
    // ec_cert must be the real EC cert (with cert_bytes and hashed_id_8).
    Result<CertInfo> request_authorization_ticket(
        const KeyHandle& ec_handle,
        const CertInfo& ec_cert,
        const AtRecord& rec);

    // --- Discovery ---

    // GET /trustanchor → RCA cert COER
    Result<CertInfo> fetch_trust_anchor();

    // GET /cert/{name} → cert COER
    Result<CertInfo> fetch_cert_by_name(const std::string& name);

    // GET /lookup/{hid8} → cert COER
    Result<CertInfo> fetch_cert_by_hashed_id_8(
        const std::array<uint8_t, 8>& hid8);

    // --- CCMS trust discovery (TS 102 941 Annex D + CPOC v3.2) ---

    // Bootstrap trust: TLM -> ECTL -> CTL -> EA/AA URLs.
    // Updates internal ea_url/aa_url from discovered entries.
    Result<TrustTopology> discover_trust();

    // --- Legacy trust list (kept for backward compat) ---

    Result<std::vector<CertInfo>> fetch_ectl();
    Result<std::vector<CertInfo>> fetch_crl(
        const std::array<uint8_t, 8>& rca_hid8);

    // --- Accessors ---
    const TrustChain& trust_chain() const;
    KeyStore& key_store();

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace v2xpki
