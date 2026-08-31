#pragma once

// CRL decoding and the revocation set. TS 102 941 §6.1.4 NOTE 4: ATs are not revoked.

#include <array>
#include <cstdint>
#include <map>
#include <set>
#include <vector>

#include "v2xpki/result.hpp"
#include "v2xpki/sizes.hpp"
#include "v2xpki/trust_chain.hpp" // current_tai_seconds

namespace v2xpki {

struct CrlContents {
    std::array<uint8_t, 8> issuer_hid8{}; // taken from the signer of the outer message
    uint32_t this_update = 0; // Time32, seconds since the TAI epoch
    uint32_t next_update = 0;
    std::vector<std::array<uint8_t, 8>> revoked;
};

// The issuer is the signer of the outer envelope, not a field of ToBeSignedCrl.
Result<CrlContents> decode_crl(const std::vector<uint8_t>& coer,
                               const std::vector<uint8_t>& rca_pubkey,
                               const std::vector<uint8_t>& rca_cert_coer);

// Revocation state, keyed by issuer: a CRL only speaks for the CA that signed it.
class RevocationStore {
public:
    // Rejects a CRL past next_update: a stale list would mask revocations published since.
    // KNOWN NON-CONFORMANCE: a newer CRL replaces the issuer's whole set, so a shortened one
    // reinstates certs. §6.3.3 NOTE 2: "revoked permanently and cannot be reinstated".
    // TODO: make the store union-only (open: whether to prune expired entries).
    bool apply(const CrlContents& crl, int64_t now_tai = current_tai_seconds());

    bool is_revoked(const std::array<uint8_t, 8>& issuer_hid8,
                    const std::array<uint8_t, 8>& cert_hid8) const;

    size_t issuer_count() const { return revoked_.size(); }

private:
    std::map<std::array<uint8_t, 8>, std::set<std::array<uint8_t, 8>>> revoked_;
};

} // namespace v2xpki
