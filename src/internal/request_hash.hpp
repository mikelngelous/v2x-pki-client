// requestHash correlation check shared by the EC and AT response decoders.
#pragma once

#include "v2xpki/crypto_ec.hpp"
#include "v2xpki/static_bytes.hpp"

#include <algorithm>
#include <cstdint>
#include <vector>

namespace v2xpki {

// TS 102 941: requestHash is the leftmost 16 octets of SHA-256 over the request exactly as sent
// (the outer encrypted message), for both EC and AT.
inline bool request_hash_matches(const std::vector<uint8_t>& request_bytes,
                                 const StaticBytes<16>& response_hash) {
    if (request_bytes.empty() || response_hash.size() != 16) return false;
    auto digest = crypto::hash_sha256(request_bytes);
    if (digest.size() < 16) return false;
    return std::equal(response_hash.begin(), response_hash.end(), digest.begin());
}

} // namespace v2xpki
