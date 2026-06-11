// CertificateBase → CertInfo parser (one implementation, two entry points).
#pragma once

#include "v2xpki/trust_chain.hpp"

#include <array>
#include <cstdint>
#include <vector>

struct CertificateBase;

namespace v2xpki::cert {

// HashedId8 = rightmost 8 bytes of SHA-256(cert_COER).
std::array<uint8_t, 8> compute_hid8(const std::vector<uint8_t>& cert_coer);

// Decode COER cert bytes → CertInfo (public key, encryption key, TBS, sig, etc.)
CertInfo from_coer(const std::vector<uint8_t>& cert_coer);

// Build CertInfo from a decoded CertificateBase* and its original COER bytes.
CertInfo from_struct(const struct CertificateBase* cert, const std::vector<uint8_t>& cert_coer);

} // namespace v2xpki::cert
