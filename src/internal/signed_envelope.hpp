// IEEE 1609.2 SignedData envelope builders (multi-curve).
// Internal toolkit — not installed, not part of the public API.

#pragma once

#include "v2xpki/trust_chain.hpp"
#include "v2xpki/sizes.hpp"

#include <cstdint>
#include <vector>

namespace v2xpki::sign {

// Build self-signed Ieee1609Dot2Data{signedData} wrapping unsecuredData payload.
// signer=self, IEEE 1609.2 §5.3.1 double hash with empty signer_identifier_input.
// Returns COER-encoded Ieee1609Dot2Data, or empty on failure.
std::vector<uint8_t> build_self_signed(const std::vector<uint8_t>& payload_bytes,
                                       const std::vector<uint8_t>& private_key,
                                       Curve curve = Curve::NistP256);

// Build Ieee1609Dot2Data{signedData} with extDataHash (SignedExternalPayload).
// signer=digest(ec_cert HID8), IEEE 1609.2 §5.3.1 double hash.
// signer_identifier_input = COER(certificate) per §5.3.1.
// Returns COER-encoded Ieee1609Dot2Data, or empty on failure.
std::vector<uint8_t> build_external_payload(const std::vector<uint8_t>& ext_data_hash,
                                            const CertInfo& ec_cert,
                                            const std::vector<uint8_t>& ec_private_key,
                                            Curve curve = Curve::NistP256);

} // namespace v2xpki::sign
