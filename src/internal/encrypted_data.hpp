// EncryptedData builder + response decrypt/unwrap.

#pragma once

#include "v2xpki/crypto_ec.hpp"
#include "v2xpki/result.hpp"
#include "v2xpki/trust_chain.hpp"

#include <cstdint>
#include <vector>

struct Ieee1609Dot2Data;

namespace v2xpki::enc {

// Build Ieee1609Dot2Data{encryptedData} from ECIES result.
// Picks EncryptedDataEncryptionKey variant based on recipient cert curve.
Ieee1609Dot2Data* build_encrypted_data(const crypto::EciesEncryptResult& ecies,
                                       const CertInfo& recipient_cert,
                                       Curve curve = Curve::NistP256);

// etsi_response_tag: 0x81 (enrolmentResponse) or 0x83 (authorizationResponse).
Result<std::vector<uint8_t>> decrypt_and_unwrap(const std::vector<uint8_t>& response_bytes,
                                                const std::vector<uint8_t>& recipient_private_key,
                                                const std::vector<uint8_t>& request_aes_key,
                                                uint8_t etsi_response_tag,
                                                const CertInfo& signer_cert);

} // namespace v2xpki::enc
