// Unwrap + verify an EtsiTs103097Data-Signed envelope. Shared by the trust-list (ECTL/CTL)
// and CRL decoders — nothing here is specific to either payload.
#pragma once

#include "v2xpki/sizes.hpp"

#include <array>
#include <cstdint>
#include <optional>
#include <vector>

namespace v2xpki::signed_msg {

struct SignedMessage {
    std::vector<uint8_t> payload_coer; // raw EtsiTs102941Data COER
    std::vector<uint8_t> tbs_coer;
    std::array<uint8_t, 8> signer_hid8{};
    std::vector<uint8_t> sig_r;
    std::vector<uint8_t> sig_s;
    Curve sig_curve = Curve::NistP256;
    bool has_signer_digest = false;
};

std::optional<SignedMessage> unwrap(const std::vector<uint8_t>& coer);

// IEEE 1609.2 §5.3.1: signedDataHash = H( H(COER(tbsData)) || H(signerIdentifierInput) ).
bool verify(const SignedMessage& data, const std::vector<uint8_t>& verifier_pubkey,
            const std::vector<uint8_t>& signer_cert_coer);

} // namespace v2xpki::signed_msg
