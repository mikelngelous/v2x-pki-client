// Unwrap + verify an EtsiTs103097Data-Signed envelope (IEEE 1609.2 §5.3.1).

#include "signed_message.hpp"

#include "v2xpki/crypto_ec.hpp"
#include "v2xpki/key_store.hpp"
#include "v2xpki/static_bytes.hpp"

#include <algorithm>

extern "C" {
#include "Ieee1609Dot2Data.h"
#include "Ieee1609Dot2Content.h"
#include "SignedData.h"
#include "ToBeSignedData.h"
#include "SignedDataPayload.h"
#include "SignerIdentifier.h"
#include "Signature.h"
#include "asn_application.h"
}

#include "coer.hpp"
#include "asn_ptr.hpp"
#include "curve_point.hpp"
#include "cert_parse.hpp"

namespace v2xpki::signed_msg {

std::optional<SignedMessage> unwrap(const std::vector<uint8_t> &coer) {
    auto outer = asn_decode_fallback<Ieee1609Dot2Data_t>(asn_DEF_Ieee1609Dot2Data, coer.data(),
                                                         coer.size());
    if (!outer) return std::nullopt;

    if (!outer->content || outer->content->present != Ieee1609Dot2Content_PR_signedData) {
        return std::nullopt;
    }

    auto *sd = outer->content->choice.signedData;
    if (!sd || !sd->tbsData || !sd->tbsData->payload) {
        return std::nullopt;
    }

    SignedMessage result;

    // TBS COER for signature verification
    result.tbs_coer = coer::encode(&asn_DEF_ToBeSignedData, sd->tbsData);

    // Signer HID8
    if (sd->signer && sd->signer->present == SignerIdentifier_PR_digest) {
        auto d = octet::bytes(&sd->signer->choice.digest);
        if (d.size() == kHashedId8Len) {
            std::copy_n(d.begin(), kHashedId8Len, result.signer_hid8.begin());
            result.has_signer_digest = true;
        }
    }

    // Signature r, s — detect curve from signature variant
    point::SigRS rs;
    if (point::extract_sig(sd->signature, rs)) {
        result.sig_r = std::move(rs.r);
        result.sig_s = std::move(rs.s);
        result.sig_curve = rs.curve;
    }

    // Contains COER-encoded EtsiTs102941Data (version + EtsiTs102941DataContent)
    auto *payload = sd->tbsData->payload;
    if (!payload->data || !payload->data->content ||
        payload->data->content->present != Ieee1609Dot2Content_PR_unsecuredData) {
        return std::nullopt;
    }

    result.payload_coer = octet::bytes(&payload->data->content->choice.unsecuredData);

    if (result.payload_coer.empty()) return std::nullopt;
    return result;
}

// IEEE 1609.2 §5.3.1 signed data verification (multi-curve).
// Hash algorithm matches signature curve: SHA-256 for P-256/BP256, SHA-384 for BP384.
// signedDataHash = H( H(COER(tbsData)) || H(signerIdentifierInput) )
bool verify(const SignedMessage &data, const std::vector<uint8_t> &verifier_pubkey,
            const std::vector<uint8_t> &signer_cert_coer) {
    if (verifier_pubkey.empty() || data.tbs_coer.empty()) return false;
    auto slen = scalar_len(data.sig_curve);
    if (data.sig_r.size() != slen || data.sig_s.size() != slen) return false;

    // TS 102 941 §6.3.4: a CTL carries signer=certificate, so only a digest binds the caller's.
    // TODO: when signer=certificate, verify against the embedded cert instead of the caller's.
    if (data.has_signer_digest) {
        auto computed_hid8 = cert::compute_hid8(signer_cert_coer);
        if (computed_hid8 != data.signer_hid8) return false;
    }

    auto tbs_hash = crypto::hash_for_curve(data.tbs_coer, data.sig_curve);
    auto signer_hash = crypto::hash_for_curve(signer_cert_coer, data.sig_curve);

    std::vector<uint8_t> concat;
    concat.reserve(tbs_hash.size() + signer_hash.size());
    concat.insert(concat.end(), tbs_hash.begin(), tbs_hash.end());
    concat.insert(concat.end(), signer_hash.begin(), signer_hash.end());
    auto signed_data_hash = crypto::hash_for_curve(concat, data.sig_curve);

    auto sig_r = StaticBytes<kP384ScalarLen>::from(data.sig_r);
    auto sig_s = StaticBytes<kP384ScalarLen>::from(data.sig_s);
    if (!sig_r || !sig_s) return false;

    v2xpki::Signature sig;
    sig.r = *sig_r;
    sig.s = *sig_s;

    return crypto::ecdsa_verify_digest(verifier_pubkey, signed_data_hash, sig, data.sig_curve);
}

} // namespace v2xpki::signed_msg
