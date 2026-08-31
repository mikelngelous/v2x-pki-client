// IEEE 1609.2 SignedData envelope builders (multi-curve).

#include "signed_envelope.hpp"
#include "asn_ptr.hpp"
#include "coer.hpp"
#include "curve_point.hpp"
#include "v2xpki/crypto_ec.hpp"
#include "v2xpki/sizes.hpp"

#include <chrono>

extern "C" {
#include "Ieee1609Dot2Data.h"
#include "Ieee1609Dot2Content.h"
#include "SignedData.h"
#include "ToBeSignedData.h"
#include "SignedDataPayload.h"
#include "HashedData.h"
#include "HeaderInfo.h"
#include "SignerIdentifier.h"
#include "Signature.h"
#include "EcdsaP256Signature.h"
#include "EcdsaP384Signature.h"
#include "EccP256CurvePoint.h"
#include "EccP384CurvePoint.h"
#include "HashAlgorithm.h"
}

namespace v2xpki::sign {

namespace {

uint64_t current_generation_time() {
    auto now_us = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::microseconds>(
                                            std::chrono::system_clock::now().time_since_epoch())
                                            .count());
    uint64_t tai_epoch_us = static_cast<uint64_t>(kTaiEpochUnix) * 1000000ULL;
    return now_us - tai_epoch_us;
}

// Build the ASN.1 Signature node for the given curve.
Signature_t *build_asn_signature(const v2xpki::Signature &sig, Curve curve) {
    auto *asn_sig = asn_calloc<Signature_t>();
    auto slen = scalar_len(curve);

    if (is_p256_size(curve)) {
        auto *ecdsa = asn_calloc<EcdsaP256Signature_t>();
        auto *r_pt = asn_calloc<EccP256CurvePoint_t>();
        r_pt->present = EccP256CurvePoint_PR_x_only;
        octet::set(&r_pt->choice.x_only, sig.r.data(), slen);
        ecdsa->rSig = r_pt;
        octet::set(&ecdsa->sSig, sig.s.data(), slen);

        if (curve == Curve::BrainpoolP256r1) {
            asn_sig->present = Signature_PR_ecdsaBrainpoolP256r1Signature;
            asn_sig->choice.ecdsaBrainpoolP256r1Signature = ecdsa;
        } else {
            asn_sig->present = Signature_PR_ecdsaNistP256Signature;
            asn_sig->choice.ecdsaNistP256Signature = ecdsa;
        }
    } else {
        auto *ecdsa = asn_calloc<EcdsaP384Signature_t>();
        auto *r_pt = asn_calloc<EccP384CurvePoint_t>();
        r_pt->present = EccP384CurvePoint_PR_x_only;
        octet::set(&r_pt->choice.x_only, sig.r.data(), slen);
        ecdsa->rSig = r_pt;
        octet::set(&ecdsa->sSig, sig.s.data(), slen);

        // TODO: P-384 sign assumes Brainpool; NIST P-384 would need ecdsaNistP384Signature.
        asn_sig->present = Signature_PR_ecdsaBrainpoolP384r1Signature;
        asn_sig->choice.ecdsaBrainpoolP384r1Signature = ecdsa;
    }
    return asn_sig;
}

// IEEE 1609.2 §5.3.1 double hash, sign, build signer + signature ASN.1 nodes,
// wrap in Ieee1609Dot2Data, COER-encode.
// tbs: caller-built ToBeSignedData (assigned into wrapper, freed by this function).
// signer_cert_bytes: empty for self-signed, or COER cert bytes for digest signer.
// signer_hid8: used only when signer_cert_bytes is non-empty.
std::vector<uint8_t> finalize_signed_data(ToBeSignedData_t *tbs,
                                          const std::vector<uint8_t> &private_key,
                                          const std::vector<uint8_t> &signer_cert_bytes,
                                          const std::array<uint8_t, 8> &signer_hid8, Curve curve) {

    Ieee1609Dot2Data_t wrapper{};
    wrapper.protocolVersion = kIeee1609Dot2Version;

    auto *content = asn_calloc<Ieee1609Dot2Content_t>();
    content->present = Ieee1609Dot2Content_PR_signedData;

    auto *sd = asn_calloc<SignedData_t>();
    sd->hashId = is_p256_size(curve) ? HashAlgorithm_sha256 : HashAlgorithm_sha384;
    sd->tbsData = tbs;

    // Encode tbsData, then sign per IEEE 1609.2 §5.3.1:
    //   e = H( H(COER(tbsData)) || H(signer_identifier_input) )
    auto tbs_bytes = coer::encode(&asn_DEF_ToBeSignedData, tbs);
    if (tbs_bytes.empty()) {
        content->choice.signedData = sd;
        wrapper.content = content;
        ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_Ieee1609Dot2Data, &wrapper);
        return {};
    }
    auto h_tbs = crypto::hash_for_curve(tbs_bytes, curve);
    auto h_signer = crypto::hash_for_curve(signer_cert_bytes, curve);
    std::vector<uint8_t> concat;
    concat.reserve(h_tbs.size() + h_signer.size());
    concat.insert(concat.end(), h_tbs.begin(), h_tbs.end());
    concat.insert(concat.end(), h_signer.begin(), h_signer.end());
    auto e = crypto::hash_for_curve(concat, curve);
    auto sig_opt = crypto::ecdsa_sign_digest(private_key, e, curve);
    if (!sig_opt) {
        content->choice.signedData = sd;
        wrapper.content = content;
        ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_Ieee1609Dot2Data, &wrapper);
        return {};
    }

    // signer
    auto *signer = asn_calloc<SignerIdentifier_t>();
    if (signer_cert_bytes.empty()) {
        signer->present = SignerIdentifier_PR_self;
    } else {
        signer->present = SignerIdentifier_PR_digest;
        octet::set(&signer->choice.digest, signer_hid8.data(), kHashedId8Len);
    }
    sd->signer = signer;

    // signature
    sd->signature = build_asn_signature(*sig_opt, curve);

    content->choice.signedData = sd;
    wrapper.content = content;

    auto result = coer::encode(&asn_DEF_Ieee1609Dot2Data, &wrapper);
    ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_Ieee1609Dot2Data, &wrapper);
    return result;
}

ToBeSignedData_t *make_unsecured_tbs(const std::vector<uint8_t> &payload_bytes) {
    auto *tbs = asn_calloc<ToBeSignedData_t>();

    auto *payload = asn_calloc<SignedDataPayload_t>();
    auto *payload_data = asn_calloc<Ieee1609Dot2Data_t>();
    payload_data->protocolVersion = kIeee1609Dot2Version;
    auto *unsecured_content = asn_calloc<Ieee1609Dot2Content_t>();
    unsecured_content->present = Ieee1609Dot2Content_PR_unsecuredData;
    octet::set(&unsecured_content->choice.unsecuredData, payload_bytes.data(),
               payload_bytes.size());
    payload_data->content = unsecured_content;
    payload->data = payload_data;
    tbs->payload = payload;

    auto *hdr = asn_calloc<HeaderInfo_t>();
    hdr->psid = kPsidScr;
    auto *gen_time = asn_calloc<Time64_t>();
    asn_ulong2INTEGER(gen_time, current_generation_time());
    hdr->generationTime = gen_time;
    tbs->headerInfo = hdr;

    return tbs;
}

}

std::vector<uint8_t> build_self_signed(const std::vector<uint8_t> &payload_bytes,
                                       const std::vector<uint8_t> &private_key, Curve curve) {
    return finalize_signed_data(make_unsecured_tbs(payload_bytes), private_key, {}, {}, curve);
}

std::vector<uint8_t> build_signed_by_cert(const std::vector<uint8_t> &payload_bytes,
                                          const CertInfo &signer_cert,
                                          const std::vector<uint8_t> &private_key, Curve curve) {
    return finalize_signed_data(make_unsecured_tbs(payload_bytes), private_key,
                                signer_cert.cert_bytes.to_vector(), signer_cert.hashed_id_8, curve);
}

std::vector<uint8_t> build_external_payload(const std::vector<uint8_t> &ext_data_hash,
                                            const CertInfo &ec_cert,
                                            const std::vector<uint8_t> &ec_private_key,
                                            Curve curve) {

    auto *tbs = asn_calloc<ToBeSignedData_t>();

    auto *payload = asn_calloc<SignedDataPayload_t>();
    auto *hashed = asn_calloc<HashedData_t>();
    if (is_p256_size(curve)) {
        hashed->present = HashedData_PR_sha256HashedData;
        octet::set(&hashed->choice.sha256HashedData, ext_data_hash.data(), ext_data_hash.size());
    } else {
        hashed->present = HashedData_PR_sha384HashedData;
        octet::set(&hashed->choice.sha384HashedData, ext_data_hash.data(), ext_data_hash.size());
    }
    payload->extDataHash = hashed;
    tbs->payload = payload;

    auto *hdr = asn_calloc<HeaderInfo_t>();
    hdr->psid = kPsidScr;
    auto *gen_time = asn_calloc<Time64_t>();
    asn_ulong2INTEGER(gen_time, current_generation_time());
    hdr->generationTime = gen_time;
    tbs->headerInfo = hdr;

    return finalize_signed_data(tbs, ec_private_key, ec_cert.cert_bytes.to_vector(),
                                ec_cert.hashed_id_8, curve);
}

} // namespace v2xpki::sign
