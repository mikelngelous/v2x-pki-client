// AT (Authorization Ticket) request implementation. Per TS 102 941 §6.2.3.3.

#include "v2xpki/at_request.hpp"
#include "v2xpki/crypto_ec.hpp"
#include "v2xpki/sizes.hpp"

#include <algorithm>
#include <chrono>
#include <cstring>
#include <openssl/hmac.h>

extern "C" {
#include "InnerAtRequest.h"
#include "InnerAtResponse.h"
#include "SharedAtRequest.h"
#include "EcSignature.h"
#include "EtsiTs103097Data-SignedExternalPayload.h"
#include "EtsiTs103097Data-Encrypted.h"
#include "CertificateFormat.h"
#include "CertificateSubjectAttributes.h"
#include "CertificateId.h"
#include "PublicKeys.h"
#include "PublicVerificationKey.h"
#include "EccP256CurvePoint.h"
#include "EccP384CurvePoint.h"
#include "ValidityPeriod.h"
#include "Duration.h"
#include "SequenceOfPsidSsp.h"
#include "PsidSsp.h"
#include "CertificateBase.h"
#include "Ieee1609Dot2Data.h"
#include "asn_application.h"
}

#include "internal/coer.hpp"
#include "internal/asn_ptr.hpp"
#include "internal/encrypted_data.hpp"
#include "internal/signed_envelope.hpp"
#include "internal/curve_point.hpp"

namespace v2xpki {

namespace {

uint32_t unix_to_tai32(std::chrono::system_clock::time_point tp) {
    auto secs = std::chrono::duration_cast<std::chrono::seconds>(tp.time_since_epoch()).count();
    if (secs < kTaiEpochUnix) return 0;
    return static_cast<uint32_t>(secs - kTaiEpochUnix);
}

}

// --- Validator ---

bool validate_at_record(const AtRecord& rec, std::string* err) {
    if (rec.at_public_key.size() != pubkey_len(rec.curve) || rec.at_public_key[0] != 0x04) {
        if (err) *err = "at_public_key must be uncompressed (0x04 prefix, correct size for curve)";
        return false;
    }
    if (rec.requested_psids.empty()) {
        if (err) *err = "requested_psids must not be empty";
        return false;
    }
    for (auto psid : rec.requested_psids) {
        if (psid < 0) {
            if (err) *err = "psid values must be non-negative";
            return false;
        }
    }
    if (rec.validity_period_hours <= 0 || rec.validity_period_hours > 87600) {
        if (err) *err = "validity_period_hours must be 1-87600";
        return false;
    }
    return true;
}

// --- Assembler ---

AtRequestDescription assemble_at_request(const AtRecord& rec,
                                         std::chrono::system_clock::time_point now) {

    AtRequestDescription desc;
    desc.verification_key = rec.at_public_key;
    desc.psids = rec.requested_psids;
    desc.validity_start = unix_to_tai32(now);
    desc.validity_duration_hours = static_cast<uint16_t>(std::min(rec.validity_period_hours,
                                                                  int64_t(65535)));
    desc.aa_hid8 = rec.aa_hashed_id_8;
    desc.ea_hid8 = rec.ea_hashed_id_8;
    desc.curve = rec.curve;

    auto hmac_kp = crypto::generate_keypair(); // reuse keygen for random bytes
    if (hmac_kp) {
        desc.hmac_key.assign(hmac_kp->private_key.begin(),
                             hmac_kp->private_key.begin() + kP256ScalarLen);
    } else {
        desc.hmac_key.resize(kSha256Len, 0);
    }

    return desc;
}

// --- Encoder ---

Result<AtRequestResult> encode_at_request(const AtRequestDescription& desc, const CertInfo& aa_cert,
                                          const CertInfo& ea_cert, const CertInfo& ec_cert,
                                          const std::vector<uint8_t>& ec_private_key,
                                          const std::vector<uint8_t>& at_private_key) {

    // keyTag = HMAC-SHA256(hmacKey, OER(PublicVerificationKey))[:16]
    auto curve = desc.curve;
    PublicVerificationKey_t pvk{};
    switch (curve) {
        case Curve::BrainpoolP256r1:
            pvk.present = PublicVerificationKey_PR_ecdsaBrainpoolP256r1;
            pvk.choice.ecdsaBrainpoolP256r1 = point::from_sec1(desc.verification_key);
            break;
        case Curve::BrainpoolP384r1:
            pvk.present = PublicVerificationKey_PR_ecdsaBrainpoolP384r1;
            pvk.choice.ecdsaBrainpoolP384r1 = point::from_sec1_384(desc.verification_key);
            break;
        default:
            pvk.present = PublicVerificationKey_PR_ecdsaNistP256;
            pvk.choice.ecdsaNistP256 = point::from_sec1(desc.verification_key);
            break;
    }
    auto pvk_oer = coer::encode(&asn_DEF_PublicVerificationKey, &pvk);
    ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_PublicVerificationKey, &pvk);
    if (pvk_oer.empty()) return Error::Encode;

    uint8_t hmac_out[32];
    unsigned int hmac_len = 0;
    HMAC(EVP_sha256(), desc.hmac_key.data(), static_cast<int>(desc.hmac_key.size()), pvk_oer.data(),
         pvk_oer.size(), hmac_out, &hmac_len);
    std::vector<uint8_t> key_tag(hmac_out, hmac_out + 16);

    SharedAtRequest_t shared{};
    octet::set(&shared.eaId, desc.ea_hid8.data(), kHashedId8Len);
    octet::set(&shared.keyTag, key_tag.data(), 16);
    shared.certificateFormat = CertificateFormat_ts103097v131;

    auto* attrs = asn_calloc<CertificateSubjectAttributes_t>();
    auto* vp = asn_calloc<ValidityPeriod_t>();
    vp->start = desc.validity_start;
    auto* dur = asn_calloc<Duration_t>();
    dur->present = Duration_PR_hours;
    dur->choice.hours = desc.validity_duration_hours;
    vp->duration = dur;
    attrs->validityPeriod = vp;

    auto* perms = asn_calloc<SequenceOfPsidSsp_t>();
    for (auto psid : desc.psids) {
        auto* entry = asn_calloc<PsidSsp_t>();
        entry->psid = static_cast<unsigned long>(psid);
        ASN_SEQUENCE_ADD(&perms->list, entry);
    }
    attrs->appPermissions = perms;
    shared.requestedSubjectAttributes = attrs;

    auto shared_coer = coer::encode(&asn_DEF_SharedAtRequest, &shared);
    if (shared_coer.empty()) {
        ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_SharedAtRequest, &shared);
        return Error::Encode;
    }

    /* Build ecSignature: SignedExternalPayload signed with EC key,
       then ECIES-encrypted to EA.
       extDataHash = H(OER(sharedAtRequest)) where H matches curve
    */
    auto ext_hash = crypto::hash_for_curve(shared_coer, curve);
    auto signed_ext_bytes = sign::build_external_payload(ext_hash, ec_cert, ec_private_key, curve);
    if (signed_ext_bytes.empty()) {
        ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_SharedAtRequest, &shared);
        return Error::Crypto;
    }

    /* ECIES encrypt the signed external payload to EA's encryption key
       (fall back to public_key for synthetic test certs without one).
       ECIES is always P-256 (NIST or Brainpool), even for P-384 certs.
    */
    const std::vector<uint8_t>& ea_enc_key = ea_cert.encryption_key.empty()
                                                 ? ea_cert.public_key
                                                 : ea_cert.encryption_key;
    if (ea_enc_key.size() < 33) {
        ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_SharedAtRequest, &shared);
        return Error::InvalidArgument;
    }
    // ECIES curve matches the EA cert's encryption key curve, not the requester's curve.
    Curve ea_ecies_curve = ea_cert.enc_curve;
    auto p1_ea = crypto::hash_sha256(ea_cert.cert_bytes);
    auto ecies_ea = crypto::ecies_encrypt(ea_enc_key, signed_ext_bytes, p1_ea, ea_ecies_curve);
    if (!ecies_ea) {
        ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_SharedAtRequest, &shared);
        return Error::Crypto;
    }

    auto* enc_ec_sig = enc::build_encrypted_data(*ecies_ea, ea_cert, ea_ecies_curve);
    if (!enc_ec_sig) {
        ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_SharedAtRequest, &shared);
        return Error::Encode;
    }

    InnerAtRequest_t inner{};

    auto* pkeys = asn_calloc<PublicKeys_t>();
    auto* pvk_inner = asn_calloc<PublicVerificationKey_t>();
    switch (curve) {
        case Curve::BrainpoolP256r1:
            pvk_inner->present = PublicVerificationKey_PR_ecdsaBrainpoolP256r1;
            pvk_inner->choice.ecdsaBrainpoolP256r1 = point::from_sec1(desc.verification_key);
            break;
        case Curve::BrainpoolP384r1:
            pvk_inner->present = PublicVerificationKey_PR_ecdsaBrainpoolP384r1;
            pvk_inner->choice.ecdsaBrainpoolP384r1 = point::from_sec1_384(desc.verification_key);
            break;
        default:
            pvk_inner->present = PublicVerificationKey_PR_ecdsaNistP256;
            pvk_inner->choice.ecdsaNistP256 = point::from_sec1(desc.verification_key);
            break;
    }
    pkeys->verificationKey = pvk_inner;
    inner.publicKeys = pkeys;

    octet::set(&inner.hmacKey, desc.hmac_key.data(), desc.hmac_key.size());

    // sharedAtRequest — re-decode from COER to get a clean allocated copy
    auto shared_decoded = asn_decode<SharedAtRequest_t>(asn_DEF_SharedAtRequest, shared_coer.data(),
                                                        shared_coer.size());
    ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_SharedAtRequest, &shared);
    if (!shared_decoded) {
        ASN_STRUCT_FREE(asn_DEF_Ieee1609Dot2Data, enc_ec_sig);
        ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_InnerAtRequest, &inner);
        return Error::Encode;
    }
    inner.sharedAtRequest = shared_decoded.release();

    // ecSignature = encryptedEcSignature (ECIES to EA)
    auto* ec_signature = asn_calloc<EcSignature_t>();
    ec_signature->present = EcSignature_PR_encryptedEcSignature;
    ec_signature->choice
        .encryptedEcSignature = (struct EtsiTs103097Data_Encrypted*)((void*)enc_ec_sig);
    inner.ecSignature = ec_signature;

    auto inner_bytes = coer::encode(&asn_DEF_InnerAtRequest, &inner);
    ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_InnerAtRequest, &inner);
    if (inner_bytes.empty()) return Error::Encode;

    // Wrap in EtsiTs102941Data: version=0x01, CHOICE tag=0x82 (authorizationRequest [2])
    std::vector<uint8_t> etsi_bytes;
    etsi_bytes.push_back(0x01); // version = v1
    etsi_bytes.push_back(0x82); // CHOICE tag: authorizationRequest (context-class [2])
    etsi_bytes.insert(etsi_bytes.end(), inner_bytes.begin(), inner_bytes.end());

    // Build outer signed envelope (signer=self, AT private key, double hash)
    // TS 102 941 §6.2.3.3: PoP signed with the NEW verification key.
    auto outer_signed_bytes = sign::build_self_signed(etsi_bytes, at_private_key, curve);
    if (outer_signed_bytes.empty()) return Error::Crypto;

    /* ECIES encrypt to AA's encryption key (fall back to public_key for
       synthetic test certs without one).
       ECIES is always P-256 (NIST or Brainpool), even for P-384 certs.
    */
    const std::vector<uint8_t>& aa_enc_key = aa_cert.encryption_key.empty()
                                                 ? aa_cert.public_key
                                                 : aa_cert.encryption_key;
    if (aa_enc_key.size() < 33) return Error::InvalidArgument;
    // ECIES curve matches the AA cert's encryption key curve.
    Curve aa_ecies_curve = aa_cert.enc_curve;
    auto p1_aa = crypto::hash_sha256(aa_cert.cert_bytes);
    auto ecies_aa = crypto::ecies_encrypt(aa_enc_key, outer_signed_bytes, p1_aa, aa_ecies_curve);
    if (!ecies_aa) return Error::Crypto;

    auto* enc_outer = enc::build_encrypted_data(*ecies_aa, aa_cert, aa_ecies_curve);
    if (!enc_outer) return Error::Encode;

    auto final_bytes = coer::encode(&asn_DEF_Ieee1609Dot2Data, enc_outer);
    auto aes_key = ecies_aa->aes_key;
    ASN_STRUCT_FREE(asn_DEF_Ieee1609Dot2Data, enc_outer);

    if (final_bytes.empty()) return Error::Encode;
    return AtRequestResult{std::move(final_bytes), std::move(aes_key)};
}

// --- Response decoder ---

Result<AtResponse> decode_at_response(const std::vector<uint8_t>& response_bytes,
                                      const std::vector<uint8_t>& recipient_private_key,
                                      const std::vector<uint8_t>& request_aes_key) {

    auto inner_bytes = enc::decrypt_and_unwrap(response_bytes, recipient_private_key,
                                               request_aes_key, 0x83);
    if (!inner_bytes) return inner_bytes.error();

    auto resp = asn_decode<InnerAtResponse_t>(asn_DEF_InnerAtResponse, inner_bytes->data(),
                                              inner_bytes->size());
    if (!resp) return Error::Decode;

    AtResponse result;
    result.response_code = static_cast<AuthorizationResponseCode>(resp->responseCode);
    result.request_hash = octet::bytes(&resp->requestHash);

    if (resp->certificate) {
        CertInfo ci;
        ci.cert_bytes = coer::encode(&asn_DEF_CertificateBase, resp->certificate);
        auto h = crypto::hash_sha256(ci.cert_bytes);
        std::copy_n(h.end() - 8, 8, ci.hashed_id_8.begin());
        ci.label = "at_response";
        result.certificate = ci;
    }

    return result;
}

} // namespace v2xpki
