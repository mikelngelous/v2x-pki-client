// EC (Enrolment Credential) request implementation. TS 102 941 §6.2.3.2.

#include "v2xpki/ec_request.hpp"
#include "v2xpki/crypto_ec.hpp"
#include "v2xpki/sizes.hpp"

#include <algorithm>
#include <chrono>
#include <cstring>

extern "C" {
#include "InnerEcRequest.h"
#include "InnerEcResponse.h"
#include "CertificateFormat.h"
#include "PublicKeys.h"
#include "PublicVerificationKey.h"
#include "EccP256CurvePoint.h"
#include "EccP384CurvePoint.h"
#include "CertificateSubjectAttributes.h"
#include "CertificateId.h"
#include "ValidityPeriod.h"
#include "Duration.h"
#include "SequenceOfPsidSsp.h"
#include "PsidSsp.h"
#include "CertificateBase.h"
#include "Ieee1609Dot2Data.h"
#include "EtsiTs102941MessagesCa_EtsiTs102941Data.h"
#include "EtsiTs102941MessagesCa_EtsiTs102941DataContent.h"
#include "InnerEcRequestSignedForPop.h"
#include "asn_application.h"
}

#include "internal/coer.hpp"
#include "internal/asn_ptr.hpp"
#include "internal/cert_parse.hpp"
#include "internal/request_hash.hpp"
#include "internal/encrypted_data.hpp"
#include "internal/curve_point.hpp"
#include "internal/signed_envelope.hpp"

namespace v2xpki {

namespace {

uint32_t unix_to_tai32(std::chrono::system_clock::time_point tp) {
    auto secs = std::chrono::duration_cast<std::chrono::seconds>(tp.time_since_epoch()).count();
    if (secs < kTaiEpochUnix) return 0;
    return static_cast<uint32_t>(secs - kTaiEpochUnix);
}

}

// --- Validator ---

bool validate_ec_record(const EcRecord& rec, std::string* err) {
    if (rec.canonical_public_key.size() != pubkey_len(rec.curve) ||
        rec.canonical_public_key[0] != 0x04) {
        if (err)
            *err =
                "canonical_public_key must be uncompressed (0x04 prefix, correct size for curve)";
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
    if (rec.validity_period_days <= 0 || rec.validity_period_days > 3650) {
        if (err) *err = "validity_period_days must be 1-3650";
        return false;
    }
    return true;
}

// --- Assembler ---

EcRequestDescription assemble_ec_request(const EcRecord& rec,
                                         std::chrono::system_clock::time_point now) {

    EcRequestDescription desc;
    desc.its_id = rec.its_id.empty() ? "v2xpki-its-s" : rec.its_id;
    desc.verification_key = rec.canonical_public_key;
    desc.psids = rec.requested_psids;
    desc.validity_start = unix_to_tai32(now);
    desc.validity_duration_hours = static_cast<uint16_t>(rec.validity_period_days * 24);
    desc.ea_hid8 = rec.ea_hashed_id_8;
    desc.curve = rec.curve;
    return desc;
}

// --- Encoder ---

Result<EcRequestResult> encode_ec_request(const EcRequestDescription& desc, const CertInfo& ea_cert,
                                          const std::vector<uint8_t>& canonical_private_key) {

    InnerEcRequest_t inner{};
    auto curve = desc.curve;

    octet::set(&inner.itsId, reinterpret_cast<const uint8_t*>(desc.its_id.data()),
               desc.its_id.size());

    inner.certificateFormat = CertificateFormat_ts103097v131;

    auto* pkeys = asn_calloc<PublicKeys_t>();
    auto* pvk = asn_calloc<PublicVerificationKey_t>();
    switch (curve) {
        case Curve::BrainpoolP256r1:
            pvk->present = PublicVerificationKey_PR_ecdsaBrainpoolP256r1;
            pvk->choice.ecdsaBrainpoolP256r1 = point::from_sec1(desc.verification_key.to_vector());
            break;
        case Curve::BrainpoolP384r1:
            pvk->present = PublicVerificationKey_PR_ecdsaBrainpoolP384r1;
            pvk->choice
                .ecdsaBrainpoolP384r1 = point::from_sec1_384(desc.verification_key.to_vector());
            break;
        default:
            pvk->present = PublicVerificationKey_PR_ecdsaNistP256;
            pvk->choice.ecdsaNistP256 = point::from_sec1(desc.verification_key.to_vector());
            break;
    }
    pkeys->verificationKey = pvk;
    inner.publicKeys = pkeys;

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

    inner.requestedSubjectAttributes = attrs;

    auto inner_bytes = coer::encode(&asn_DEF_InnerEcRequest, &inner);
    ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_InnerEcRequest, &inner);

    if (inner_bytes.empty()) return Error::Encode;

    // InnerEcRequestSignedForPop: InnerEcRequest signed with the canonical key.
    auto pop_signed_bytes = sign::build_self_signed(inner_bytes, canonical_private_key, curve);
    if (pop_signed_bytes.empty()) return Error::Crypto;

    // EtsiTs102941Data{enrolmentRequest}: build the COER directly to preserve the PoP signed bytes
    std::vector<uint8_t> etsi_bytes;
    etsi_bytes.push_back(0x01); // version v1
    etsi_bytes.push_back(0x80); // CHOICE [0] enrolmentRequest
    etsi_bytes.insert(etsi_bytes.end(), pop_signed_bytes.begin(), pop_signed_bytes.end());

    // Outer signed envelope (TS 102 941 §6.2.3.2.1): ECIES plaintext signed with canonical key.
    auto outer_signed_bytes = sign::build_self_signed(etsi_bytes, canonical_private_key, curve);
    if (outer_signed_bytes.empty()) return Error::Crypto;

    /* ECIES to the EA's encryption key, not its verification key (test certs without one fall back
       to public_key). TS 102 941 §B.2: P1 = SHA-256(recipient cert COER). ECIES is always P-256
       (NIST or Brainpool), even for P-384 certs.
    */
    std::vector<uint8_t> ea_enc_key = ea_cert.encryption_key.empty()
                                          ? ea_cert.public_key.to_vector()
                                          : ea_cert.encryption_key.to_vector();
    if (ea_enc_key.size() < 33) return Error::InvalidArgument;

    // ECIES curve = the EA cert's encryption-key curve, not the requester's.
    Curve ecies_curve = ea_cert.enc_curve;
    auto p1 = crypto::hash_sha256(ea_cert.cert_bytes.to_vector());
    auto ecies_result = crypto::ecies_encrypt(ea_enc_key, outer_signed_bytes, p1, ecies_curve);
    if (!ecies_result) return Error::Crypto;

    auto* enc_wrapper = enc::build_encrypted_data(*ecies_result, ea_cert, ecies_curve);
    if (!enc_wrapper) return Error::Encode;

    auto final_bytes = coer::encode(&asn_DEF_Ieee1609Dot2Data, enc_wrapper);
    ASN_STRUCT_FREE(asn_DEF_Ieee1609Dot2Data, enc_wrapper);

    if (final_bytes.empty()) return Error::Encode;
    auto encoded = StaticBytes<kMaxCoerMessageLen>::from(final_bytes);
    if (!encoded) return Error::Encode;
    auto aes_key = StaticBytes<kAesKeyLen>::from(ecies_result->aes_key);
    if (!aes_key) return Error::Crypto;
    return EcRequestResult{*encoded, *aes_key};
}

// --- Response decoder ---

Result<EcResponse> decode_ec_response(const std::vector<uint8_t>& response_bytes,
                                      const std::vector<uint8_t>& recipient_private_key,
                                      const std::vector<uint8_t>& request_aes_key,
                                      const std::vector<uint8_t>& request_bytes) {

    auto inner_bytes = enc::decrypt_and_unwrap(response_bytes, recipient_private_key,
                                               request_aes_key, 0x81);
    if (!inner_bytes) return inner_bytes.error();

    auto resp = asn_decode<InnerEcResponse_t>(asn_DEF_InnerEcResponse, inner_bytes->data(),
                                              inner_bytes->size());
    if (!resp) return Error::Decode;

    EcResponse result;
    result.response_code = static_cast<EnrolmentResponseCode>(resp->responseCode);
    auto request_hash = StaticBytes<16>::from(octet::bytes(&resp->requestHash));
    if (!request_hash) return Error::Decode;
    result.request_hash = *request_hash;

    // TS 102 941 §6.2.3.2.2: requestHash = leftmost 16 octets of SHA-256 over the request as sent.
    if (!request_hash_matches(request_bytes, result.request_hash)) return Error::SignatureInvalid;

    if (resp->certificate) {
        auto cert_bytes = coer::encode(&asn_DEF_CertificateBase, resp->certificate);
        // EtsiTs103097Certificate_t is just a CertificateBase_t typedef; the struct tag hides it.
        auto ci = cert::from_struct(reinterpret_cast<const CertificateBase*>(resp->certificate),
                                    cert_bytes);
        ci.label = "ec_response";
        result.certificate = ci;
    }

    return result;
}

} // namespace v2xpki
