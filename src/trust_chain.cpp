#include "v2xpki/trust_chain.hpp"
#include "v2xpki/crypto_ec.hpp"
#include "v2xpki/sizes.hpp"

#include <algorithm>
#include <cstring>
#include <filesystem>
#include <fstream>

extern "C" {
#include "CertificateBase.h"
#include "Certificate.h"
#include "CertificateId.h"
#include "CertificateType.h"
#include "Duration.h"
#include "EccP256CurvePoint.h"
#include "EcdsaP256Signature.h"
#include "HashAlgorithm.h"
#include "HashedId3.h"
#include "IssuerIdentifier.h"
#include "PublicVerificationKey.h"
#include "Signature.h"
#include "ToBeSignedCertificate.h"
#include "ValidityPeriod.h"
#include "VerificationKeyIndicator.h"
#include "asn_application.h"
}

#include "internal/coer.hpp"
#include "internal/asn_ptr.hpp"
#include "internal/curve_point.hpp"
#include "internal/cert_parse.hpp"

namespace v2xpki {

// --- TrustChain ---

bool TrustChain::load_from_directory(const std::string& certs_dir) {
    namespace fs = std::filesystem;
    if (!fs::is_directory(certs_dir)) return false;

    bool loaded_any = false;
    for (const auto& entry : fs::directory_iterator(certs_dir)) {
        if (!entry.is_regular_file()) continue;
        auto ext = entry.path().extension().string();
        if (ext != ".cert") continue;

        std::ifstream ifs(entry.path(), std::ios::binary);
        if (!ifs) continue;
        std::vector<uint8_t> raw((std::istreambuf_iterator<char>(ifs)),
                                 std::istreambuf_iterator<char>());
        if (raw.empty()) continue;

        auto ci = cert::from_coer(raw);
        if (ci.cert_bytes.empty()) continue;
        ci.label = entry.path().stem().string();

        add_cert(ci);
        loaded_any = true;
    }
    return loaded_any;
}

bool TrustChain::add_cert(const CertInfo& ci) {
    certs_[ci.hashed_id_8] = ci;
    return true;
}

std::optional<CertInfo> TrustChain::find_by_hashed_id_8(const std::array<uint8_t, 8>& hid8) const {
    auto it = certs_.find(hid8);
    if (it == certs_.end()) return std::nullopt;
    return it->second;
}

bool TrustChain::validate_chain(const CertInfo& at_cert) const {
    if (at_cert.is_self_signed) return false;

    auto aa_opt = find_by_hashed_id_8(at_cert.issuer_hash_id_8);
    if (!aa_opt) return false;
    const auto& aa_cert = *aa_opt;

    if (!verify_cert_signature(at_cert, aa_cert)) return false;

    if (aa_cert.is_self_signed) {
        return verify_cert_signature(aa_cert, aa_cert);
    }

    auto rca_opt = find_by_hashed_id_8(aa_cert.issuer_hash_id_8);
    if (!rca_opt) return false;
    const auto& rca_cert = *rca_opt;

    if (!verify_cert_signature(aa_cert, rca_cert)) return false;
    if (!rca_cert.is_self_signed) return false;
    return verify_cert_signature(rca_cert, rca_cert);
}

std::vector<CertInfo> TrustChain::get_rcas() const { return get_by_prefix("rca_"); }
std::vector<CertInfo> TrustChain::get_aas() const { return get_by_prefix("aa_"); }
std::vector<CertInfo> TrustChain::get_eas() const { return get_by_prefix("ea_"); }
std::vector<CertInfo> TrustChain::get_tlms() const { return get_by_prefix("tlm_"); }

bool TrustChain::verify_cert_signature(const CertInfo& cert, const CertInfo& issuer) const {
    auto slen = scalar_len(cert.curve);
    if (cert.tbs_bytes.empty() || cert.signature_r.size() != slen ||
        cert.signature_s.size() != slen)
        return false;
    if (issuer.public_key.empty()) return false;

    // IEEE 1609.2 §5.3.1: e = H( H(COER(toBeSigned)) || H(signerIdentifierInput) )
    auto tbs_hash = crypto::hash_for_curve(cert.tbs_bytes, cert.curve);
    std::vector<uint8_t> signer_input;
    if (cert.is_self_signed)
        signer_input = {}; // self-signed: signerIdentifierInput is empty
    else
        signer_input = issuer.cert_bytes; // issuer cert COER bytes
    auto signer_hash = crypto::hash_for_curve(signer_input, cert.curve);

    std::vector<uint8_t> concat;
    concat.reserve(tbs_hash.size() + signer_hash.size());
    concat.insert(concat.end(), tbs_hash.begin(), tbs_hash.end());
    concat.insert(concat.end(), signer_hash.begin(), signer_hash.end());
    auto digest = crypto::hash_for_curve(concat, cert.curve);

    Signature sig;
    sig.r = cert.signature_r;
    sig.s = cert.signature_s;
    return crypto::ecdsa_verify_digest(issuer.public_key, digest, sig, cert.curve);
}

std::vector<CertInfo> TrustChain::get_by_prefix(const std::string& prefix) const {
    std::vector<CertInfo> result;
    for (const auto& [hid8, ci] : certs_) {
        if (ci.label.find(prefix) == 0) {
            result.push_back(ci);
        }
    }
    return result;
}

// --- cert_utils ---

namespace cert_utils {

std::vector<uint8_t> encode_tbs_uper(const std::string& name,
                                     const std::vector<uint8_t>& public_key, bool is_ca,
                                     uint32_t start_time, uint16_t duration_years) {

    if (public_key.size() != kP256PublicKeyLen) return {};

    ToBeSignedCertificate_t tbs{};

    auto* id = asn_calloc<CertificateId_t>();
    id->present = CertificateId_PR_name;
    OCTET_STRING_fromBuf(&id->choice.name, name.c_str(), static_cast<int>(name.size()));
    tbs.id = id;

    uint8_t craca[3] = {0, 0, 0};
    octet::set(&tbs.cracaId, craca, 3);
    tbs.crlSeries = 0;

    auto* vp = asn_calloc<ValidityPeriod_t>();
    vp->start = start_time;
    auto* dur = asn_calloc<Duration_t>();
    dur->present = Duration_PR_years;
    dur->choice.years = duration_years;
    vp->duration = dur;
    tbs.validityPeriod = vp;

    auto* vki = asn_calloc<VerificationKeyIndicator_t>();
    vki->present = VerificationKeyIndicator_PR_verificationKey;

    auto* pvk = asn_calloc<PublicVerificationKey_t>();
    pvk->present = PublicVerificationKey_PR_ecdsaNistP256;

    auto* point = asn_calloc<EccP256CurvePoint_t>();
    point->present = EccP256CurvePoint_PR_uncompressedP256;
    octet::set(&point->choice.uncompressedP256.x, public_key.data() + 1, kP256ScalarLen);
    octet::set(&point->choice.uncompressedP256.y, public_key.data() + kP256CompressedLen,
               kP256ScalarLen);

    pvk->choice.ecdsaNistP256 = point;
    vki->choice.verificationKey = pvk;
    tbs.verifyKeyIndicator = vki;

    if (is_ca) {
        auto* perms = asn_calloc<SequenceOfPsidGroupPermissions_t>();
        tbs.certIssuePermissions = perms;
    }

    auto result = coer::encode_uper(&asn_DEF_ToBeSignedCertificate, &tbs);

    ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_ToBeSignedCertificate, &tbs);
    return result;
}

// Build a ToBeSignedCertificate struct (not yet encoded) for use with COER cert building
static ToBeSignedCertificate_t* build_tbs_struct(const std::string& name,
                                                 const std::vector<uint8_t>& public_key, bool is_ca,
                                                 uint32_t start_time, uint16_t duration_years) {

    if (public_key.size() != kP256PublicKeyLen) return nullptr;

    auto* tbs = asn_calloc<ToBeSignedCertificate_t>();

    auto* id = asn_calloc<CertificateId_t>();
    id->present = CertificateId_PR_name;
    OCTET_STRING_fromBuf(&id->choice.name, name.c_str(), static_cast<int>(name.size()));
    tbs->id = id;

    uint8_t craca[3] = {0, 0, 0};
    octet::set(&tbs->cracaId, craca, 3);
    tbs->crlSeries = 0;

    auto* vp = asn_calloc<ValidityPeriod_t>();
    vp->start = start_time;
    auto* dur = asn_calloc<Duration_t>();
    dur->present = Duration_PR_years;
    dur->choice.years = duration_years;
    vp->duration = dur;
    tbs->validityPeriod = vp;

    auto* vki = asn_calloc<VerificationKeyIndicator_t>();
    vki->present = VerificationKeyIndicator_PR_verificationKey;

    auto* pvk = asn_calloc<PublicVerificationKey_t>();
    pvk->present = PublicVerificationKey_PR_ecdsaNistP256;

    auto* point = asn_calloc<EccP256CurvePoint_t>();
    point->present = EccP256CurvePoint_PR_uncompressedP256;
    octet::set(&point->choice.uncompressedP256.x, public_key.data() + 1, kP256ScalarLen);
    octet::set(&point->choice.uncompressedP256.y, public_key.data() + kP256CompressedLen,
               kP256ScalarLen);

    pvk->choice.ecdsaNistP256 = point;
    vki->choice.verificationKey = pvk;
    tbs->verifyKeyIndicator = vki;

    if (is_ca) {
        auto* perms = asn_calloc<SequenceOfPsidGroupPermissions_t>();
        tbs->certIssuePermissions = perms;
    }

    return tbs;
}

std::optional<CertInfo> build_signed_cert(const std::string& name,
                                          const std::vector<uint8_t>& subject_public_key,
                                          const std::vector<uint8_t>& issuer_private_key,
                                          const std::array<uint8_t, 8>& issuer_hid8, bool is_ca,
                                          bool is_self_signed,
                                          const std::vector<uint8_t>& issuer_cert_bytes) {

    if (subject_public_key.size() != kP256PublicKeyLen) return std::nullopt;

    uint32_t start_time = 0;
    uint16_t duration_years = 30;

    // Build TBS struct and encode to COER for signing
    auto* tbs = build_tbs_struct(name, subject_public_key, is_ca, start_time, duration_years);
    if (!tbs) return std::nullopt;

    auto tbs_coer = coer::encode(&asn_DEF_ToBeSignedCertificate, tbs);
    if (tbs_coer.empty()) {
        ASN_STRUCT_FREE(asn_DEF_ToBeSignedCertificate, tbs);
        return std::nullopt;
    }

    // IEEE 1609.2 §5.3.1: sign H( H(COER(toBeSigned)) || H(signerIdentifierInput) )
    auto tbs_hash = crypto::hash_sha256(tbs_coer);
    std::vector<uint8_t> signer_input = is_self_signed ? std::vector<uint8_t>{} : issuer_cert_bytes;
    auto signer_hash = crypto::hash_sha256(signer_input);
    std::vector<uint8_t> concat;
    concat.reserve(tbs_hash.size() + signer_hash.size());
    concat.insert(concat.end(), tbs_hash.begin(), tbs_hash.end());
    concat.insert(concat.end(), signer_hash.begin(), signer_hash.end());
    auto digest = crypto::hash_sha256(concat);
    auto sig_opt = crypto::ecdsa_sign_digest(issuer_private_key, digest);
    if (!sig_opt) {
        ASN_STRUCT_FREE(asn_DEF_ToBeSignedCertificate, tbs);
        return std::nullopt;
    }

    // Build full CertificateBase ASN.1 struct
    CertificateBase_t cert{};
    cert.version = kIeee1609Dot2Version;
    cert.type = CertificateType_explicit;

    auto* issuer = asn_calloc<IssuerIdentifier_t>();
    if (is_self_signed) {
        issuer->present = IssuerIdentifier_PR_self;
        issuer->choice.self = HashAlgorithm_sha256;
    } else {
        issuer->present = IssuerIdentifier_PR_sha256AndDigest;
        octet::set(&issuer->choice.sha256AndDigest, issuer_hid8.data(), kHashedId8Len);
    }
    cert.issuer = issuer;

    // TBS — pass ownership of struct directly (already built)
    cert.toBeSigned = tbs;

    // Signature
    auto* asn_sig = asn_calloc<Signature_t>();
    asn_sig->present = Signature_PR_ecdsaNistP256Signature;

    auto* ecdsa_sig = asn_calloc<EcdsaP256Signature_t>();

    auto* r_point = asn_calloc<EccP256CurvePoint_t>();
    r_point->present = EccP256CurvePoint_PR_x_only;
    octet::set(&r_point->choice.x_only, sig_opt->r.data(), kP256ScalarLen);
    ecdsa_sig->rSig = r_point;

    octet::set(&ecdsa_sig->sSig, sig_opt->s.data(), kP256ScalarLen);

    asn_sig->choice.ecdsaNistP256Signature = ecdsa_sig;
    cert.signature = asn_sig;

    // Encode full cert to COER → cert_bytes (wire format)
    auto cert_bytes = coer::encode(&asn_DEF_CertificateBase, &cert);
    ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_CertificateBase, &cert);

    if (cert_bytes.empty()) return std::nullopt;

    // Build CertInfo
    CertInfo ci;
    ci.cert_bytes = cert_bytes; // COER wire bytes
    ci.hashed_id_8 = cert::compute_hid8(cert_bytes); // HID8 = SHA-256(COER) last 8
    ci.public_key = subject_public_key;
    ci.is_self_signed = is_self_signed;
    ci.tbs_bytes = tbs_coer; // TBS COER for signature verify
    ci.signature_r = sig_opt->r;
    ci.signature_s = sig_opt->s;
    ci.label = name;

    if (is_self_signed) {
        ci.issuer_hash_id_8 = {};
    } else {
        ci.issuer_hash_id_8 = issuer_hid8;
    }

    return ci;
}

std::optional<CertInfo> build_root_cert(const std::string& name,
                                        const std::vector<uint8_t>& public_key,
                                        const std::vector<uint8_t>& private_key) {

    return build_signed_cert(name, public_key, private_key, {}, /*is_ca=*/true,
                             /*is_self_signed=*/true);
}

} // namespace cert_utils
} // namespace v2xpki
