// CertificateBase → CertInfo parser.

#include "cert_parse.hpp"
#include "coer.hpp"
#include "asn_ptr.hpp"
#include "curve_point.hpp"
#include "v2xpki/crypto_ec.hpp"
#include "v2xpki/sizes.hpp"
#include "v2xpki/static_bytes.hpp"

#include <algorithm>

extern "C" {
#include "CertificateBase.h"
#include "IssuerIdentifier.h"
#include "VerificationKeyIndicator.h"
#include "PublicVerificationKey.h"
#include "BasePublicEncryptionKey.h"
#include "ToBeSignedCertificate.h"
#include "ValidityPeriod.h"
#include "Duration.h"
}

namespace v2xpki::cert {

std::array<uint8_t, 8> compute_hid8(const std::vector<uint8_t> &cert_coer) {
    auto hash = crypto::hash_sha256(cert_coer);
    std::array<uint8_t, 8> hid8{};
    std::copy_n(hash.end() - kHashedId8Len, kHashedId8Len, hid8.begin());
    return hid8;
}

namespace {

// IEEE 1609.2 §6.4.10. Absent or unknown CHOICE → 0, which callers read as expired: fail closed.
uint64_t duration_seconds(const struct Duration *d) {
    if (!d) return 0;
    switch (d->present) {
        case Duration_PR_microseconds: return d->choice.microseconds / 1000000;
        case Duration_PR_milliseconds: return d->choice.milliseconds / 1000;
        case Duration_PR_seconds: return d->choice.seconds;
        case Duration_PR_minutes: return static_cast<uint64_t>(d->choice.minutes) * 60;
        case Duration_PR_hours: return static_cast<uint64_t>(d->choice.hours) * 3600;
        case Duration_PR_sixtyHours:
            return static_cast<uint64_t>(d->choice.sixtyHours) * kSixtyHoursSeconds;
        case Duration_PR_years: return static_cast<uint64_t>(d->choice.years) * kYearSeconds;
        default: return 0;
    }
}

} // namespace

CertInfo from_struct(const struct CertificateBase *cert, const std::vector<uint8_t> &cert_coer) {
    CertInfo ci;
    // Empty on overflow reuses the "decode failed" signal callers already check.
    if (auto cb = StaticBytes<kMaxCoerMessageLen>::from(cert_coer)) ci.cert_bytes = *cb;
    ci.hashed_id_8 = compute_hid8(cert_coer);

    // Issuer
    if (cert->issuer) {
        if (cert->issuer->present == IssuerIdentifier_PR_self) {
            ci.is_self_signed = true;
        } else if (cert->issuer->present == IssuerIdentifier_PR_sha256AndDigest) {
            ci.is_self_signed = false;
            auto issuer_bytes = octet::bytes(&cert->issuer->choice.sha256AndDigest);
            if (issuer_bytes.size() == kHashedId8Len) {
                std::copy_n(issuer_bytes.begin(), kHashedId8Len, ci.issuer_hash_id_8.begin());
            }
        } else if (cert->issuer->present == IssuerIdentifier_PR_sha384AndDigest) {
            ci.is_self_signed = false;
            auto issuer_bytes = octet::bytes(&cert->issuer->choice.sha384AndDigest);
            if (issuer_bytes.size() == kHashedId8Len) {
                std::copy_n(issuer_bytes.begin(), kHashedId8Len, ci.issuer_hash_id_8.begin());
            }
        }
    }

    // Verification key — detect curve from ASN.1 CHOICE variant
    if (cert->toBeSigned && cert->toBeSigned->verifyKeyIndicator) {
        auto *vki = cert->toBeSigned->verifyKeyIndicator;
        if (vki->present == VerificationKeyIndicator_PR_verificationKey &&
            vki->choice.verificationKey) {
            auto *pvk = vki->choice.verificationKey;
            if (pvk->present == PublicVerificationKey_PR_ecdsaNistP256 &&
                pvk->choice.ecdsaNistP256) {
                if (auto pk = StaticBytes<
                        kP384PublicKeyLen>::from(point::to_sec1(pvk->choice.ecdsaNistP256)))
                    ci.public_key = *pk;
                ci.curve = Curve::NistP256;
            } else if (pvk->present == PublicVerificationKey_PR_ecdsaBrainpoolP256r1 &&
                       pvk->choice.ecdsaBrainpoolP256r1) {
                if (auto pk = StaticBytes<
                        kP384PublicKeyLen>::from(point::to_sec1(pvk->choice.ecdsaBrainpoolP256r1)))
                    ci.public_key = *pk;
                ci.curve = Curve::BrainpoolP256r1;
            } else if (pvk->present == PublicVerificationKey_PR_ecdsaBrainpoolP384r1 &&
                       pvk->choice.ecdsaBrainpoolP384r1) {
                if (auto pk = StaticBytes<kP384PublicKeyLen>::
                        from(point::to_sec1_384(pvk->choice.ecdsaBrainpoolP384r1)))
                    ci.public_key = *pk;
                ci.curve = Curve::BrainpoolP384r1;
            } else if (pvk->present == PublicVerificationKey_PR_ecdsaNistP384 &&
                       pvk->choice.ecdsaNistP384) {
                if (auto pk = StaticBytes<
                        kP384PublicKeyLen>::from(point::to_sec1_384(pvk->choice.ecdsaNistP384)))
                    ci.public_key = *pk;
                ci.curve = Curve::NistP384;
            }
        }
    }

    // Encryption key — handle both NIST and Brainpool P-256 ECIES
    if (cert->toBeSigned && cert->toBeSigned->encryptionKey &&
        cert->toBeSigned->encryptionKey->publicKey) {
        auto *bpek = cert->toBeSigned->encryptionKey->publicKey;
        if (bpek->present == BasePublicEncryptionKey_PR_eciesNistP256 &&
            bpek->choice.eciesNistP256) {
            if (auto ek = StaticBytes<kP256PublicKeyLen>::from(point::to_sec1(bpek->choice
                                                                                  .eciesNistP256)))
                ci.encryption_key = *ek;
            ci.enc_curve = Curve::NistP256;
        } else if (bpek->present == BasePublicEncryptionKey_PR_eciesBrainpoolP256r1 &&
                   bpek->choice.eciesBrainpoolP256r1) {
            if (auto ek = StaticBytes<
                    kP256PublicKeyLen>::from(point::to_sec1(bpek->choice.eciesBrainpoolP256r1)))
                ci.encryption_key = *ek;
            ci.enc_curve = Curve::BrainpoolP256r1;
        }
    }

    if (cert->toBeSigned && cert->toBeSigned->validityPeriod) {
        ci.validity_start = static_cast<uint32_t>(cert->toBeSigned->validityPeriod->start);
        ci.validity_duration_seconds = duration_seconds(cert->toBeSigned->validityPeriod->duration);
    }

    // TBS bytes (for signature verification)
    if (cert->toBeSigned) {
        if (auto tb = StaticBytes<
                kMaxCoerMessageLen>::from(coer::encode(&asn_DEF_ToBeSignedCertificate,
                                                       cert->toBeSigned)))
            ci.tbs_bytes = *tb;
    }

    // Signature (multi-curve: extract_sig detects the curve)
    if (cert->signature) {
        point::SigRS rs;
        if (point::extract_sig(cert->signature, rs)) {
            auto r = StaticBytes<kP384ScalarLen>::from(rs.r);
            auto s = StaticBytes<kP384ScalarLen>::from(rs.s);
            if (r) ci.signature_r = *r;
            if (s) ci.signature_s = *s;
        }
    }

    return ci;
}

CertInfo from_coer(const std::vector<uint8_t> &cert_coer) {
    auto cert = asn_decode<CertificateBase_t>(asn_DEF_CertificateBase, cert_coer.data(),
                                              cert_coer.size());
    if (!cert) return {};

    auto ci = from_struct(cert.get(), cert_coer);
    return ci;
}

} // namespace v2xpki::cert
