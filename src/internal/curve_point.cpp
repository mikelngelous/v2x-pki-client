// Curve point ↔ SEC1 byte vector conversions (P-256 and P-384).

#include "curve_point.hpp"
#include "asn_ptr.hpp"
#include "coer.hpp"
#include "v2xpki/sizes.hpp"

extern "C" {
#include "EcdsaP256Signature.h"
#include "EcdsaP384Signature.h"
}

namespace v2xpki::point {

// ============ P-256 ============

std::vector<uint8_t> to_sec1(const EccP256CurvePoint_t *pt) {
    if (!pt) return {};

    if (pt->present == EccP256CurvePoint_PR_uncompressedP256) {
        auto x = octet::bytes(&pt->choice.uncompressedP256.x);
        auto y = octet::bytes(&pt->choice.uncompressedP256.y);
        if (x.size() != kP256ScalarLen || y.size() != kP256ScalarLen) return {};
        std::vector<uint8_t> key;
        key.reserve(kP256PublicKeyLen);
        key.push_back(0x04);
        key.insert(key.end(), x.begin(), x.end());
        key.insert(key.end(), y.begin(), y.end());
        return key;
    }
    if (pt->present == EccP256CurvePoint_PR_x_only) {
        return octet::bytes(&pt->choice.x_only);
    }
    if (pt->present == EccP256CurvePoint_PR_compressed_y_0) {
        auto x = octet::bytes(&pt->choice.compressed_y_0);
        if (x.size() != kP256ScalarLen) return {};
        std::vector<uint8_t> key;
        key.reserve(kP256CompressedLen);
        key.push_back(0x02);
        key.insert(key.end(), x.begin(), x.end());
        return key;
    }
    if (pt->present == EccP256CurvePoint_PR_compressed_y_1) {
        auto x = octet::bytes(&pt->choice.compressed_y_1);
        if (x.size() != kP256ScalarLen) return {};
        std::vector<uint8_t> key;
        key.reserve(kP256CompressedLen);
        key.push_back(0x03);
        key.insert(key.end(), x.begin(), x.end());
        return key;
    }
    return {};
}

EccP256CurvePoint_t *from_sec1(const std::vector<uint8_t> &pubkey) {
    if (pubkey.size() != kP256PublicKeyLen) return nullptr;
    auto *pt = asn_calloc<EccP256CurvePoint_t>();
    bool y_odd = (pubkey[64] & 1) != 0;
    if (y_odd) {
        pt->present = EccP256CurvePoint_PR_compressed_y_1;
        octet::set(&pt->choice.compressed_y_1, pubkey.data() + 1, kP256ScalarLen);
    } else {
        pt->present = EccP256CurvePoint_PR_compressed_y_0;
        octet::set(&pt->choice.compressed_y_0, pubkey.data() + 1, kP256ScalarLen);
    }
    return pt;
}

EccP256CurvePoint_t *from_sec1_uncompressed(const std::vector<uint8_t> &pubkey) {
    if (pubkey.size() != kP256PublicKeyLen || pubkey[0] != 0x04) return nullptr;
    auto *pt = asn_calloc<EccP256CurvePoint_t>();
    pt->present = EccP256CurvePoint_PR_uncompressedP256;
    octet::set(&pt->choice.uncompressedP256.x, pubkey.data() + 1, kP256ScalarLen);
    octet::set(&pt->choice.uncompressedP256.y, pubkey.data() + 1 + kP256ScalarLen, kP256ScalarLen);
    return pt;
}

std::vector<uint8_t> sig_r(const EccP256CurvePoint_t *pt) {
    if (!pt) return {};
    if (pt->present == EccP256CurvePoint_PR_x_only) return octet::bytes(&pt->choice.x_only);
    if (pt->present == EccP256CurvePoint_PR_compressed_y_0)
        return octet::bytes(&pt->choice.compressed_y_0);
    if (pt->present == EccP256CurvePoint_PR_compressed_y_1)
        return octet::bytes(&pt->choice.compressed_y_1);
    if (pt->present == EccP256CurvePoint_PR_uncompressedP256)
        return octet::bytes(&pt->choice.uncompressedP256.x);
    return {};
}

// ============ P-384 ============

std::vector<uint8_t> to_sec1_384(const EccP384CurvePoint_t *pt) {
    if (!pt) return {};

    if (pt->present == EccP384CurvePoint_PR_uncompressedP384) {
        auto x = octet::bytes(&pt->choice.uncompressedP384.x);
        auto y = octet::bytes(&pt->choice.uncompressedP384.y);
        if (x.size() != kP384ScalarLen || y.size() != kP384ScalarLen) return {};
        std::vector<uint8_t> key;
        key.reserve(kP384PublicKeyLen);
        key.push_back(0x04);
        key.insert(key.end(), x.begin(), x.end());
        key.insert(key.end(), y.begin(), y.end());
        return key;
    }
    if (pt->present == EccP384CurvePoint_PR_x_only) {
        return octet::bytes(&pt->choice.x_only);
    }
    if (pt->present == EccP384CurvePoint_PR_compressed_y_0) {
        auto x = octet::bytes(&pt->choice.compressed_y_0);
        if (x.size() != kP384ScalarLen) return {};
        std::vector<uint8_t> key;
        key.reserve(kP384CompressedLen);
        key.push_back(0x02);
        key.insert(key.end(), x.begin(), x.end());
        return key;
    }
    if (pt->present == EccP384CurvePoint_PR_compressed_y_1) {
        auto x = octet::bytes(&pt->choice.compressed_y_1);
        if (x.size() != kP384ScalarLen) return {};
        std::vector<uint8_t> key;
        key.reserve(kP384CompressedLen);
        key.push_back(0x03);
        key.insert(key.end(), x.begin(), x.end());
        return key;
    }
    return {};
}

EccP384CurvePoint_t *from_sec1_384(const std::vector<uint8_t> &pubkey) {
    if (pubkey.size() != kP384PublicKeyLen) return nullptr;
    auto *pt = asn_calloc<EccP384CurvePoint_t>();
    bool y_odd = (pubkey[96] & 1) != 0;
    if (y_odd) {
        pt->present = EccP384CurvePoint_PR_compressed_y_1;
        octet::set(&pt->choice.compressed_y_1, pubkey.data() + 1, kP384ScalarLen);
    } else {
        pt->present = EccP384CurvePoint_PR_compressed_y_0;
        octet::set(&pt->choice.compressed_y_0, pubkey.data() + 1, kP384ScalarLen);
    }
    return pt;
}

std::vector<uint8_t> sig_r_384(const EccP384CurvePoint_t *pt) {
    if (!pt) return {};
    if (pt->present == EccP384CurvePoint_PR_x_only) return octet::bytes(&pt->choice.x_only);
    if (pt->present == EccP384CurvePoint_PR_compressed_y_0)
        return octet::bytes(&pt->choice.compressed_y_0);
    if (pt->present == EccP384CurvePoint_PR_compressed_y_1)
        return octet::bytes(&pt->choice.compressed_y_1);
    if (pt->present == EccP384CurvePoint_PR_uncompressedP384)
        return octet::bytes(&pt->choice.uncompressedP384.x);
    return {};
}

// ============ Signature extraction (multi-curve) ============

bool extract_sig(const Signature_t *sig, SigRS &out) {
    if (!sig) return false;

    // NIST P-256
    if (sig->present == Signature_PR_ecdsaNistP256Signature) {
        auto *ecdsa = sig->choice.ecdsaNistP256Signature;
        if (!ecdsa || !ecdsa->rSig) return false;
        out.s = octet::bytes(&ecdsa->sSig);
        if (out.s.size() != kP256ScalarLen) return false;
        out.r = sig_r(ecdsa->rSig);
        out.curve = Curve::NistP256;
        return out.r.size() == kP256ScalarLen;
    }

    // Brainpool P-256r1 (same ASN.1 type as NIST P-256: EcdsaP256Signature)
    if (sig->present == Signature_PR_ecdsaBrainpoolP256r1Signature) {
        auto *ecdsa = sig->choice.ecdsaBrainpoolP256r1Signature;
        if (!ecdsa || !ecdsa->rSig) return false;
        out.s = octet::bytes(&ecdsa->sSig);
        if (out.s.size() != kP256ScalarLen) return false;
        out.r = sig_r(ecdsa->rSig);
        out.curve = Curve::BrainpoolP256r1;
        return out.r.size() == kP256ScalarLen;
    }

    // Brainpool P-384r1 (EcdsaP384Signature with EccP384CurvePoint)
    if (sig->present == Signature_PR_ecdsaBrainpoolP384r1Signature) {
        auto *ecdsa = sig->choice.ecdsaBrainpoolP384r1Signature;
        if (!ecdsa || !ecdsa->rSig) return false;
        out.s = octet::bytes(&ecdsa->sSig);
        if (out.s.size() != kP384ScalarLen) return false;
        out.r = sig_r_384(ecdsa->rSig);
        out.curve = Curve::BrainpoolP384r1;
        return out.r.size() == kP384ScalarLen;
    }

    // NIST P-384 (EcdsaP384Signature)
    if (sig->present == Signature_PR_ecdsaNistP384Signature) {
        auto *ecdsa = sig->choice.ecdsaNistP384Signature;
        if (!ecdsa || !ecdsa->rSig) return false;
        out.s = octet::bytes(&ecdsa->sSig);
        if (out.s.size() != kP384ScalarLen) return false;
        out.r = sig_r_384(ecdsa->rSig);
        out.curve = Curve::NistP384;
        return out.r.size() == kP384ScalarLen;
    }

    return false;
}

} // namespace v2xpki::point
