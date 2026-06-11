// Curve point ↔ SEC1 byte vector conversions (P-256 and P-384).

#pragma once

#include <cstdint>
#include <vector>

#include "v2xpki/sizes.hpp"

extern "C" {
#include "EccP256CurvePoint.h"
#include "EccP384CurvePoint.h"
#include "Signature.h"
}

namespace v2xpki::point {

// --- P-256 ---

std::vector<uint8_t> to_sec1(const EccP256CurvePoint_t *pt);
std::vector<uint8_t> sig_r(const EccP256CurvePoint_t *pt);
EccP256CurvePoint_t *from_sec1(const std::vector<uint8_t> &pubkey);
EccP256CurvePoint_t *from_sec1_uncompressed(const std::vector<uint8_t> &pubkey);

// --- P-384 ---

std::vector<uint8_t> to_sec1_384(const EccP384CurvePoint_t *pt);
std::vector<uint8_t> sig_r_384(const EccP384CurvePoint_t *pt);
EccP384CurvePoint_t *from_sec1_384(const std::vector<uint8_t> &pubkey);

// --- Signature extraction (multi-curve) ---

struct SigRS {
    std::vector<uint8_t> r, s;
    Curve curve = Curve::NistP256;
};
bool extract_sig(const Signature_t *sig, SigRS &out);

} // namespace v2xpki::point
