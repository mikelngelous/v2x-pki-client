// Roundtrip: SEC1 uncompressed -> EccPxxxCurvePoint compressed CHOICE -> SEC1 compressed.
// A fixed parity selector would still pass any single fixed-parity fixture.

#include <gtest/gtest.h>

#include "v2xpki/crypto_ec.hpp"

#include "internal/curve_point.hpp"
#include "internal/asn_ptr.hpp"

extern "C" {
#include "EccP256CurvePoint.h"
#include "EccP384CurvePoint.h"
}

using namespace v2xpki;

namespace {
constexpr int kIterations = 500;
}

TEST(CurvePointRoundtrip, P256CompressedParityMatchesY) {
    for (int i = 0; i < kIterations; ++i) {
        auto kp = crypto::generate_keypair(Curve::NistP256);
        ASSERT_TRUE(kp.has_value());
        auto pubkey = kp->public_key.to_vector();
        ASSERT_EQ(pubkey.size(), 65u);

        bool y_odd = (pubkey[64] & 1) != 0;

        auto* pt = point::from_sec1(pubkey);
        ASSERT_NE(pt, nullptr);
        auto compressed = point::to_sec1(pt);
        ASN_STRUCT_FREE(asn_DEF_EccP256CurvePoint, pt);

        ASSERT_EQ(compressed.size(), 33u) << "iteration " << i;
        EXPECT_EQ(compressed[0], y_odd ? 0x03 : 0x02) << "iteration " << i;
        EXPECT_TRUE(std::equal(compressed.begin() + 1, compressed.end(), pubkey.begin() + 1))
            << "X mismatch at iteration " << i;
    }
}

TEST(CurvePointRoundtrip, P384CompressedParityMatchesY) {
    for (int i = 0; i < kIterations; ++i) {
        auto kp = crypto::generate_keypair(Curve::BrainpoolP384r1);
        ASSERT_TRUE(kp.has_value());
        auto pubkey = kp->public_key.to_vector();
        ASSERT_EQ(pubkey.size(), 97u);

        bool y_odd = (pubkey[96] & 1) != 0;

        auto* pt = point::from_sec1_384(pubkey);
        ASSERT_NE(pt, nullptr);
        auto compressed = point::to_sec1_384(pt);
        ASN_STRUCT_FREE(asn_DEF_EccP384CurvePoint, pt);

        ASSERT_EQ(compressed.size(), 49u) << "iteration " << i;
        EXPECT_EQ(compressed[0], y_odd ? 0x03 : 0x02) << "iteration " << i;
        EXPECT_TRUE(std::equal(compressed.begin() + 1, compressed.end(), pubkey.begin() + 1))
            << "X mismatch at iteration " << i;
    }
}
