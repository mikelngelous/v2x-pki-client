// Tests for the revocation store (TS 102 941 §6.3.3).

#include <gtest/gtest.h>

#include "v2xpki/revocation.hpp"
#include "v2xpki/trust_chain.hpp"
#include "v2xpki/crypto_ec.hpp"

using namespace v2xpki;

namespace {

std::array<uint8_t, 8> hid(uint8_t tag) { return {tag, 1, 2, 3, 4, 5, 6, 7}; }

CrlContents crl_for(const std::array<uint8_t, 8>& issuer,
                    std::vector<std::array<uint8_t, 8>> revoked, uint32_t next_update = 0) {
    CrlContents c;
    c.issuer_hid8 = issuer;
    c.revoked = std::move(revoked);
    c.next_update = next_update;
    return c;
}

} // namespace

TEST(RevocationStoreTest, ReportsRevokedCert) {
    RevocationStore store;
    ASSERT_TRUE(store.apply(crl_for(hid(0xAA), {hid(0x01), hid(0x02)})));

    EXPECT_TRUE(store.is_revoked(hid(0xAA), hid(0x01)));
    EXPECT_TRUE(store.is_revoked(hid(0xAA), hid(0x02)));
    EXPECT_FALSE(store.is_revoked(hid(0xAA), hid(0x03)));
}

TEST(RevocationStoreTest, RevocationIsScopedToIssuer) {
    RevocationStore store;
    ASSERT_TRUE(store.apply(crl_for(hid(0xAA), {hid(0x01)})));

    EXPECT_TRUE(store.is_revoked(hid(0xAA), hid(0x01)));
    EXPECT_FALSE(store.is_revoked(hid(0xBB), hid(0x01)));
}

TEST(RevocationStoreTest, UnknownIssuerIsNotRevoked) {
    RevocationStore store;
    EXPECT_FALSE(store.is_revoked(hid(0xAA), hid(0x01)));
}

// Pins the non-conformance documented on RevocationStore::apply. Expected to fail — and to be
// rewritten — when the store becomes union-only.
TEST(RevocationStoreTest, ReplacingIssuerSetReinstatesCerts_KnownNonConformance) {
    RevocationStore store;
    ASSERT_TRUE(store.apply(crl_for(hid(0xAA), {hid(0x01), hid(0x02)})));
    ASSERT_TRUE(store.apply(crl_for(hid(0xAA), {hid(0x02)})));

    EXPECT_FALSE(store.is_revoked(hid(0xAA), hid(0x01)));
    EXPECT_TRUE(store.is_revoked(hid(0xAA), hid(0x02)));
}

TEST(RevocationStoreTest, IssuersAreIndependent) {
    RevocationStore store;
    ASSERT_TRUE(store.apply(crl_for(hid(0xAA), {hid(0x01)})));
    ASSERT_TRUE(store.apply(crl_for(hid(0xBB), {hid(0x02)})));

    EXPECT_EQ(store.issuer_count(), 2u);
    EXPECT_TRUE(store.is_revoked(hid(0xAA), hid(0x01)));
    EXPECT_TRUE(store.is_revoked(hid(0xBB), hid(0x02)));
}

TEST(RevocationStoreTest, RejectsStaleCrl) {
    RevocationStore store;
    auto stale = crl_for(hid(0xAA), {hid(0x01)}, /*next_update=*/1000);
    EXPECT_FALSE(store.apply(stale, /*now_tai=*/2000));
    EXPECT_FALSE(store.is_revoked(hid(0xAA), hid(0x01)));
}

TEST(RevocationStoreTest, AcceptsCrlStillFresh) {
    RevocationStore store;
    auto fresh = crl_for(hid(0xAA), {hid(0x01)}, /*next_update=*/5000);
    EXPECT_TRUE(store.apply(fresh, /*now_tai=*/2000));
    EXPECT_TRUE(store.is_revoked(hid(0xAA), hid(0x01)));
}

TEST(RevocationStoreTest, StaleCrlDoesNotClobberExistingState) {
    RevocationStore store;
    ASSERT_TRUE(store.apply(crl_for(hid(0xAA), {hid(0x01)}, 5000), 2000));
    EXPECT_FALSE(store.apply(crl_for(hid(0xAA), {}, 1000), 2000));

    EXPECT_TRUE(store.is_revoked(hid(0xAA), hid(0x01)));
}

TEST(RevocationStoreTest, NextUpdateZeroMeansNoExpiry) {
    RevocationStore store;
    EXPECT_TRUE(store.apply(crl_for(hid(0xAA), {hid(0x01)}, 0), 999999999));
    EXPECT_TRUE(store.is_revoked(hid(0xAA), hid(0x01)));
}
