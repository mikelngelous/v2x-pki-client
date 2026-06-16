// test_trust_list.cpp — unit tests for CCMS trust list decode (CtlFormat).

#include <gtest/gtest.h>

#include "v2xpki/trust_list.hpp"
#include "v2xpki/crypto_ec.hpp"

using namespace v2xpki;

TEST(TrustListTest, Hid8HexUpper) {
    std::array<uint8_t, 8> h = {0x74, 0x53, 0x4B, 0x8C, 0x39, 0x47, 0x79, 0xF4};
    EXPECT_EQ(hid8_hex_upper(h), "74534B8C394779F4");

    std::array<uint8_t, 8> z = {};
    EXPECT_EQ(hid8_hex_upper(z), "0000000000000000");
}

TEST(TrustListTest, ParseHid8Hex) {
    auto r = parse_hid8_hex("74534B8C394779F4");
    ASSERT_TRUE(r.has_value());
    EXPECT_EQ((*r)[0], 0x74);
    EXPECT_EQ((*r)[7], 0xF4);
    EXPECT_EQ(hid8_hex_upper(*r), "74534B8C394779F4");

    auto r2 = parse_hid8_hex("74534b8c394779f4");
    EXPECT_TRUE(r2.has_value());

    EXPECT_FALSE(parse_hid8_hex("ABCDEF").has_value());
    EXPECT_FALSE(parse_hid8_hex("ZZZZZZZZZZZZZZZZ").has_value());
}

TEST(TrustListTest, TrustTopologyDefaults) {
    TrustTopology topo;
    EXPECT_EQ(topo.ectl_next_update, 0u);
    EXPECT_EQ(topo.ctl_next_update, 0u);
    EXPECT_FALSE(topo.ectl_expired);
    EXPECT_FALSE(topo.ctl_expired);
    EXPECT_FALSE(topo.ectl_signature_verified);
    EXPECT_FALSE(topo.ctl_signature_verified);
}

TEST(TrustListTest, DecodeGarbage) {
    std::vector<uint8_t> empty;
    auto r1 = decode_ectl(empty);
    EXPECT_FALSE(r1.has_value());
    EXPECT_EQ(r1.error(), Error::Decode);

    std::vector<uint8_t> garbage = {0x00, 0x01, 0x02, 0x03};
    auto r2 = decode_ectl(garbage);
    EXPECT_FALSE(r2.has_value());
    EXPECT_EQ(r2.error(), Error::Decode);

    auto r3 = decode_rca_ctl(empty);
    EXPECT_FALSE(r3.has_value());
    EXPECT_EQ(r3.error(), Error::Decode);

    auto r4 = decode_rca_ctl(garbage);
    EXPECT_FALSE(r4.has_value());
    EXPECT_EQ(r4.error(), Error::Decode);
}
