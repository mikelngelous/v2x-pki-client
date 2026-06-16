// test_dc_url.cpp — URL composition and multi-RCA DcEntry mapping tests.

#include <gtest/gtest.h>

#include "v2xpki/trust_list.hpp"

#include <string>

using namespace v2xpki;

// Reproduce the inline normalization from pki_client.cpp discover_trust
static std::string compose_ctl_url(const std::string& raw_dc_url, const std::string& rca_hid8_hex) {
    std::string base = raw_dc_url;
    if (!base.empty() && base.back() == '/') base.pop_back();
    return base + "/getctl/" + rca_hid8_hex;
}

static std::string compose_crl_url(const std::string& raw_dc_url, const std::string& rca_hex) {
    std::string base = raw_dc_url;
    if (!base.empty() && base.back() == '/') base.pop_back();
    return base + "/getcrl/" + rca_hex;
}

TEST(DcUrlTest, TrailingSlashStripped) {
    auto url = compose_ctl_url("https://dc.example.com/", "AABBCCDD11223344");
    EXPECT_EQ(url, "https://dc.example.com/getctl/AABBCCDD11223344");
}

TEST(DcUrlTest, NoTrailingSlashUnchanged) {
    auto url = compose_ctl_url("https://dc.example.com", "AABBCCDD11223344");
    EXPECT_EQ(url, "https://dc.example.com/getctl/AABBCCDD11223344");
}

TEST(DcUrlTest, NoDoubleSlash) {
    auto url1 = compose_ctl_url("https://dc.dev.etsi.c2x.isscms.com/", "B735AC70F6A82B2D");
    EXPECT_EQ(url1.find("//getctl"), std::string::npos);

    auto url2 = compose_ctl_url("https://0.example-dc.l0.example.org/", "1B5CB4BEBE6FE9E9");
    EXPECT_EQ(url2.find("//getctl"), std::string::npos);
}

TEST(DcUrlTest, CrlTrailingSlash) {
    auto url = compose_crl_url("https://dc.example.com/", "AABBCCDD11223344");
    EXPECT_EQ(url.find("//getcrl"), std::string::npos);
    EXPECT_EQ(url, "https://dc.example.com/getcrl/AABBCCDD11223344");
}

TEST(DcUrlTest, EmptyUrl) {
    auto url = compose_ctl_url("", "AABBCCDD11223344");
    EXPECT_EQ(url, "/getctl/AABBCCDD11223344");
}

TEST(DcUrlTest, MultiRcaLookup) {
    DcInfo dc;
    dc.url = "https://0.fr-dc.l0.c-its-pki.eu/";
    std::array<uint8_t, 8> rca1 = {0xB7, 0x35, 0xAC, 0x70, 0xF6, 0xA8, 0x2B, 0x2D};
    std::array<uint8_t, 8> rca2 = {0xA1, 0x33, 0x3B, 0x3F, 0x84, 0x89, 0xF6, 0x88};
    dc.serves.push_back(rca1);
    dc.serves.push_back(rca2);

    EXPECT_EQ(dc.serves.size(), 2u);

    bool found_rca1 = false, found_rca2 = false;
    for (const auto& served : dc.serves) {
        if (served == rca1) found_rca1 = true;
        if (served == rca2) found_rca2 = true;
    }
    EXPECT_TRUE(found_rca1);
    EXPECT_TRUE(found_rca2);
}

TEST(DcUrlTest, MultiRcaTopologyLookup) {
    TrustTopology topo;

    DcInfo dc1;
    dc1.url = "https://0.fr-dc.l0.c-its-pki.eu/";
    dc1.serves.push_back({0xB7, 0x35, 0xAC, 0x70, 0xF6, 0xA8, 0x2B, 0x2D});
    dc1.serves.push_back({0xA1, 0x33, 0x3B, 0x3F, 0x84, 0x89, 0xF6, 0x88});
    topo.dcs.push_back(dc1);

    DcInfo dc2;
    dc2.url = "https://0.eu-dc.l0.c-its-pki.eu/";
    dc2.serves.push_back({0x1B, 0x5C, 0xB4, 0xBE, 0xBE, 0x6F, 0xE9, 0xE9});
    dc2.serves.push_back({0xD8, 0x75, 0x15, 0x1D, 0xE8, 0xA4, 0x1E, 0xBD});
    topo.dcs.push_back(dc2);

    auto find_dc = [&](const std::array<uint8_t, 8>& rca_hid8) -> std::string {
        for (auto& dc : topo.dcs) {
            for (auto& served : dc.serves) {
                if (served == rca_hid8) return dc.url;
            }
        }
        return "";
    };

    EXPECT_EQ(find_dc({0xB7, 0x35, 0xAC, 0x70, 0xF6, 0xA8, 0x2B, 0x2D}), dc1.url);
    EXPECT_EQ(find_dc({0xA1, 0x33, 0x3B, 0x3F, 0x84, 0x89, 0xF6, 0x88}), dc1.url);
    EXPECT_EQ(find_dc({0x1B, 0x5C, 0xB4, 0xBE, 0xBE, 0x6F, 0xE9, 0xE9}), dc2.url);
    EXPECT_EQ(find_dc({0xD8, 0x75, 0x15, 0x1D, 0xE8, 0xA4, 0x1E, 0xBD}), dc2.url);
    EXPECT_TRUE(find_dc({0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}).empty());
}
