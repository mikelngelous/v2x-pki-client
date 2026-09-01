// Integration tests against Castell PROD (https://pki.skyv2x.com).
// Validates PkiClient E2E against real PKI infrastructure.

#include <gtest/gtest.h>

#include <chrono>
#include "v2xpki/facade.hpp"
#include "v2xpki/crypto_ec.hpp"
#include "v2xpki/http_client.hpp"
#include "v2xpki/trust_chain.hpp"
#include "v2xpki/trust_list.hpp"
#include "internal/cert_parse.hpp"

extern "C" {
#include "CertificateBase.h"
#include "Ieee1609Dot2Data.h"
#include "Ieee1609Dot2Content.h"
#include "SignedData.h"
#include "ToBeSignedData.h"
#include "SignedDataPayload.h"
#include "SignerIdentifier.h"
#include "Signature.h"
#include "EcdsaP256Signature.h"
#include "EccP256CurvePoint.h"
#include "HeaderInfo.h"
#include "asn_application.h"
}

#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/obj_mac.h>

#include <algorithm>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <sstream>

using namespace v2xpki;

static const char *CASTELL_URL = "https://pki.skyv2x.com";
static const char *RCA_HID8_HEX = "FA8B241AD2E9DBE7";
static const char *TLM_HID8_HEX = "0A065E9D1B8D241A";
static const char *MA_HID8_HEX = "1051D873785C203B";

static std::string bytes_to_hex_upper(const uint8_t *data, size_t len) {
    std::ostringstream oss;
    for (size_t i = 0; i < len; ++i)
        oss << std::hex << std::setfill('0') << std::setw(2) << std::uppercase
            << static_cast<int>(data[i]);
    return oss.str();
}

static std::string hid8_hex(const std::array<uint8_t, 8> &h) {
    return bytes_to_hex_upper(h.data(), 8);
}

static std::array<uint8_t, 8> compute_hid8(const std::vector<uint8_t> &cert_coer) {
    return cert::compute_hid8(cert_coer);
}

static std::string body_to_string(const std::vector<uint8_t> &body) {
    return {body.begin(), body.end()};
}

static std::vector<uint8_t> get_octet_bytes(const OCTET_STRING_t *os) {
    if (!os || !os->buf || os->size == 0) return {};
    return {os->buf, os->buf + os->size};
}

class CastellTest : public ::testing::Test {
protected:
    static HttpClient http_;
    static std::vector<uint8_t> rca_bytes_;
    static std::vector<uint8_t> tlm_bytes_;
    static std::vector<uint8_t> ma_bytes_;

    static void SetUpTestSuite() {
        auto rca = http_.get(std::string(CASTELL_URL) + "/trustanchor");
        if (rca && rca->status_code == 200) rca_bytes_ = rca->body;

        auto tlm = http_.get(std::string(CASTELL_URL) + "/tlm");
        if (tlm && tlm->status_code == 200) tlm_bytes_ = tlm->body;

        auto ma = http_.get(std::string(CASTELL_URL) + "/ma");
        if (ma && ma->status_code == 200) ma_bytes_ = ma->body;
    }
};

HttpClient CastellTest::http_(HttpClientConfig{"", std::chrono::seconds{15}, true});
std::vector<uint8_t> CastellTest::rca_bytes_;
std::vector<uint8_t> CastellTest::tlm_bytes_;
std::vector<uint8_t> CastellTest::ma_bytes_;

// ==================== Group A: Discovery ====================

TEST_F(CastellTest, A1_Healthz) {
    auto resp = http_.get(std::string(CASTELL_URL) + "/healthz");
    ASSERT_TRUE(resp.has_value());
    EXPECT_EQ(resp->status_code, 200);
    auto body = body_to_string(resp->body);
    EXPECT_NE(body.find("\"status\":\"ok\""), std::string::npos);
    EXPECT_NE(body.find("\"rca_hashedId8\":\"FA8B241AD2E9DBE7\""), std::string::npos);
}

TEST_F(CastellTest, A2_Version) {
    auto resp = http_.get(std::string(CASTELL_URL) + "/version");
    ASSERT_TRUE(resp.has_value());
    EXPECT_EQ(resp->status_code, 200);
    auto body = body_to_string(resp->body);
    EXPECT_NE(body.find("\"name\""), std::string::npos);
    EXPECT_NE(body.find("Castell"), std::string::npos);
}

TEST_F(CastellTest, A3_Capabilities) {
    auto resp = http_.get(std::string(CASTELL_URL) + "/capabilities");
    ASSERT_TRUE(resp.has_value());
    EXPECT_EQ(resp->status_code, 200);
    auto body = body_to_string(resp->body);
    EXPECT_NE(body.find("\"endpoints\""), std::string::npos);
    EXPECT_NE(body.find("\"trust_anchors\""), std::string::npos);
}

TEST_F(CastellTest, A4_TrustAnchor) {
    ASSERT_FALSE(rca_bytes_.empty());
    EXPECT_GE(rca_bytes_.size(), 380u);
    EXPECT_LE(rca_bytes_.size(), 440u);

    void *structure = nullptr;
    auto dr = asn_decode(nullptr, ATS_CANONICAL_OER, &asn_DEF_CertificateBase, &structure,
                         rca_bytes_.data(), rca_bytes_.size());
    ASSERT_EQ(dr.code, RC_OK);

    if (structure) {
        auto *cert = static_cast<CertificateBase_t *>(structure);
        bool is_self = cert->issuer && cert->issuer->present == IssuerIdentifier_PR_self;
        EXPECT_TRUE(is_self);
        ASN_STRUCT_FREE(asn_DEF_CertificateBase, structure);
    }
}

TEST_F(CastellTest, A5_Tlm) {
    ASSERT_FALSE(tlm_bytes_.empty());
    EXPECT_GE(tlm_bytes_.size(), 120u);
    EXPECT_LE(tlm_bytes_.size(), 200u);

    void *structure = nullptr;
    auto dr = asn_decode(nullptr, ATS_CANONICAL_OER, &asn_DEF_CertificateBase, &structure,
                         tlm_bytes_.data(), tlm_bytes_.size());
    EXPECT_EQ(dr.code, RC_OK);
    if (structure) ASN_STRUCT_FREE(asn_DEF_CertificateBase, structure);
}

TEST_F(CastellTest, A6_Ma) {
    ASSERT_FALSE(ma_bytes_.empty());
    EXPECT_GE(ma_bytes_.size(), 150u);
    EXPECT_LE(ma_bytes_.size(), 230u);

    void *structure = nullptr;
    auto dr = asn_decode(nullptr, ATS_CANONICAL_OER, &asn_DEF_CertificateBase, &structure,
                         ma_bytes_.data(), ma_bytes_.size());
    EXPECT_EQ(dr.code, RC_OK);
    if (structure) ASN_STRUCT_FREE(asn_DEF_CertificateBase, structure);
}

// ==================== Group B: HID8 Canonical Validation ====================

TEST_F(CastellTest, B1_Hid8Rca) {
    if (rca_bytes_.empty()) GTEST_SKIP() << "no RCA cert";

    auto calc_hid8 = compute_hid8(rca_bytes_);
    auto calc_hex = hid8_hex(calc_hid8);
    EXPECT_EQ(calc_hex, RCA_HID8_HEX);

    auto resp = http_.get(std::string(CASTELL_URL) + "/lookup/" + calc_hex);
    ASSERT_TRUE(resp.has_value());
    EXPECT_EQ(resp->status_code, 200);
    EXPECT_EQ(resp->body, rca_bytes_);
}

TEST_F(CastellTest, B2_Hid8Tlm) {
    if (tlm_bytes_.empty()) GTEST_SKIP() << "no TLM cert";

    auto calc_hid8 = compute_hid8(tlm_bytes_);
    auto calc_hex = hid8_hex(calc_hid8);
    EXPECT_EQ(calc_hex, TLM_HID8_HEX);

    auto resp = http_.get(std::string(CASTELL_URL) + "/lookup/" + calc_hex);
    ASSERT_TRUE(resp.has_value());
    EXPECT_EQ(resp->status_code, 200);
    EXPECT_EQ(resp->body, tlm_bytes_);
}

TEST_F(CastellTest, B3_Hid8Ma) {
    if (ma_bytes_.empty()) GTEST_SKIP() << "no MA cert";

    auto calc_hid8 = compute_hid8(ma_bytes_);
    auto calc_hex = hid8_hex(calc_hid8);
    EXPECT_EQ(calc_hex, MA_HID8_HEX);

    auto resp = http_.get(std::string(CASTELL_URL) + "/lookup/" + calc_hex);
    ASSERT_TRUE(resp.has_value());
    EXPECT_EQ(resp->status_code, 200);
    EXPECT_EQ(resp->body, ma_bytes_);
}

// ==================== Group C: Fetch by name ====================

TEST_F(CastellTest, C1_CertByNameRoot) {
    auto resp = http_.get(std::string(CASTELL_URL) + "/cert/root");
    ASSERT_TRUE(resp.has_value());
    EXPECT_EQ(resp->status_code, 200);
    if (!rca_bytes_.empty()) {
        EXPECT_EQ(resp->body, rca_bytes_);
    }
}

TEST_F(CastellTest, C2_CertByNameTlm) {
    auto resp = http_.get(std::string(CASTELL_URL) + "/cert/tlm");
    ASSERT_TRUE(resp.has_value());
    EXPECT_EQ(resp->status_code, 200);
    if (!tlm_bytes_.empty()) {
        EXPECT_EQ(resp->body, tlm_bytes_);
    }
}

// ==================== Group D: ECTL + CRL ====================

TEST_F(CastellTest, D1_Ectl) {
    auto resp = http_.get(std::string(CASTELL_URL) + "/getectl");
    ASSERT_TRUE(resp.has_value());
    EXPECT_EQ(resp->status_code, 200);
    EXPECT_GT(resp->body.size(), 100u);

    void *structure = nullptr;
    auto dr = asn_decode(nullptr, ATS_CANONICAL_OER, &asn_DEF_Ieee1609Dot2Data, &structure,
                         resp->body.data(), resp->body.size());
    ASSERT_EQ(dr.code, RC_OK);

    if (structure) {
        auto *outer = static_cast<Ieee1609Dot2Data_t *>(structure);
        EXPECT_EQ(outer->protocolVersion, 3);
        bool is_signed = outer->content &&
                         outer->content->present == Ieee1609Dot2Content_PR_signedData;
        EXPECT_TRUE(is_signed);

        if (is_signed && outer->content->choice.signedData) {
            auto *sd = outer->content->choice.signedData;

            if (sd->signer && sd->signer->present == SignerIdentifier_PR_digest) {
                auto signer_bytes = get_octet_bytes(&sd->signer->choice.digest);
                if (signer_bytes.size() == 8) {
                    auto signer_hex = bytes_to_hex_upper(signer_bytes.data(), 8);
                    EXPECT_EQ(signer_hex, TLM_HID8_HEX);
                }
            }
        }
        ASN_STRUCT_FREE(asn_DEF_Ieee1609Dot2Data, structure);
    }
}

TEST_F(CastellTest, D2_Crl) {
    auto resp = http_.get(std::string(CASTELL_URL) + "/getcrl/" + RCA_HID8_HEX);
    ASSERT_TRUE(resp.has_value());
    EXPECT_EQ(resp->status_code, 200);
    EXPECT_GT(resp->body.size(), 20u);

    void *structure = nullptr;
    auto dr = asn_decode(nullptr, ATS_CANONICAL_OER, &asn_DEF_Ieee1609Dot2Data, &structure,
                         resp->body.data(), resp->body.size());
    EXPECT_EQ(dr.code, RC_OK);

    if (dr.code == RC_OK && structure) {
        auto *outer = static_cast<Ieee1609Dot2Data_t *>(structure);
        EXPECT_EQ(outer->protocolVersion, 3);
        ASN_STRUCT_FREE(asn_DEF_Ieee1609Dot2Data, structure);
    }
}

TEST_F(CastellTest, D3_CrlDecodedAgainstRca) {
    if (rca_bytes_.empty()) GTEST_SKIP() << "no RCA cert";
    auto resp = http_.get(std::string(CASTELL_URL) + "/getcrl/" + RCA_HID8_HEX);
    ASSERT_TRUE(resp.has_value());
    ASSERT_EQ(resp->status_code, 200);

    auto rca = cert::from_coer(rca_bytes_);
    ASSERT_FALSE(rca.public_key.empty());

    auto crl = decode_crl(resp->body, rca.public_key.to_vector(), rca_bytes_);
    ASSERT_TRUE(crl) << "error " << static_cast<int>(crl.error());

    EXPECT_EQ(hid8_hex(crl->issuer_hid8), RCA_HID8_HEX);
    EXPECT_GT(crl->this_update, 0u);
    EXPECT_GT(crl->next_update, crl->this_update);
}

// ==================== Group E: Enrolment flow ====================

TEST_F(CastellTest, E1_EaCert) {
    auto resp = http_.get(std::string(CASTELL_URL) + "/cert/ea");
    ASSERT_TRUE(resp.has_value());
    EXPECT_EQ(resp->status_code, 200);
    EXPECT_GT(resp->body.size(), 100u);

    void *structure = nullptr;
    auto dr = asn_decode(nullptr, ATS_CANONICAL_OER, &asn_DEF_CertificateBase, &structure,
                         resp->body.data(), resp->body.size());
    EXPECT_EQ(dr.code, RC_OK);
    if (structure) ASN_STRUCT_FREE(asn_DEF_CertificateBase, structure);

    auto ea_hid8 = compute_hid8(resp->body);
    auto ea_hex = hid8_hex(ea_hid8);

    auto lookup = http_.get(std::string(CASTELL_URL) + "/lookup/" + ea_hex);
    ASSERT_TRUE(lookup.has_value());
    EXPECT_EQ(lookup->status_code, 200);
    EXPECT_EQ(lookup->body, resp->body);
}

TEST_F(CastellTest, E2_EcRequestToCastell) {
    namespace fs = std::filesystem;

    auto ea_resp = http_.get(std::string(CASTELL_URL) + "/cert/ea");
    if (!ea_resp || ea_resp->status_code != 200) {
        GTEST_SKIP() << "cannot fetch EA cert";
    }
    if (rca_bytes_.empty()) GTEST_SKIP() << "no RCA cert";

    auto tmp = fs::temp_directory_path() / "pki_integration_test";
    auto trust_dir = tmp / "certs";
    auto keys_dir = tmp / "keys";
    fs::create_directories(trust_dir);
    fs::create_directories(keys_dir);

    // validate_chain walks EC → EA → RCA, so both must be on disk.
    {
        std::ofstream ofs((trust_dir / "ea.cert").string(), std::ios::binary);
        ofs.write(reinterpret_cast<const char *>(ea_resp->body.data()),
                  static_cast<std::streamsize>(ea_resp->body.size()));
    }
    {
        std::ofstream ofs((trust_dir / "rca.cert").string(), std::ios::binary);
        ofs.write(reinterpret_cast<const char *>(rca_bytes_.data()),
                  static_cast<std::streamsize>(rca_bytes_.size()));
    }

    auto kp = crypto::generate_keypair();
    ASSERT_TRUE(kp.has_value());

    PkiClientConfig cfg;
    cfg.ea_url = std::string(CASTELL_URL) + "/ec-request";
    cfg.tlm_url = CASTELL_URL;
    cfg.trust_dir = trust_dir.string();
    cfg.keystore_dir = keys_dir.string();
    cfg.timeout = std::chrono::seconds{15};
    cfg.verify_tls = true;

    PkiClient client(cfg);

    auto handle = *KeyHandle::from("canonical_integration");
    client.key_store().store_keypair(handle, *kp);

    auto ea_hid8 = compute_hid8(ea_resp->body);

    EcRecord rec;
    rec.canonical_public_key = kp->public_key;
    rec.ea_hashed_id_8 = ea_hid8;
    rec.requested_psids = {36};
    rec.validity_period_days = 30;

    auto result = client.request_enrolment_credential(handle, rec);
    fs::remove_all(tmp);

    ASSERT_TRUE(result) << "EC request failed: error " << static_cast<int>(result.error());
    EXPECT_GT(result->cert_bytes.size(), 50u);
    EXPECT_EQ(result->issuer_hash_id_8, ea_hid8);
}

// ==================== Group F: Verify Hardening ====================

TEST_F(CastellTest, F1_RealCertSignatureVerify) {
    if (rca_bytes_.empty()) GTEST_SKIP() << "no RCA cert";
    auto rca = cert::from_coer(rca_bytes_);
    ASSERT_FALSE(rca.cert_bytes.empty());
    ASSERT_TRUE(rca.is_self_signed);
    TrustChain tc;
    // Self-signed RCA: verify using IEEE 1609.2 §5.3.1 double-hash
    EXPECT_TRUE(tc.verify_cert_signature(rca, rca));
}

TEST_F(CastellTest, F2_EctlSignerHid8Pinning) {
    if (tlm_bytes_.empty()) GTEST_SKIP() << "no TLM cert";

    // Fetch ECTL
    auto ectl_resp = http_.get(std::string(CASTELL_URL) + "/getectl/" + TLM_HID8_HEX);
    if (!ectl_resp || ectl_resp->status_code != 200) GTEST_SKIP() << "cannot fetch ECTL";

    auto tlm = cert::from_coer(tlm_bytes_);
    ASSERT_FALSE(tlm.public_key.empty());

    // Correct signer → should verify
    auto topo = decode_ectl(ectl_resp->body, tlm.public_key.to_vector(), tlm_bytes_);
    ASSERT_TRUE(topo.has_value());
    EXPECT_TRUE(topo->ectl_signature_verified);

    // Wrong signer cert bytes → HID8 pinning rejects
    if (!rca_bytes_.empty()) {
        auto topo_bad = decode_ectl(ectl_resp->body, tlm.public_key.to_vector(), rca_bytes_);
        ASSERT_TRUE(topo_bad.has_value());
        EXPECT_FALSE(topo_bad->ectl_signature_verified);
    }
}
