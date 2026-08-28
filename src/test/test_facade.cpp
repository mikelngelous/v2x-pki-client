// Tests for PkiClient facade + HID8 COER verification.

#include <gtest/gtest.h>

#include <chrono>
#include "v2xpki/facade.hpp"
#include "v2xpki/crypto_ec.hpp"
#include "v2xpki/trust_chain.hpp"

extern "C" {
#include "CertificateBase.h"
#include "asn_application.h"
}

#include <algorithm>
#include <filesystem>
#include <fstream>

using namespace v2xpki;

class FacadeTest : public ::testing::Test {
protected:
    static KeyPair rca_keys_;
    static CertInfo rca_cert_;
    static bool pool_ok_;
    static std::string trust_dir_;
    static std::string keys_dir_;

    static void SetUpTestSuite() {
        namespace fs = std::filesystem;
        auto tmp = fs::temp_directory_path() / "pki_facade_test";
        fs::create_directories(tmp / "certs");
        fs::create_directories(tmp / "keys");
        trust_dir_ = (tmp / "certs").string();
        keys_dir_ = (tmp / "keys").string();

        auto rca = crypto::generate_keypair();
        if (!rca) return;
        rca_keys_ = *rca;

        auto rca_cert = cert_utils::build_root_cert("rca_test", rca->public_key.to_vector(),
                                                    rca->private_key.to_vector());
        if (!rca_cert) return;
        rca_cert_ = *rca_cert;

        std::ofstream ofs(trust_dir_ + "/rca_test.cert", std::ios::binary);
        ofs.write(reinterpret_cast<const char *>(rca_cert_.cert_bytes.data()),
                  static_cast<std::streamsize>(rca_cert_.cert_bytes.size()));
        ofs.close();

        pool_ok_ = true;
    }

    static void TearDownTestSuite() {
        namespace fs = std::filesystem;
        auto tmp = fs::temp_directory_path() / "pki_facade_test";
        fs::remove_all(tmp);
    }
};

KeyPair FacadeTest::rca_keys_;
CertInfo FacadeTest::rca_cert_;
bool FacadeTest::pool_ok_ = false;
std::string FacadeTest::trust_dir_;
std::string FacadeTest::keys_dir_;

TEST_F(FacadeTest, ConstructOk) {
    ASSERT_TRUE(pool_ok_);
    PkiClientConfig cfg;
    cfg.ea_url = "http://localhost:1/ec-request";
    cfg.aa_url = "http://localhost:1/at-request";
    cfg.tlm_url = "http://localhost:1";
    cfg.trust_dir = trust_dir_;
    cfg.keystore_dir = keys_dir_;
    cfg.timeout = std::chrono::seconds{3};
    cfg.verify_tls = false;

    PkiClient client(cfg);
    EXPECT_EQ(client.trust_chain().size(), 1u);
}

TEST_F(FacadeTest, TrustChainLoaded) {
    PkiClientConfig cfg;
    cfg.trust_dir = trust_dir_;
    cfg.keystore_dir = keys_dir_;
    cfg.verify_tls = false;

    PkiClient client(cfg);
    auto found = client.trust_chain().find_by_hashed_id_8(rca_cert_.hashed_id_8);
    ASSERT_TRUE(found.has_value());
    EXPECT_EQ(found->label, "rca_test");
}

TEST_F(FacadeTest, FetchTrustAnchorFail) {
    PkiClientConfig cfg;
    cfg.tlm_url = "http://localhost:1";
    cfg.trust_dir = trust_dir_;
    cfg.keystore_dir = keys_dir_;
    cfg.timeout = std::chrono::seconds{2};
    cfg.verify_tls = false;

    PkiClient client(cfg);
    auto result = client.fetch_trust_anchor();
    EXPECT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), Error::Network);
}

TEST_F(FacadeTest, FetchByHid8Fail) {
    PkiClientConfig cfg;
    cfg.tlm_url = "http://localhost:1";
    cfg.trust_dir = trust_dir_;
    cfg.keystore_dir = keys_dir_;
    cfg.timeout = std::chrono::seconds{2};
    cfg.verify_tls = false;

    PkiClient client(cfg);
    auto result = client.fetch_cert_by_hashed_id_8(rca_cert_.hashed_id_8);
    EXPECT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), Error::Network);
}

TEST_F(FacadeTest, EcRequestNoEa) {
    PkiClientConfig cfg;
    cfg.ea_url = "http://localhost:1/ec-request";
    cfg.trust_dir = trust_dir_;
    cfg.keystore_dir = keys_dir_;
    cfg.timeout = std::chrono::seconds{2};
    cfg.verify_tls = false;

    PkiClient client(cfg);

    auto canonical = crypto::generate_keypair();
    ASSERT_TRUE(canonical.has_value());
    auto handle = *KeyHandle::from("canonical_test");
    client.key_store().store_keypair(handle, *canonical);

    EcRecord rec;
    rec.canonical_public_key = canonical->public_key;
    rec.ea_hashed_id_8 = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    rec.requested_psids = {36};
    rec.validity_period_days = 30;

    auto result = client.request_enrolment_credential(handle, rec);
    EXPECT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), Error::NotFound);
}

TEST_F(FacadeTest, AtRequestNoAa) {
    PkiClientConfig cfg;
    cfg.aa_url = "http://localhost:1/at-request";
    cfg.trust_dir = trust_dir_;
    cfg.keystore_dir = keys_dir_;
    cfg.timeout = std::chrono::seconds{2};
    cfg.verify_tls = false;

    PkiClient client(cfg);

    auto ec = crypto::generate_keypair();
    ASSERT_TRUE(ec.has_value());
    auto handle = *KeyHandle::from("ec_test");
    client.key_store().store_keypair(handle, *ec);

    AtRecord rec;
    rec.at_public_key = ec->public_key;
    rec.aa_hashed_id_8 = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    rec.ea_hashed_id_8 = rca_cert_.hashed_id_8;
    rec.requested_psids = {36};
    rec.validity_period_hours = 24;

    CertInfo dummy_ec;
    dummy_ec.public_key = ec->public_key;
    auto at_handle = *KeyHandle::from("at_test");
    auto result = client.request_authorization_ticket(handle, dummy_ec, at_handle, rec);
    EXPECT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), Error::NotFound);
}

TEST_F(FacadeTest, FetchByNameFail) {
    PkiClientConfig cfg;
    cfg.tlm_url = "http://localhost:1";
    cfg.keystore_dir = keys_dir_;
    cfg.timeout = std::chrono::seconds{2};
    cfg.verify_tls = false;

    PkiClient client(cfg);
    auto result = client.fetch_cert_by_name("root");
    EXPECT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), Error::Network);
}

TEST_F(FacadeTest, Hid8CoerVsUper) {
    auto kp = crypto::generate_keypair();
    ASSERT_TRUE(kp.has_value());

    auto cert = cert_utils::build_root_cert("hid8_test", kp->public_key.to_vector(),
                                            kp->private_key.to_vector());
    ASSERT_TRUE(cert.has_value());

    auto coer_bytes = cert->cert_bytes;
    auto hid8_coer = cert->hashed_id_8;

    void *structure = nullptr;
    asn_dec_rval_t dr = asn_decode(nullptr, ATS_CANONICAL_OER, &asn_DEF_CertificateBase, &structure,
                                   coer_bytes.data(), coer_bytes.size());
    ASSERT_EQ(dr.code, RC_OK);

    if (structure) {
        void *uper_buf = nullptr;
        ssize_t uper_len = uper_encode_to_new_buffer(&asn_DEF_CertificateBase, nullptr, structure,
                                                     &uper_buf);
        ASSERT_GT(uper_len, 0);

        if (uper_buf) {
            std::vector<uint8_t> uper_bytes(static_cast<uint8_t *>(uper_buf),
                                            static_cast<uint8_t *>(uper_buf) + uper_len);

            EXPECT_NE(coer_bytes, uper_bytes);

            auto hash_uper = crypto::hash_sha256(uper_bytes);
            std::array<uint8_t, 8> hid8_uper{};
            std::copy_n(hash_uper.end() - 8, 8, hid8_uper.begin());
            EXPECT_NE(hid8_coer, hid8_uper);

            free(uper_buf);
        }
        ASN_STRUCT_FREE(asn_DEF_CertificateBase, structure);
    }
}

TEST_F(FacadeTest, Hid8CoerConsistency) {
    auto kp = crypto::generate_keypair();
    ASSERT_TRUE(kp.has_value());

    auto cert = cert_utils::build_root_cert("consistency_test", kp->public_key.to_vector(),
                                            kp->private_key.to_vector());
    ASSERT_TRUE(cert.has_value());

    auto original_hid8 = cert->hashed_id_8;
    auto original_bytes = cert->cert_bytes;

    void *structure2 = nullptr;
    asn_dec_rval_t dr2 = asn_decode(nullptr, ATS_CANONICAL_OER, &asn_DEF_CertificateBase,
                                    &structure2, original_bytes.data(), original_bytes.size());

    if (dr2.code == RC_OK && structure2) {
        auto res = asn_encode_to_new_buffer(nullptr, ATS_CANONICAL_OER, &asn_DEF_CertificateBase,
                                            structure2);
        if (res.buffer && res.result.encoded > 0) {
            std::vector<uint8_t> re_encoded(static_cast<uint8_t *>(res.buffer),
                                            static_cast<uint8_t *>(res.buffer) +
                                                res.result.encoded);

            EXPECT_EQ(re_encoded, original_bytes);

            auto re_hash = crypto::hash_sha256(re_encoded);
            std::array<uint8_t, 8> re_hid8{};
            std::copy_n(re_hash.end() - 8, 8, re_hid8.begin());
            EXPECT_EQ(re_hid8, original_hid8);

            free(res.buffer);
        }
        ASN_STRUCT_FREE(asn_DEF_CertificateBase, structure2);
    }
}

TEST_F(FacadeTest, LoadFromDirCoer) {
    PkiClientConfig cfg;
    cfg.trust_dir = trust_dir_;
    cfg.keystore_dir = keys_dir_;
    cfg.verify_tls = false;

    PkiClient client(cfg);
    auto found = client.trust_chain().find_by_hashed_id_8(rca_cert_.hashed_id_8);
    ASSERT_TRUE(found.has_value());
    EXPECT_EQ(found->cert_bytes, rca_cert_.cert_bytes);
    EXPECT_EQ(found->hashed_id_8, rca_cert_.hashed_id_8);
}
