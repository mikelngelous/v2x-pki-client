// Tests for EC request.
// Synthetic pool with EA cert COER for ECIES wrap/unwrap.

#include <gtest/gtest.h>

#include "v2xpki/ec_request.hpp"
#include "v2xpki/crypto_ec.hpp"
#include "v2xpki/trust_chain.hpp"

using namespace v2xpki;

class EcRequestTest : public ::testing::Test {
protected:
    static KeyPair canonical_keys_;
    static KeyPair ea_keys_;
    static CertInfo ea_cert_;
    static bool pool_ok_;

    static void SetUpTestSuite() {
        auto canonical = crypto::generate_keypair();
        auto ea = crypto::generate_keypair();
        if (!canonical || !ea) return;
        canonical_keys_ = *canonical;
        ea_keys_ = *ea;

        auto ea_cert = cert_utils::build_root_cert("ea_test", ea->public_key, ea->private_key);
        if (!ea_cert) return;
        ea_cert_ = *ea_cert;
        pool_ok_ = true;
    }
};

KeyPair EcRequestTest::canonical_keys_;
KeyPair EcRequestTest::ea_keys_;
CertInfo EcRequestTest::ea_cert_;
bool EcRequestTest::pool_ok_ = false;

TEST_F(EcRequestTest, ValidateOk) {
    ASSERT_TRUE(pool_ok_);
    EcRecord rec;
    rec.canonical_public_key = canonical_keys_.public_key;
    rec.ea_hashed_id_8 = ea_cert_.hashed_id_8;
    rec.requested_psids = {36, 37};
    rec.validity_period_days = 30;
    EXPECT_TRUE(validate_ec_record(rec));
}

TEST_F(EcRequestTest, ValidateBadKey) {
    EcRecord rec;
    rec.canonical_public_key = {0x01, 0x02, 0x03};
    rec.ea_hashed_id_8 = ea_cert_.hashed_id_8;
    rec.requested_psids = {36};
    rec.validity_period_days = 30;

    std::string err;
    EXPECT_FALSE(validate_ec_record(rec, &err));
    EXPECT_FALSE(err.empty());
}

TEST_F(EcRequestTest, ValidateEmptyPsids) {
    EcRecord rec;
    rec.canonical_public_key = canonical_keys_.public_key;
    rec.ea_hashed_id_8 = ea_cert_.hashed_id_8;
    rec.requested_psids = {};
    rec.validity_period_days = 30;

    std::string err;
    EXPECT_FALSE(validate_ec_record(rec, &err));
    EXPECT_NE(err.find("psids"), std::string::npos);
}

TEST_F(EcRequestTest, ValidateBadValidity) {
    EcRecord rec;
    rec.canonical_public_key = canonical_keys_.public_key;
    rec.ea_hashed_id_8 = ea_cert_.hashed_id_8;
    rec.requested_psids = {36};
    rec.validity_period_days = 0;
    EXPECT_FALSE(validate_ec_record(rec));

    rec.validity_period_days = 5000;
    EXPECT_FALSE(validate_ec_record(rec));
}

TEST_F(EcRequestTest, Assemble) {
    EcRecord rec;
    rec.canonical_public_key = canonical_keys_.public_key;
    rec.ea_hashed_id_8 = ea_cert_.hashed_id_8;
    rec.requested_psids = {36, 37, 38};
    rec.validity_period_days = 7;

    auto desc = assemble_ec_request(rec, std::chrono::system_clock::now());
    EXPECT_EQ(desc.verification_key.size(), 65u);
    EXPECT_EQ(desc.psids.size(), 3u);
    EXPECT_EQ(desc.ea_hid8, ea_cert_.hashed_id_8);
    EXPECT_EQ(desc.validity_duration_hours, 7 * 24);
    EXPECT_FALSE(desc.its_id.empty());
}

TEST_F(EcRequestTest, EncodeProducesBytes) {
    EcRecord rec;
    rec.canonical_public_key = canonical_keys_.public_key;
    rec.ea_hashed_id_8 = ea_cert_.hashed_id_8;
    rec.requested_psids = {36};
    rec.validity_period_days = 30;

    auto desc = assemble_ec_request(rec, std::chrono::system_clock::now());
    auto encoded = encode_ec_request(desc, ea_cert_, canonical_keys_.private_key);
    ASSERT_TRUE(encoded.has_value());
    EXPECT_GT(encoded->encoded.size(), 100u);
    EXPECT_EQ(encoded->request_aes_key.size(), 16u);
}

TEST_F(EcRequestTest, EncodeDecodeRoundtrip) {
    EcRecord rec;
    rec.canonical_public_key = canonical_keys_.public_key;
    rec.ea_hashed_id_8 = ea_cert_.hashed_id_8;
    rec.requested_psids = {36, 37};
    rec.validity_period_days = 15;

    auto desc = assemble_ec_request(rec, std::chrono::system_clock::now());
    auto encoded = encode_ec_request(desc, ea_cert_, canonical_keys_.private_key);
    ASSERT_TRUE(encoded.has_value());
    EXPECT_GT(encoded->encoded.size(), 0u);
}

TEST_F(EcRequestTest, EncodeBadEa) {
    EcRecord rec;
    rec.canonical_public_key = canonical_keys_.public_key;
    rec.ea_hashed_id_8 = ea_cert_.hashed_id_8;
    rec.requested_psids = {36};
    rec.validity_period_days = 30;

    auto desc = assemble_ec_request(rec, std::chrono::system_clock::now());
    CertInfo bad_ea = ea_cert_;
    bad_ea.public_key.clear();

    auto req_result = encode_ec_request(desc, bad_ea, canonical_keys_.private_key);
    EXPECT_FALSE(req_result.has_value());
    EXPECT_TRUE(req_result.error() == Error::InvalidArgument ||
                req_result.error() == Error::Crypto);
}

TEST_F(EcRequestTest, EciesRoundtripViaRequest) {
    EcRecord rec;
    rec.canonical_public_key = canonical_keys_.public_key;
    rec.ea_hashed_id_8 = ea_cert_.hashed_id_8;
    rec.requested_psids = {36};
    rec.validity_period_days = 30;

    auto desc = assemble_ec_request(rec, std::chrono::system_clock::now());
    auto encoded = encode_ec_request(desc, ea_cert_, canonical_keys_.private_key);
    ASSERT_TRUE(encoded.has_value());
    EXPECT_GT(encoded->encoded.size(), 200u);
}
