// Tests for AT request.
// Synthetic pool with AA + EA + EC cert COER.

#include <gtest/gtest.h>

#include "v2xpki/at_request.hpp"
#include "v2xpki/crypto_ec.hpp"
#include "v2xpki/trust_chain.hpp"

using namespace v2xpki;

class AtRequestTest : public ::testing::Test {
protected:
    static KeyPair ec_keys_, at_keys_, aa_keys_, ea_keys_;
    static CertInfo aa_cert_, ea_cert_, ec_cert_;
    static bool pool_ok_;

    static void SetUpTestSuite() {
        auto ec = crypto::generate_keypair();
        auto at = crypto::generate_keypair();
        auto aa = crypto::generate_keypair();
        auto ea = crypto::generate_keypair();
        if (!ec || !at || !aa || !ea) return;
        ec_keys_ = *ec;
        at_keys_ = *at;
        aa_keys_ = *aa;
        ea_keys_ = *ea;

        auto ea_cert = cert_utils::build_root_cert("ea_test", ea->public_key.to_vector(),
                                                   ea->private_key.to_vector());
        if (!ea_cert) return;
        ea_cert_ = *ea_cert;

        auto aa_cert = cert_utils::build_root_cert("aa_test", aa->public_key.to_vector(),
                                                   aa->private_key.to_vector());
        if (!aa_cert) return;
        aa_cert_ = *aa_cert;

        auto ec_cert = cert_utils::build_signed_cert("ec_test", ec->public_key.to_vector(),
                                                     ea->private_key.to_vector(),
                                                     ea_cert_.hashed_id_8, false, false,
                                                     ea_cert_.cert_bytes.to_vector());
        if (!ec_cert) return;
        ec_cert_ = *ec_cert;

        pool_ok_ = true;
    }
};

KeyPair AtRequestTest::ec_keys_;
KeyPair AtRequestTest::at_keys_;
KeyPair AtRequestTest::aa_keys_;
KeyPair AtRequestTest::ea_keys_;
CertInfo AtRequestTest::aa_cert_;
CertInfo AtRequestTest::ea_cert_;
CertInfo AtRequestTest::ec_cert_;
bool AtRequestTest::pool_ok_ = false;

TEST_F(AtRequestTest, ValidateOk) {
    ASSERT_TRUE(pool_ok_);
    AtRecord rec;
    rec.at_public_key = at_keys_.public_key;
    rec.aa_hashed_id_8 = aa_cert_.hashed_id_8;
    rec.ea_hashed_id_8 = ea_cert_.hashed_id_8;
    rec.requested_psids = {36, 37};
    rec.validity_period_hours = 24;
    EXPECT_TRUE(validate_at_record(rec));
}

TEST_F(AtRequestTest, ValidateBadKey) {
    AtRecord rec;
    rec.at_public_key = *StaticBytes<kP384PublicKeyLen>::from(std::vector<uint8_t>{0x01});
    rec.aa_hashed_id_8 = aa_cert_.hashed_id_8;
    rec.ea_hashed_id_8 = ea_cert_.hashed_id_8;
    rec.requested_psids = {36};
    rec.validity_period_hours = 24;

    std::string err;
    EXPECT_FALSE(validate_at_record(rec, &err));
    EXPECT_FALSE(err.empty());
}

TEST_F(AtRequestTest, ValidateEmptyPsids) {
    AtRecord rec;
    rec.at_public_key = at_keys_.public_key;
    rec.aa_hashed_id_8 = aa_cert_.hashed_id_8;
    rec.ea_hashed_id_8 = ea_cert_.hashed_id_8;
    rec.requested_psids = {};
    rec.validity_period_hours = 24;
    EXPECT_FALSE(validate_at_record(rec));
}

TEST_F(AtRequestTest, ValidateBadValidity) {
    AtRecord rec;
    rec.at_public_key = at_keys_.public_key;
    rec.aa_hashed_id_8 = aa_cert_.hashed_id_8;
    rec.ea_hashed_id_8 = ea_cert_.hashed_id_8;
    rec.requested_psids = {36};
    rec.validity_period_hours = 0;
    EXPECT_FALSE(validate_at_record(rec));
}

TEST_F(AtRequestTest, Assemble) {
    AtRecord rec;
    rec.at_public_key = at_keys_.public_key;
    rec.aa_hashed_id_8 = aa_cert_.hashed_id_8;
    rec.ea_hashed_id_8 = ea_cert_.hashed_id_8;
    rec.requested_psids = {36, 37};
    rec.validity_period_hours = 48;

    auto desc = assemble_at_request(rec, std::chrono::system_clock::now());
    EXPECT_EQ(desc.verification_key.size(), 65u);
    EXPECT_EQ(desc.psids.size(), 2u);
    EXPECT_EQ(desc.aa_hid8, aa_cert_.hashed_id_8);
    EXPECT_EQ(desc.ea_hid8, ea_cert_.hashed_id_8);
    EXPECT_EQ(desc.hmac_key.size(), 32u);
}

TEST_F(AtRequestTest, EncodeProducesBytes) {
    AtRecord rec;
    rec.at_public_key = at_keys_.public_key;
    rec.aa_hashed_id_8 = aa_cert_.hashed_id_8;
    rec.ea_hashed_id_8 = ea_cert_.hashed_id_8;
    rec.requested_psids = {36};
    rec.validity_period_hours = 24;

    auto desc = assemble_at_request(rec, std::chrono::system_clock::now());
    auto encoded = encode_at_request(desc, aa_cert_, ea_cert_, ec_cert_,
                                     ec_keys_.private_key.to_vector(),
                                     at_keys_.private_key.to_vector());
    ASSERT_TRUE(encoded.has_value());
    EXPECT_GT(encoded->encoded.size(), 100u);
    EXPECT_EQ(encoded->request_aes_key.size(), 16u);
}

TEST_F(AtRequestTest, EncodeBadAa) {
    AtRecord rec;
    rec.at_public_key = at_keys_.public_key;
    rec.aa_hashed_id_8 = aa_cert_.hashed_id_8;
    rec.ea_hashed_id_8 = ea_cert_.hashed_id_8;
    rec.requested_psids = {36};
    rec.validity_period_hours = 24;

    auto desc = assemble_at_request(rec, std::chrono::system_clock::now());
    CertInfo bad_aa = aa_cert_;
    bad_aa.public_key.clear();

    auto encoded = encode_at_request(desc, bad_aa, ea_cert_, ec_cert_,
                                     ec_keys_.private_key.to_vector(),
                                     at_keys_.private_key.to_vector());
    EXPECT_FALSE(encoded.has_value());
    EXPECT_TRUE(encoded.error() == Error::InvalidArgument || encoded.error() == Error::Crypto);
}

TEST_F(AtRequestTest, EncodeEciesWrapped) {
    AtRecord rec;
    rec.at_public_key = at_keys_.public_key;
    rec.aa_hashed_id_8 = aa_cert_.hashed_id_8;
    rec.ea_hashed_id_8 = ea_cert_.hashed_id_8;
    rec.requested_psids = {36, 37, 38};
    rec.validity_period_hours = 72;

    auto desc = assemble_at_request(rec, std::chrono::system_clock::now());
    auto encoded = encode_at_request(desc, aa_cert_, ea_cert_, ec_cert_,
                                     ec_keys_.private_key.to_vector(),
                                     at_keys_.private_key.to_vector());
    ASSERT_TRUE(encoded.has_value());
    EXPECT_GT(encoded->encoded.size(), 200u);
    EXPECT_EQ(encoded->encoded[0], 0x03); // Ieee1609Dot2Data protocolVersion
}
