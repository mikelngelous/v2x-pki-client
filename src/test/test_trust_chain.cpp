// Tests for TrustChain + cert_utils.
// Synthetic cert pool generated at runtime via CSPRNG keygen.
// Chain: RCA (self-signed) → AA (signed by RCA) → AT (signed by AA).

#include <gtest/gtest.h>

#include "v2xpki/trust_chain.hpp"
#include "v2xpki/crypto_ec.hpp"

#include "internal/cert_parse.hpp"

#include <filesystem>
#include <fstream>

using namespace v2xpki;

struct SyntheticPool {
    KeyPair rca_keys, aa_keys, at_keys;
    CertInfo rca_cert, aa_cert, at_cert;
    bool valid = false;
};

class TrustChainTest : public ::testing::Test {
protected:
    static SyntheticPool pool_;

    static void SetUpTestSuite() {
        auto rca_kp = crypto::generate_keypair();
        auto aa_kp = crypto::generate_keypair();
        auto at_kp = crypto::generate_keypair();
        if (!rca_kp || !aa_kp || !at_kp) return;
        pool_.rca_keys = *rca_kp;
        pool_.aa_keys = *aa_kp;
        pool_.at_keys = *at_kp;

        auto rca_opt = cert_utils::build_root_cert("rca_test", rca_kp->public_key.to_vector(),
                                                   rca_kp->private_key.to_vector());
        if (!rca_opt) return;
        pool_.rca_cert = *rca_opt;

        auto aa_opt = cert_utils::build_signed_cert("aa_test", aa_kp->public_key.to_vector(),
                                                    rca_kp->private_key.to_vector(),
                                                    pool_.rca_cert.hashed_id_8, true, false,
                                                    pool_.rca_cert.cert_bytes.to_vector());
        if (!aa_opt) return;
        pool_.aa_cert = *aa_opt;

        auto at_opt = cert_utils::build_signed_cert("at_test", at_kp->public_key.to_vector(),
                                                    aa_kp->private_key.to_vector(),
                                                    pool_.aa_cert.hashed_id_8, false, false,
                                                    pool_.aa_cert.cert_bytes.to_vector());
        if (!at_opt) return;
        pool_.at_cert = *at_opt;

        pool_.valid = true;
    }
};

SyntheticPool TrustChainTest::pool_;

TEST_F(TrustChainTest, BuildRootCert) {
    ASSERT_TRUE(pool_.valid);
    const auto& rca = pool_.rca_cert;
    EXPECT_TRUE(rca.is_self_signed);
    EXPECT_FALSE(rca.cert_bytes.empty());
    EXPECT_EQ(rca.public_key.size(), 65u);
    EXPECT_EQ(rca.signature_r.size(), 32u);
    EXPECT_EQ(rca.signature_s.size(), 32u);
    EXPECT_EQ(rca.label, "rca_test");
}

TEST_F(TrustChainTest, BuildAaCert) {
    const auto& aa = pool_.aa_cert;
    EXPECT_FALSE(aa.is_self_signed);
    EXPECT_EQ(aa.issuer_hash_id_8, pool_.rca_cert.hashed_id_8);
    EXPECT_EQ(aa.public_key.size(), 65u);
    EXPECT_EQ(aa.label, "aa_test");
}

TEST_F(TrustChainTest, BuildAtCert) {
    const auto& at = pool_.at_cert;
    EXPECT_FALSE(at.is_self_signed);
    EXPECT_EQ(at.issuer_hash_id_8, pool_.aa_cert.hashed_id_8);
    EXPECT_EQ(at.public_key.size(), 65u);
}

TEST_F(TrustChainTest, AddAndFind) {
    TrustChain tc;
    EXPECT_EQ(tc.size(), 0u);

    tc.add_cert(pool_.rca_cert);
    EXPECT_EQ(tc.size(), 1u);

    auto found = tc.find_by_hashed_id_8(pool_.rca_cert.hashed_id_8);
    ASSERT_TRUE(found.has_value());
    EXPECT_EQ(found->label, "rca_test");

    std::array<uint8_t, 8> bad_hid8 = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    auto not_found = tc.find_by_hashed_id_8(bad_hid8);
    EXPECT_FALSE(not_found.has_value());
}

TEST_F(TrustChainTest, ValidateChainValid) {
    TrustChain tc;
    tc.add_cert(pool_.rca_cert);
    tc.add_cert(pool_.aa_cert);
    tc.add_cert(pool_.at_cert);
    EXPECT_TRUE(tc.validate_chain(pool_.at_cert));
}

TEST_F(TrustChainTest, ValidateChainMissingAa) {
    TrustChain tc;
    tc.add_cert(pool_.rca_cert);
    tc.add_cert(pool_.at_cert);
    EXPECT_FALSE(tc.validate_chain(pool_.at_cert));
}

TEST_F(TrustChainTest, ValidateChainMissingRca) {
    TrustChain tc;
    tc.add_cert(pool_.aa_cert);
    tc.add_cert(pool_.at_cert);
    EXPECT_FALSE(tc.validate_chain(pool_.at_cert));
}

TEST_F(TrustChainTest, ValidateChainSelfSignedAt) {
    TrustChain tc;
    tc.add_cert(pool_.rca_cert);
    EXPECT_FALSE(tc.validate_chain(pool_.rca_cert));
}

TEST_F(TrustChainTest, GetByRole) {
    TrustChain tc;
    tc.add_cert(pool_.rca_cert);
    tc.add_cert(pool_.aa_cert);
    tc.add_cert(pool_.at_cert);

    auto rcas = tc.get_rcas();
    EXPECT_EQ(rcas.size(), 1u);
    EXPECT_EQ(rcas[0].label, "rca_test");

    auto aas = tc.get_aas();
    EXPECT_EQ(aas.size(), 1u);

    auto eas = tc.get_eas();
    EXPECT_TRUE(eas.empty());
}

TEST_F(TrustChainTest, Hid8Uniqueness) {
    EXPECT_NE(pool_.rca_cert.hashed_id_8, pool_.aa_cert.hashed_id_8);
    EXPECT_NE(pool_.aa_cert.hashed_id_8, pool_.at_cert.hashed_id_8);
    EXPECT_NE(pool_.rca_cert.hashed_id_8, pool_.at_cert.hashed_id_8);
}

TEST_F(TrustChainTest, BuildCertInvalidKey) {
    std::vector<uint8_t> bad_key = {0x04, 0x01, 0x02};
    auto result = cert_utils::build_signed_cert("bad_key_cert", bad_key,
                                                pool_.rca_keys.private_key.to_vector(),
                                                pool_.rca_cert.hashed_id_8, false, false,
                                                pool_.rca_cert.cert_bytes.to_vector());
    EXPECT_FALSE(result.has_value());
}

// --- Validity period enforcement ---

TEST_F(TrustChainTest, ValidateChainRejectsExpiredCert) {
    TrustChain tc;
    tc.add_cert(pool_.rca_cert);
    tc.add_cert(pool_.aa_cert);
    tc.add_cert(pool_.at_cert);

    // Synthetic certs start at TAI 0 and last 30 years; step past that.
    int64_t past_expiry = static_cast<int64_t>(31) * kYearSeconds;
    EXPECT_FALSE(tc.validate_chain(pool_.at_cert, past_expiry));
}

TEST_F(TrustChainTest, ValidateChainRejectsNotYetValidCert) {
    TrustChain tc;
    tc.add_cert(pool_.rca_cert);
    tc.add_cert(pool_.aa_cert);
    tc.add_cert(pool_.at_cert);

    EXPECT_FALSE(tc.validate_chain(pool_.at_cert, -1));
}

TEST_F(TrustChainTest, ValidateChainAcceptsInsideValidityWindow) {
    TrustChain tc;
    tc.add_cert(pool_.rca_cert);
    tc.add_cert(pool_.aa_cert);
    tc.add_cert(pool_.at_cert);

    EXPECT_TRUE(tc.validate_chain(pool_.at_cert, static_cast<int64_t>(kYearSeconds)));
}

TEST_F(TrustChainTest, ValidateChainRejectsExpiredIssuer) {
    auto aa_expired = pool_.aa_cert;
    aa_expired.validity_duration_seconds = 1;

    TrustChain tc;
    tc.add_cert(pool_.rca_cert);
    tc.add_cert(aa_expired);
    tc.add_cert(pool_.at_cert);

    EXPECT_FALSE(tc.validate_chain(pool_.at_cert, static_cast<int64_t>(kYearSeconds)));
}

// TS 103 097 v2.2.1 §6: the end is exclusive.
TEST_F(TrustChainTest, ValidityWindowEndIsExclusive) {
    CertInfo cert = pool_.at_cert;
    cert.validity_start = 100;
    cert.validity_duration_seconds = 10;

    EXPECT_TRUE(cert.valid_at(100));
    EXPECT_TRUE(cert.valid_at(109));
    EXPECT_FALSE(cert.valid_at(110));
    EXPECT_FALSE(cert.valid_at(99));
}

TEST_F(TrustChainTest, CertWithoutDurationIsNeverValid) {
    CertInfo no_duration = pool_.at_cert;
    no_duration.validity_duration_seconds = 0;

    EXPECT_FALSE(no_duration.valid_at(0));
    EXPECT_FALSE(no_duration.valid_at(static_cast<int64_t>(kYearSeconds)));
}

TEST_F(TrustChainTest, ValidityParsedFromRealCert) {
    // build_signed_cert asks for 30 years starting at the TAI epoch.
    EXPECT_EQ(pool_.at_cert.validity_start, 0u);
    EXPECT_EQ(pool_.at_cert.validity_duration_seconds, 30ull * kYearSeconds);

    auto reparsed = cert::from_coer(pool_.at_cert.cert_bytes.to_vector());
    EXPECT_EQ(reparsed.validity_start, pool_.at_cert.validity_start);
    EXPECT_EQ(reparsed.validity_duration_seconds, pool_.at_cert.validity_duration_seconds);
}

TEST_F(TrustChainTest, LoadNonexistentDir) {
    TrustChain tc;
    EXPECT_FALSE(tc.load_from_directory("/nonexistent/path/certs"));
}

TEST_F(TrustChainTest, LoadEmptyDir) {
    namespace fs = std::filesystem;
    auto tmp = fs::temp_directory_path() / "pki_test_empty_certs";
    fs::create_directories(tmp);

    TrustChain tc;
    EXPECT_FALSE(tc.load_from_directory(tmp.string()));

    fs::remove_all(tmp);
}

TEST_F(TrustChainTest, LoadFromDirectory) {
    namespace fs = std::filesystem;
    auto tmp = fs::temp_directory_path() / "pki_test_certs";
    fs::create_directories(tmp);

    auto write_cert = [&](const CertInfo& ci) {
        std::ofstream ofs(tmp / (ci.label + ".cert"), std::ios::binary);
        ofs.write(reinterpret_cast<const char*>(ci.cert_bytes.data()),
                  static_cast<std::streamsize>(ci.cert_bytes.size()));
    };
    write_cert(pool_.rca_cert);
    write_cert(pool_.aa_cert);
    write_cert(pool_.at_cert);

    TrustChain tc;
    ASSERT_TRUE(tc.load_from_directory(tmp.string()));
    EXPECT_EQ(tc.size(), 3u);

    auto rca = tc.find_by_hashed_id_8(pool_.rca_cert.hashed_id_8);
    EXPECT_TRUE(rca.has_value());
    auto aa = tc.find_by_hashed_id_8(pool_.aa_cert.hashed_id_8);
    EXPECT_TRUE(aa.has_value());
    auto at = tc.find_by_hashed_id_8(pool_.at_cert.hashed_id_8);
    ASSERT_TRUE(at.has_value());

    EXPECT_TRUE(tc.validate_chain(*at));

    fs::remove_all(tmp);
}

TEST_F(TrustChainTest, TwoIndependentChains) {
    auto rca2_kp = crypto::generate_keypair();
    auto at2_kp = crypto::generate_keypair();
    ASSERT_TRUE(rca2_kp.has_value() && at2_kp.has_value());

    auto rca2 = cert_utils::build_root_cert("rca_second", rca2_kp->public_key.to_vector(),
                                            rca2_kp->private_key.to_vector());
    ASSERT_TRUE(rca2.has_value());

    auto at2 = cert_utils::build_signed_cert("at_second", at2_kp->public_key.to_vector(),
                                             rca2_kp->private_key.to_vector(), rca2->hashed_id_8,
                                             false, false, rca2->cert_bytes.to_vector());
    ASSERT_TRUE(at2.has_value());

    TrustChain tc;
    tc.add_cert(*rca2);
    tc.add_cert(*at2);

    EXPECT_FALSE(tc.validate_chain(pool_.at_cert));
    EXPECT_TRUE(tc.validate_chain(*at2));
}
