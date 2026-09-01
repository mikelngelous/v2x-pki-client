// Whole-certificate hash dispatch against EU L0 trust material
// (cpoc.jrc.ec.europa.eu, captured 2026-08-30).

#include <gtest/gtest.h>

#include "v2xpki/trust_chain.hpp"

#include "internal/cert_parse.hpp"

#include <fstream>
#include <iomanip>
#include <sstream>

using namespace v2xpki;

namespace {

std::vector<uint8_t> fixture(const std::string& name) {
    std::ifstream ifs(std::string(FIXTURE_DIR) + "/" + name, std::ios::binary);
    return {std::istreambuf_iterator<char>(ifs), std::istreambuf_iterator<char>()};
}

std::string hex8(const std::array<uint8_t, 8>& h) {
    std::ostringstream o;
    for (auto b : h)
        o << std::hex << std::setfill('0') << std::setw(2) << std::uppercase << static_cast<int>(b);
    return o.str();
}

} // namespace

class WholeCertHashTest : public ::testing::Test {
protected:
    std::vector<uint8_t> rca_ = fixture("rca-bp384r1.coer");
    std::vector<uint8_t> subject_ = fixture("subject-p256-by-bp384r1.coer");
};

TEST_F(WholeCertHashTest, FixturesLoad) {
    ASSERT_FALSE(rca_.empty());
    ASSERT_FALSE(subject_.empty());
}

TEST_F(WholeCertHashTest, RootCaHashedId8FollowsItsP384Key) {
    EXPECT_EQ(hex8(cert::compute_hid8(rca_)), "3B49ECA411F89706");
}

TEST_F(WholeCertHashTest, SubjectIssuerReferenceMatchesTheRootCa) {
    auto rca = cert::from_coer(rca_);
    auto subject = cert::from_coer(subject_);

    EXPECT_EQ(rca.curve, Curve::BrainpoolP384r1);
    EXPECT_TRUE(rca.is_self_signed);
    EXPECT_EQ(subject.issuer_hash_id_8, rca.hashed_id_8);
}

TEST_F(WholeCertHashTest, SubjectKeyAndIssuerHashDisagree) {
    auto subject = cert::from_coer(subject_);

    EXPECT_TRUE(is_p256_size(subject.curve));
    EXPECT_EQ(subject.issuer_hash, SigHash::Sha384);
    EXPECT_EQ(subject.signature_r.size(), kP384ScalarLen);
}

TEST_F(WholeCertHashTest, VerifiesAcrossTheCurveBoundary) {
    TrustChain tc;
    EXPECT_TRUE(tc.verify_cert_signature(cert::from_coer(subject_), cert::from_coer(rca_)));
}

TEST_F(WholeCertHashTest, SelfSignedRootVerifies) {
    TrustChain tc;
    auto rca = cert::from_coer(rca_);
    EXPECT_TRUE(tc.verify_cert_signature(rca, rca));
}
