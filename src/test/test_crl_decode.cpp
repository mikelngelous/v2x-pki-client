// decode_crl over an envelope signed with the client's own builder (TS 102 941 §6.3.3, A.2.7).

#include <gtest/gtest.h>

#include "v2xpki/revocation.hpp"
#include "v2xpki/crypto_ec.hpp"
#include "v2xpki/trust_chain.hpp"

extern "C" {
#include "EtsiTs102941MessagesCa_EtsiTs102941Data.h"
#include "EtsiTs102941MessagesCa_EtsiTs102941DataContent.h"
#include "ToBeSignedCrl.h"
#include "CrlEntry.h"
#include "asn_application.h"
}

#include "internal/asn_ptr.hpp"
#include "internal/coer.hpp"
#include "internal/signed_envelope.hpp"

using namespace v2xpki;

namespace {

std::array<uint8_t, 8> hid(uint8_t tag) { return {tag, 1, 2, 3, 4, 5, 6, 7}; }

std::vector<uint8_t> encode_crl_payload(uint32_t this_update, uint32_t next_update,
                                        const std::vector<std::array<uint8_t, 8>> &revoked) {
    auto *crl = asn_calloc<ToBeSignedCrl_t>();
    crl->version = 1;
    crl->thisUpdate = this_update;
    crl->nextUpdate = next_update;
    for (const auto &h : revoked) {
        auto *entry = asn_calloc<CrlEntry_t>();
        octet::set(entry, h.data(), h.size());
        ASN_SEQUENCE_ADD(&crl->entries, entry);
    }

    auto *content = asn_calloc<EtsiTs102941MessagesCa_EtsiTs102941DataContent_t>();
    content->present = EtsiTs102941MessagesCa_EtsiTs102941DataContent_PR_certificateRevocationList;
    content->choice.certificateRevocationList = crl;

    EtsiTs102941MessagesCa_EtsiTs102941Data_t data{};
    data.version = 1;
    data.content = reinterpret_cast<struct EtsiTs102941DataContent *>(content);

    auto bytes = coer::encode(&asn_DEF_EtsiTs102941MessagesCa_EtsiTs102941Data, &data);
    ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_EtsiTs102941MessagesCa_EtsiTs102941Data, &data);
    return bytes;
}

struct CrlFixture {
    KeyPair rca_keys;
    CertInfo rca_cert;
    std::vector<uint8_t> message;
    bool valid = false;
};

} // namespace

class CrlDecodeTest : public ::testing::Test {
protected:
    static CrlFixture fx_;

    static void SetUpTestSuite() {
        auto kp = crypto::generate_keypair();
        if (!kp) return;
        fx_.rca_keys = *kp;

        auto rca = cert_utils::build_root_cert("rca_crl", kp->public_key.to_vector(),
                                               kp->private_key.to_vector());
        if (!rca) return;
        fx_.rca_cert = *rca;

        auto payload = encode_crl_payload(1000, 2000, {hid(0x01), hid(0x02)});
        if (payload.empty()) return;

        fx_.message = sign::build_signed_by_cert(payload, fx_.rca_cert,
                                                 kp->private_key.to_vector());
        fx_.valid = !fx_.message.empty();
    }
};

CrlFixture CrlDecodeTest::fx_;

TEST_F(CrlDecodeTest, DecodesEntriesAndTimestamps) {
    ASSERT_TRUE(fx_.valid);

    auto crl = decode_crl(fx_.message, fx_.rca_cert.public_key.to_vector(),
                          fx_.rca_cert.cert_bytes.to_vector());
    ASSERT_TRUE(crl) << "error " << static_cast<int>(crl.error());

    EXPECT_EQ(crl->this_update, 1000u);
    EXPECT_EQ(crl->next_update, 2000u);
    ASSERT_EQ(crl->revoked.size(), 2u);
    EXPECT_EQ(crl->revoked[0], hid(0x01));
    EXPECT_EQ(crl->revoked[1], hid(0x02));
}

TEST_F(CrlDecodeTest, IssuerComesFromTheEnvelopeSigner) {
    ASSERT_TRUE(fx_.valid);

    auto crl = decode_crl(fx_.message, fx_.rca_cert.public_key.to_vector(),
                          fx_.rca_cert.cert_bytes.to_vector());
    ASSERT_TRUE(crl);
    EXPECT_EQ(crl->issuer_hid8, fx_.rca_cert.hashed_id_8);
}

TEST_F(CrlDecodeTest, RejectsWrongVerificationKey) {
    ASSERT_TRUE(fx_.valid);
    auto other = crypto::generate_keypair();
    ASSERT_TRUE(other);

    auto crl = decode_crl(fx_.message, other->public_key.to_vector(),
                          fx_.rca_cert.cert_bytes.to_vector());
    ASSERT_FALSE(crl);
    EXPECT_EQ(crl.error(), Error::SignatureInvalid);
}

// Otherwise the revocations get filed under an issuer that did not sign them.
TEST_F(CrlDecodeTest, RejectsSignerCertThatIsNotTheDigestOnTheWire) {
    ASSERT_TRUE(fx_.valid);
    auto other = crypto::generate_keypair();
    ASSERT_TRUE(other);
    auto other_rca = cert_utils::build_root_cert("rca_other", other->public_key.to_vector(),
                                                 other->private_key.to_vector());
    ASSERT_TRUE(other_rca);

    auto crl = decode_crl(fx_.message, fx_.rca_cert.public_key.to_vector(),
                          other_rca->cert_bytes.to_vector());
    ASSERT_FALSE(crl);
    EXPECT_EQ(crl.error(), Error::SignatureInvalid);
}

// Signs over an empty signer input, so verification fails before the digest guard is reached.
// TODO: cover the signer=certificate path of that guard — needs a builder for that envelope.
TEST_F(CrlDecodeTest, RejectsSelfSignedEnvelope) {
    auto payload = encode_crl_payload(1000, 2000, {hid(0x01)});
    ASSERT_FALSE(payload.empty());
    auto self_signed = sign::build_self_signed(payload, fx_.rca_keys.private_key.to_vector());
    ASSERT_FALSE(self_signed.empty());

    auto crl = decode_crl(self_signed, fx_.rca_cert.public_key.to_vector(),
                          fx_.rca_cert.cert_bytes.to_vector());
    ASSERT_FALSE(crl);
    EXPECT_EQ(crl.error(), Error::SignatureInvalid);
}

TEST_F(CrlDecodeTest, RejectsTruncatedMessage) {
    ASSERT_TRUE(fx_.valid);
    std::vector<uint8_t> truncated(fx_.message.begin(), fx_.message.begin() + 12);

    auto crl = decode_crl(truncated, fx_.rca_cert.public_key.to_vector(),
                          fx_.rca_cert.cert_bytes.to_vector());
    ASSERT_FALSE(crl);
    EXPECT_EQ(crl.error(), Error::Decode);
}

// Must be refused, not read as an empty list.
TEST_F(CrlDecodeTest, RejectsNonCrlPayload) {
    std::vector<uint8_t> payload = {0x01, 0x02, 0x03};
    auto message = sign::build_signed_by_cert(payload, fx_.rca_cert,
                                              fx_.rca_keys.private_key.to_vector());
    ASSERT_FALSE(message.empty());

    auto crl = decode_crl(message, fx_.rca_cert.public_key.to_vector(),
                          fx_.rca_cert.cert_bytes.to_vector());
    ASSERT_FALSE(crl);
    EXPECT_EQ(crl.error(), Error::Decode);
}

TEST_F(CrlDecodeTest, RejectsMissingVerificationMaterial) {
    ASSERT_TRUE(fx_.valid);

    auto no_key = decode_crl(fx_.message, {}, fx_.rca_cert.cert_bytes.to_vector());
    ASSERT_FALSE(no_key);
    EXPECT_EQ(no_key.error(), Error::InvalidArgument);

    auto no_cert = decode_crl(fx_.message, fx_.rca_cert.public_key.to_vector(), {});
    ASSERT_FALSE(no_cert);
    EXPECT_EQ(no_cert.error(), Error::InvalidArgument);
}

TEST_F(CrlDecodeTest, FeedsTheRevocationStore) {
    ASSERT_TRUE(fx_.valid);

    auto crl = decode_crl(fx_.message, fx_.rca_cert.public_key.to_vector(),
                          fx_.rca_cert.cert_bytes.to_vector());
    ASSERT_TRUE(crl);

    RevocationStore store;
    ASSERT_TRUE(store.apply(*crl, /*now_tai=*/1500));
    EXPECT_TRUE(store.is_revoked(fx_.rca_cert.hashed_id_8, hid(0x01)));
    EXPECT_FALSE(store.is_revoked(fx_.rca_cert.hashed_id_8, hid(0x03)));
}
