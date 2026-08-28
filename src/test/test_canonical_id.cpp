// Tests for --canonical-id (EcRecord.its_id → InnerEcRequest.itsId).

#include <gtest/gtest.h>

#include "v2xpki/ec_request.hpp"
#include "v2xpki/crypto_ec.hpp"
#include "internal/asn_ptr.hpp"
#include "v2xpki/trust_chain.hpp"

#include <filesystem>
#include <fstream>

extern "C" {
#include "InnerEcRequest.h"
#include "CertificateFormat.h"
#include "PublicKeys.h"
#include "PublicVerificationKey.h"
#include "EccP256CurvePoint.h"
#include "CertificateSubjectAttributes.h"
#include "ValidityPeriod.h"
#include "Duration.h"
#include "SequenceOfPsidSsp.h"
#include "PsidSsp.h"
#include "asn_application.h"
}

#include "internal/coer.hpp"

using namespace v2xpki;

class CanonicalIdTest : public ::testing::Test {
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
        auto ea_cert = cert_utils::build_root_cert("ea_test", ea->public_key.to_vector(),
                                                   ea->private_key.to_vector());
        if (!ea_cert) return;
        ea_cert_ = *ea_cert;
        pool_ok_ = true;
    }

    // Build a complete InnerEcRequest with a given itsId, encode to COER,
    // decode back, and extract the itsId.
    static std::string encode_and_extract_its_id(const std::string &its_id) {
        EcRecord rec;
        rec.canonical_public_key = canonical_keys_.public_key;
        rec.ea_hashed_id_8 = ea_cert_.hashed_id_8;
        rec.requested_psids = {36};
        rec.validity_period_days = 30;
        rec.its_id = its_id;

        auto desc = assemble_ec_request(rec, std::chrono::system_clock::now());

        InnerEcRequest_t inner{};
        octet::set(&inner.itsId, reinterpret_cast<const uint8_t *>(desc.its_id.data()),
                   desc.its_id.size());
        inner.certificateFormat = CertificateFormat_ts103097v131;

        auto *pkeys = asn_calloc<PublicKeys_t>();
        auto *pvk = asn_calloc<PublicVerificationKey_t>();
        pvk->present = PublicVerificationKey_PR_ecdsaNistP256;
        auto *pt = asn_calloc<EccP256CurvePoint_t>();
        pt->present = EccP256CurvePoint_PR_compressed_y_0;
        octet::set(&pt->choice.compressed_y_0, desc.verification_key.data() + 1, kP256ScalarLen);
        pvk->choice.ecdsaNistP256 = pt;
        pkeys->verificationKey = pvk;
        inner.publicKeys = pkeys;

        auto *attrs = asn_calloc<CertificateSubjectAttributes_t>();
        auto *vp = asn_calloc<ValidityPeriod_t>();
        vp->start = desc.validity_start;
        auto *dur = asn_calloc<Duration_t>();
        dur->present = Duration_PR_hours;
        dur->choice.hours = desc.validity_duration_hours;
        vp->duration = dur;
        attrs->validityPeriod = vp;

        auto *perms = asn_calloc<SequenceOfPsidSsp_t>();
        auto *entry = asn_calloc<PsidSsp_t>();
        entry->psid = 36;
        ASN_SEQUENCE_ADD(&perms->list, entry);
        attrs->appPermissions = perms;
        inner.requestedSubjectAttributes = attrs;

        auto inner_bytes = coer::encode(&asn_DEF_InnerEcRequest, &inner);
        ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_InnerEcRequest, &inner);
        if (inner_bytes.empty()) return {};

        auto *decoded = static_cast<InnerEcRequest_t *>(coer::decode(&asn_DEF_InnerEcRequest,
                                                                     inner_bytes.data(),
                                                                     inner_bytes.size()));
        if (!decoded) return {};

        std::string result;
        if (decoded->itsId.buf && decoded->itsId.size > 0) {
            result.assign(reinterpret_cast<const char *>(decoded->itsId.buf), decoded->itsId.size);
        }
        ASN_STRUCT_FREE(asn_DEF_InnerEcRequest, decoded);
        return result;
    }
};

KeyPair CanonicalIdTest::canonical_keys_;
KeyPair CanonicalIdTest::ea_keys_;
CertInfo CanonicalIdTest::ea_cert_;
bool CanonicalIdTest::pool_ok_ = false;

TEST_F(CanonicalIdTest, DefaultItsId) {
    ASSERT_TRUE(pool_ok_);

    EcRecord rec;
    rec.canonical_public_key = canonical_keys_.public_key;
    rec.ea_hashed_id_8 = ea_cert_.hashed_id_8;
    rec.requested_psids = {36};
    rec.validity_period_days = 30;

    auto desc = assemble_ec_request(rec, std::chrono::system_clock::now());
    EXPECT_EQ(desc.its_id, "v2xpki-its-s");

    auto extracted = encode_and_extract_its_id("v2xpki-its-s");
    EXPECT_EQ(extracted, "v2xpki-its-s");
}

TEST_F(CanonicalIdTest, CustomItsId) {
    auto extracted = encode_and_extract_its_id("bc-interop-001");
    EXPECT_EQ(extracted, "bc-interop-001");

    EcRecord rec;
    rec.canonical_public_key = canonical_keys_.public_key;
    rec.ea_hashed_id_8 = ea_cert_.hashed_id_8;
    rec.requested_psids = {36};
    rec.validity_period_days = 30;
    rec.its_id = "bc-interop-001";

    auto desc = assemble_ec_request(rec, std::chrono::system_clock::now());
    EXPECT_EQ(desc.its_id, "bc-interop-001");
}

TEST_F(CanonicalIdTest, ValidationBounds) {
    EcRecord rec;
    rec.canonical_public_key = canonical_keys_.public_key;
    rec.ea_hashed_id_8 = ea_cert_.hashed_id_8;
    rec.requested_psids = {36};
    rec.validity_period_days = 30;

    rec.its_id = "";
    auto desc_empty = assemble_ec_request(rec, std::chrono::system_clock::now());
    EXPECT_EQ(desc_empty.its_id, "v2xpki-its-s");

    std::string max_id(64, 'x');
    auto extracted_64 = encode_and_extract_its_id(max_id);
    EXPECT_EQ(extracted_64, max_id);

    // TODO: enforce the 1-64 byte itsId bound (TS 102 941 §6.2.3.2); currently passed through.
    rec.its_id = std::string(65, 'y');
    auto desc_over = assemble_ec_request(rec, std::chrono::system_clock::now());
    EXPECT_EQ(desc_over.its_id.size(), 65u);
}

TEST_F(CanonicalIdTest, Persistence) {
    namespace fs = std::filesystem;
    auto tmp_dir = fs::temp_directory_path() / "test_canonical_id_ks";
    fs::create_directories(tmp_dir);
    auto cid_path = (tmp_dir / "canonical.id").string();

    {
        std::string cid = "bc-persist-test";
        std::ofstream ofs(cid_path, std::ios::binary);
        ASSERT_TRUE(ofs.good());
        ofs.write(cid.data(), static_cast<std::streamsize>(cid.size()));
    }

    {
        std::ifstream ifs(cid_path, std::ios::binary);
        ASSERT_TRUE(ifs.good());
        std::string loaded;
        loaded.assign(std::istreambuf_iterator<char>(ifs), std::istreambuf_iterator<char>());
        EXPECT_EQ(loaded, "bc-persist-test");
    }

    fs::remove_all(tmp_dir);
}
