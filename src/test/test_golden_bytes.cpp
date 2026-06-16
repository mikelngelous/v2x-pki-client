// Golden-bytes test: deterministic COER output of key ASN.1 structures.
// Safety net before wire-critical refactoring (phases 5, 6).

#include <gtest/gtest.h>

#include "v2xpki/sizes.hpp"
#include "internal/asn_ptr.hpp"
#include "internal/coer.hpp"

#include <cstdio>
#include <cstring>

extern "C" {
#include "InnerEcRequest.h"
#include "SharedAtRequest.h"
#include "ToBeSignedData.h"
#include "Ieee1609Dot2Data.h"
#include "Ieee1609Dot2Content.h"
#include "SignedDataPayload.h"
#include "HeaderInfo.h"
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

using namespace v2xpki;

// --- Fixed test vectors ---

static const uint8_t kFixedPubkey[65] = {
    0x04, 0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5,
    0x63, 0xa4, 0x40, 0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4,
    0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2, 0x96, 0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a,
    0x7f, 0x9b, 0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0x0f, 0x9e, 0x16, 0x2b, 0xce, 0x33,
    0x57, 0x6b, 0x31, 0x5e, 0xce, 0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51, 0xf8,
};

static const uint8_t kFixedEaHid8[8] = {0xaa, 0xbb, 0xcc, 0xdd, 0x11, 0x22, 0x33, 0x44};

static const uint8_t kFixedKeyTag[16] = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
};

static std::vector<uint8_t> build_fixed_inner_ec_request() {
    InnerEcRequest_t inner{};

    const char *its_id = "v2xpki-its-s";
    octet::set(&inner.itsId, reinterpret_cast<const uint8_t *>(its_id), strlen(its_id));

    inner.certificateFormat = CertificateFormat_ts103097v131;

    auto *pkeys = asn_calloc<PublicKeys_t>();
    auto *pvk = asn_calloc<PublicVerificationKey_t>();
    pvk->present = PublicVerificationKey_PR_ecdsaNistP256;
    auto *pt = asn_calloc<EccP256CurvePoint_t>();
    pt->present = EccP256CurvePoint_PR_compressed_y_0;
    octet::set(&pt->choice.compressed_y_0, kFixedPubkey + 1, kP256ScalarLen);
    pvk->choice.ecdsaNistP256 = pt;
    pkeys->verificationKey = pvk;
    inner.publicKeys = pkeys;

    auto *attrs = asn_calloc<CertificateSubjectAttributes_t>();
    auto *vp = asn_calloc<ValidityPeriod_t>();
    vp->start = 1000000;
    auto *dur = asn_calloc<Duration_t>();
    dur->present = Duration_PR_hours;
    dur->choice.hours = 720;
    vp->duration = dur;
    attrs->validityPeriod = vp;

    auto *perms = asn_calloc<SequenceOfPsidSsp_t>();
    auto *entry = asn_calloc<PsidSsp_t>();
    entry->psid = 36;
    ASN_SEQUENCE_ADD(&perms->list, entry);
    attrs->appPermissions = perms;
    inner.requestedSubjectAttributes = attrs;

    auto result = coer::encode(&asn_DEF_InnerEcRequest, &inner);
    ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_InnerEcRequest, &inner);
    return result;
}

static std::vector<uint8_t> build_fixed_shared_at_request() {
    SharedAtRequest_t shared{};
    octet::set(&shared.eaId, kFixedEaHid8, kHashedId8Len);
    octet::set(&shared.keyTag, kFixedKeyTag, 16);
    shared.certificateFormat = CertificateFormat_ts103097v131;

    auto *attrs = asn_calloc<CertificateSubjectAttributes_t>();
    auto *vp = asn_calloc<ValidityPeriod_t>();
    vp->start = 1000000;
    auto *dur = asn_calloc<Duration_t>();
    dur->present = Duration_PR_hours;
    dur->choice.hours = 24;
    vp->duration = dur;
    attrs->validityPeriod = vp;

    auto *perms = asn_calloc<SequenceOfPsidSsp_t>();
    auto *entry = asn_calloc<PsidSsp_t>();
    entry->psid = 36;
    ASN_SEQUENCE_ADD(&perms->list, entry);
    attrs->appPermissions = perms;
    shared.requestedSubjectAttributes = attrs;

    auto result = coer::encode(&asn_DEF_SharedAtRequest, &shared);
    ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_SharedAtRequest, &shared);
    return result;
}

static std::vector<uint8_t> build_fixed_tbs_data() {
    static const uint8_t payload_bytes[] = {0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE};

    ToBeSignedData_t tbs{};

    auto *payload = asn_calloc<SignedDataPayload_t>();
    auto *payload_data = asn_calloc<Ieee1609Dot2Data_t>();
    payload_data->protocolVersion = kIeee1609Dot2Version;
    auto *unsecured = asn_calloc<Ieee1609Dot2Content_t>();
    unsecured->present = Ieee1609Dot2Content_PR_unsecuredData;
    octet::set(&unsecured->choice.unsecuredData, payload_bytes, sizeof(payload_bytes));
    payload_data->content = unsecured;
    payload->data = payload_data;
    tbs.payload = payload;

    auto *hdr = asn_calloc<HeaderInfo_t>();
    hdr->psid = kPsidScr;
    auto *gen_time = asn_calloc<Time64_t>();
    asn_ulong2INTEGER(gen_time, 5000000000ULL);
    hdr->generationTime = gen_time;
    tbs.headerInfo = hdr;

    auto result = coer::encode(&asn_DEF_ToBeSignedData, &tbs);
    ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_ToBeSignedData, &tbs);
    return result;
}

// --- Golden vectors ---

static const uint8_t kGoldenInnerEcRequest[63] = {
    0x00, 0x0c, 0x76, 0x32, 0x78, 0x70, 0x6b, 0x69, 0x2d, 0x69, 0x74, 0x73, 0x2d, 0x73, 0x01, 0x00,
    0x80, 0x82, 0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4,
    0x40, 0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98,
    0xc2, 0x96, 0x24, 0x00, 0x0f, 0x42, 0x40, 0x84, 0x02, 0xd0, 0x01, 0x01, 0x00, 0x01, 0x24,
};
static const uint8_t kGoldenSharedAtRequest[39] = {
    0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0x11, 0x22, 0x33, 0x44, 0x01, 0x02, 0x03, 0x04,
    0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x01,
    0x24, 0x00, 0x0f, 0x42, 0x40, 0x84, 0x00, 0x18, 0x01, 0x01, 0x00, 0x01, 0x24,
};
static const uint8_t kGoldenTbsData[24] = {
    0x40, 0x03, 0x80, 0x08, 0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe,
    0x40, 0x02, 0x02, 0x6f, 0x00, 0x00, 0x00, 0x01, 0x2a, 0x05, 0xf2, 0x00,
};

static bool match_golden(const std::vector<uint8_t> &actual, const uint8_t *expected,
                         size_t expected_len) {
    if (actual.size() != expected_len) return false;
    return memcmp(actual.data(), expected, expected_len) == 0;
}

TEST(GoldenBytesTest, InnerEcRequest) {
    auto coer = build_fixed_inner_ec_request();
    ASSERT_FALSE(coer.empty());
    EXPECT_TRUE(match_golden(coer, kGoldenInnerEcRequest, sizeof(kGoldenInnerEcRequest)));

    auto *decoded = static_cast<InnerEcRequest_t *>(coer::decode(&asn_DEF_InnerEcRequest,
                                                                 coer.data(), coer.size()));
    ASSERT_NE(decoded, nullptr);
    auto re_encoded = coer::encode(&asn_DEF_InnerEcRequest, decoded);
    EXPECT_EQ(re_encoded, coer);
    ASN_STRUCT_FREE(asn_DEF_InnerEcRequest, decoded);
}

TEST(GoldenBytesTest, SharedAtRequest) {
    auto coer = build_fixed_shared_at_request();
    ASSERT_FALSE(coer.empty());
    EXPECT_TRUE(match_golden(coer, kGoldenSharedAtRequest, sizeof(kGoldenSharedAtRequest)));

    auto *decoded = static_cast<SharedAtRequest_t *>(coer::decode(&asn_DEF_SharedAtRequest,
                                                                  coer.data(), coer.size()));
    ASSERT_NE(decoded, nullptr);
    auto re_encoded = coer::encode(&asn_DEF_SharedAtRequest, decoded);
    EXPECT_EQ(re_encoded, coer);
    ASN_STRUCT_FREE(asn_DEF_SharedAtRequest, decoded);
}

TEST(GoldenBytesTest, TbsData) {
    auto coer = build_fixed_tbs_data();
    ASSERT_FALSE(coer.empty());
    EXPECT_TRUE(match_golden(coer, kGoldenTbsData, sizeof(kGoldenTbsData)));

    auto *decoded = static_cast<ToBeSignedData_t *>(coer::decode(&asn_DEF_ToBeSignedData,
                                                                 coer.data(), coer.size()));
    ASSERT_NE(decoded, nullptr);
    auto re_encoded = coer::encode(&asn_DEF_ToBeSignedData, decoded);
    EXPECT_EQ(re_encoded, coer);
    ASN_STRUCT_FREE(asn_DEF_ToBeSignedData, decoded);
}

TEST(GoldenBytesTest, EtsiPrefix) {
    auto inner = build_fixed_inner_ec_request();
    ASSERT_FALSE(inner.empty());

    std::vector<uint8_t> ec_framed;
    ec_framed.push_back(0x01);
    ec_framed.push_back(0x80);
    ec_framed.insert(ec_framed.end(), inner.begin(), inner.end());
    EXPECT_EQ(ec_framed.size(), inner.size() + 2);
    EXPECT_EQ(ec_framed[0], 0x01);
    EXPECT_EQ(ec_framed[1], 0x80);

    std::vector<uint8_t> at_framed;
    at_framed.push_back(0x01);
    at_framed.push_back(0x82);
    at_framed.insert(at_framed.end(), inner.begin(), inner.end());
    EXPECT_EQ(at_framed[0], 0x01);
    EXPECT_EQ(at_framed[1], 0x82);
}
