// Round-trip tests for PKI codecs (TS 102 941 / TS 103 097 / IEEE 1609.2).
// Pattern: build PDU → encode UPER → decode UPER → re-encode UPER →
// compare buffers bit-exact.

#include <gtest/gtest.h>

#include <cstdlib>
#include <cstring>
#include <vector>

extern "C" {
#include "Ieee1609Dot2Data.h"
#include "Ieee1609Dot2Content.h"
#include "SignedData.h"
#include "ToBeSignedData.h"
#include "SignedDataPayload.h"
#include "HeaderInfo.h"
#include "SignerIdentifier.h"
#include "Signature.h"
#include "EcdsaP256Signature.h"
#include "EccP256CurvePoint.h"
#include "HashAlgorithm.h"
#include "EtsiTs102941MessagesCa_EtsiTs102941Data.h"
#include "EtsiTs102941MessagesCa_EtsiTs102941DataContent.h"
#include "ToBeSignedCrl.h"
#include "CrlEntry.h"
#include "CtlFormat.h"
#include "ToBeSignedCertificate.h"
#include "CertificateId.h"
#include "HashedId3.h"
#include "SequenceOfPsidSsp.h"
#include "PsidSsp.h"
#include "VerificationKeyIndicator.h"
#include "PublicVerificationKey.h"
#include "ValidityPeriod.h"
#include "Duration.h"
#include "asn_application.h"
}

static std::vector<uint8_t> encode_uper(const asn_TYPE_descriptor_t *td, const void *sptr) {
    void *buffer = nullptr;
    ssize_t bytes = uper_encode_to_new_buffer(td, nullptr, sptr, &buffer);
    if (bytes < 0 || buffer == nullptr) {
        free(buffer);
        return {};
    }
    auto *buf = static_cast<uint8_t *>(buffer);
    std::vector<uint8_t> result(buf, buf + bytes);
    free(buffer);
    return result;
}

static void *decode_uper(const asn_TYPE_descriptor_t *td, const uint8_t *buf, size_t len) {
    void *structure = nullptr;
    asn_dec_rval_t dr = uper_decode_complete(nullptr, td, &structure, buf, len);
    if (dr.code != RC_OK) {
        if (structure) ASN_STRUCT_FREE(*td, structure);
        return nullptr;
    }
    return structure;
}

// Generic round-trip: encode → decode → re-encode → compare
static bool round_trip(const asn_TYPE_descriptor_t *td, const void *original, const char *name) {
    auto enc1 = encode_uper(td, original);
    if (enc1.empty()) return false;

    void *decoded = decode_uper(td, enc1.data(), enc1.size());
    if (!decoded) return false;

    auto enc2 = encode_uper(td, decoded);
    ASN_STRUCT_FREE(*td, decoded);

    if (enc2.empty()) return false;
    if (enc1.size() != enc2.size() || memcmp(enc1.data(), enc2.data(), enc1.size()) != 0)
        return false;

    return true;
}

static void fill_octet(OCTET_STRING_t *os, const uint8_t *data, size_t len) {
    OCTET_STRING_fromBuf(os, reinterpret_cast<const char *>(data), static_cast<int>(len));
}

// ========== TEST 1: Ieee1609Dot2Data unsecuredData ==========
TEST(RoundTrip, Ieee1609Unsecured) {
    uint8_t payload_data[] = {0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04};

    Ieee1609Dot2Data_t data;
    memset(&data, 0, sizeof(data));
    data.protocolVersion = 3;

    Ieee1609Dot2Content_t content;
    memset(&content, 0, sizeof(content));
    content.present = Ieee1609Dot2Content_PR_unsecuredData;
    fill_octet(&content.choice.unsecuredData, payload_data, sizeof(payload_data));
    data.content = &content;

    ASSERT_TRUE(round_trip(&asn_DEF_Ieee1609Dot2Data, &data, "Ieee1609Dot2Data.unsecured"));

    ASN_STRUCT_RESET(asn_DEF_Ieee1609Dot2Content, &content);
}

// ========== TEST 2: Ieee1609Dot2Data signedData (self-signed, P-256) ==========
TEST(RoundTrip, Ieee1609Signed) {
    uint8_t dummy32[32];
    memset(dummy32, 0xAB, sizeof(dummy32));
    uint8_t dummy_payload[] = {0xCA, 0xFE};

    Ieee1609Dot2Data_t inner_data;
    memset(&inner_data, 0, sizeof(inner_data));
    inner_data.protocolVersion = 3;
    Ieee1609Dot2Content_t inner_content;
    memset(&inner_content, 0, sizeof(inner_content));
    inner_content.present = Ieee1609Dot2Content_PR_unsecuredData;
    fill_octet(&inner_content.choice.unsecuredData, dummy_payload, sizeof(dummy_payload));
    inner_data.content = &inner_content;

    SignedDataPayload_t payload;
    memset(&payload, 0, sizeof(payload));
    payload.data = &inner_data;

    HeaderInfo_t hdr;
    memset(&hdr, 0, sizeof(hdr));
    hdr.psid = 36;

    ToBeSignedData_t tbs;
    memset(&tbs, 0, sizeof(tbs));
    tbs.payload = &payload;
    tbs.headerInfo = &hdr;

    SignerIdentifier_t signer;
    memset(&signer, 0, sizeof(signer));
    signer.present = SignerIdentifier_PR_self;

    EccP256CurvePoint_t r_point;
    memset(&r_point, 0, sizeof(r_point));
    r_point.present = EccP256CurvePoint_PR_x_only;
    fill_octet(&r_point.choice.x_only, dummy32, 32);

    EcdsaP256Signature_t ecdsa_sig;
    memset(&ecdsa_sig, 0, sizeof(ecdsa_sig));
    ecdsa_sig.rSig = &r_point;
    fill_octet(&ecdsa_sig.sSig, dummy32, 32);

    Signature_t sig;
    memset(&sig, 0, sizeof(sig));
    sig.present = Signature_PR_ecdsaNistP256Signature;
    sig.choice.ecdsaNistP256Signature = &ecdsa_sig;

    SignedData_t sd;
    memset(&sd, 0, sizeof(sd));
    sd.hashId = HashAlgorithm_sha256;
    sd.tbsData = &tbs;
    sd.signer = &signer;
    sd.signature = &sig;

    Ieee1609Dot2Content_t outer_content;
    memset(&outer_content, 0, sizeof(outer_content));
    outer_content.present = Ieee1609Dot2Content_PR_signedData;
    outer_content.choice.signedData = &sd;

    Ieee1609Dot2Data_t outer;
    memset(&outer, 0, sizeof(outer));
    outer.protocolVersion = 3;
    outer.content = &outer_content;

    ASSERT_TRUE(round_trip(&asn_DEF_Ieee1609Dot2Data, &outer, "Ieee1609Dot2Data.signed"));

    ASN_STRUCT_RESET(asn_DEF_Ieee1609Dot2Content, &inner_content);
    ASN_STRUCT_RESET(asn_DEF_EccP256CurvePoint, &r_point);
    free(ecdsa_sig.sSig.buf);
    ecdsa_sig.sSig.buf = nullptr;
}

// ========== TEST 3: ToBeSignedCrl with entries ==========
TEST(RoundTrip, CrlWithEntries) {
    ToBeSignedCrl_t crl;
    memset(&crl, 0, sizeof(crl));
    crl.version = 1;
    crl.thisUpdate = 1000000;
    crl.nextUpdate = 2000000;

    uint8_t hash_data[3][8] = {
        {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
        {0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18},
        {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x99},
    };

    CrlEntry_t entries[3];
    for (int i = 0; i < 3; i++) {
        memset(&entries[i], 0, sizeof(CrlEntry_t));
        fill_octet(&entries[i], hash_data[i], 8);
        ASN_SEQUENCE_ADD(&crl.entries, &entries[i]);
    }

    ASSERT_TRUE(round_trip(&asn_DEF_ToBeSignedCrl, &crl, "ToBeSignedCrl"));

    for (int i = 0; i < 3; i++) {
        free(entries[i].buf);
        entries[i].buf = nullptr;
    }
    free(crl.entries.list.array);
    crl.entries.list.array = nullptr;
}

// ========== TEST 4: CtlFormat (empty ECTL) ==========
TEST(RoundTrip, CtlFormat) {
    CtlFormat_t ctl;
    memset(&ctl, 0, sizeof(ctl));
    ctl.version = 1;
    ctl.nextUpdate = 3000000;
    ctl.isFullCtl = 1;
    ctl.ctlSequence = 42;

    ASSERT_TRUE(round_trip(&asn_DEF_CtlFormat, &ctl, "CtlFormat"));
}

// ========== TEST 5: Ieee1609Dot2Data unsecured with payloads of different sizes ==========
TEST(RoundTrip, Ieee1609UnsecuredSizes) {
    const uint8_t sizes[] = {1, 16, 64, 128, 255};
    for (size_t si = 0; si < sizeof(sizes) / sizeof(sizes[0]); si++) {
        std::vector<uint8_t> payload(sizes[si], static_cast<uint8_t>(si + 0x10));

        Ieee1609Dot2Data_t data;
        memset(&data, 0, sizeof(data));
        data.protocolVersion = 3;

        Ieee1609Dot2Content_t content;
        memset(&content, 0, sizeof(content));
        content.present = Ieee1609Dot2Content_PR_unsecuredData;
        fill_octet(&content.choice.unsecuredData, payload.data(), payload.size());
        data.content = &content;

        EXPECT_TRUE(round_trip(&asn_DEF_Ieee1609Dot2Data, &data, "Ieee1609Dot2Data.unsecured.size"))
            << "payload size=" << static_cast<int>(sizes[si]);

        ASN_STRUCT_RESET(asn_DEF_Ieee1609Dot2Content, &content);
    }
}

// ========== TEST 6: Ieee1609Dot2Data signedData with digest signer ==========
TEST(RoundTrip, Ieee1609SignedDigest) {
    uint8_t dummy32[32];
    memset(dummy32, 0xCD, sizeof(dummy32));
    uint8_t dummy8[8] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    uint8_t payload_bytes[] = {0xBE, 0xEF};

    Ieee1609Dot2Data_t inner_data;
    memset(&inner_data, 0, sizeof(inner_data));
    inner_data.protocolVersion = 3;
    Ieee1609Dot2Content_t inner_content;
    memset(&inner_content, 0, sizeof(inner_content));
    inner_content.present = Ieee1609Dot2Content_PR_unsecuredData;
    fill_octet(&inner_content.choice.unsecuredData, payload_bytes, sizeof(payload_bytes));
    inner_data.content = &inner_content;

    SignedDataPayload_t payload;
    memset(&payload, 0, sizeof(payload));
    payload.data = &inner_data;

    HeaderInfo_t hdr;
    memset(&hdr, 0, sizeof(hdr));
    hdr.psid = 36;

    ToBeSignedData_t tbs;
    memset(&tbs, 0, sizeof(tbs));
    tbs.payload = &payload;
    tbs.headerInfo = &hdr;

    SignerIdentifier_t signer;
    memset(&signer, 0, sizeof(signer));
    signer.present = SignerIdentifier_PR_digest;
    fill_octet(&signer.choice.digest, dummy8, 8);

    EccP256CurvePoint_t r_point;
    memset(&r_point, 0, sizeof(r_point));
    r_point.present = EccP256CurvePoint_PR_x_only;
    fill_octet(&r_point.choice.x_only, dummy32, 32);

    EcdsaP256Signature_t ecdsa_sig;
    memset(&ecdsa_sig, 0, sizeof(ecdsa_sig));
    ecdsa_sig.rSig = &r_point;
    fill_octet(&ecdsa_sig.sSig, dummy32, 32);

    Signature_t sig;
    memset(&sig, 0, sizeof(sig));
    sig.present = Signature_PR_ecdsaNistP256Signature;
    sig.choice.ecdsaNistP256Signature = &ecdsa_sig;

    SignedData_t sd;
    memset(&sd, 0, sizeof(sd));
    sd.hashId = HashAlgorithm_sha256;
    sd.tbsData = &tbs;
    sd.signer = &signer;
    sd.signature = &sig;

    Ieee1609Dot2Content_t outer_content;
    memset(&outer_content, 0, sizeof(outer_content));
    outer_content.present = Ieee1609Dot2Content_PR_signedData;
    outer_content.choice.signedData = &sd;

    Ieee1609Dot2Data_t outer;
    memset(&outer, 0, sizeof(outer));
    outer.protocolVersion = 3;
    outer.content = &outer_content;

    ASSERT_TRUE(round_trip(&asn_DEF_Ieee1609Dot2Data, &outer, "Ieee1609Dot2Data.signed.digest"));

    ASN_STRUCT_RESET(asn_DEF_Ieee1609Dot2Content, &inner_content);
    ASN_STRUCT_RESET(asn_DEF_EccP256CurvePoint, &r_point);
    free(ecdsa_sig.sSig.buf);
    ecdsa_sig.sSig.buf = nullptr;
    free(signer.choice.digest.buf);
    signer.choice.digest.buf = nullptr;
}

// ========== TEST 7: ToBeSignedCrl empty (no entries) ==========
TEST(RoundTrip, CrlEmpty) {
    ToBeSignedCrl_t crl;
    memset(&crl, 0, sizeof(crl));
    crl.version = 1;
    crl.thisUpdate = 500000;
    crl.nextUpdate = 600000;

    ASSERT_TRUE(round_trip(&asn_DEF_ToBeSignedCrl, &crl, "ToBeSignedCrl.empty"));
}

// ========== TEST 8: CtlFormat with high ctlSequence ==========
TEST(RoundTrip, CtlFormatHighSeq) {
    CtlFormat_t ctl;
    memset(&ctl, 0, sizeof(ctl));
    ctl.version = 1;
    ctl.nextUpdate = 9999999;
    ctl.isFullCtl = 0;
    ctl.ctlSequence = 255;

    ASSERT_TRUE(round_trip(&asn_DEF_CtlFormat, &ctl, "CtlFormat.high_seq"));
}

// ========== TEST 9: EtsiTs102941Data stub ==========
TEST(RoundTrip, Etsi102941Data) {
    uint8_t dummy32[32];
    memset(dummy32, 0x77, sizeof(dummy32));
    uint8_t inner_payload[] = {0x01, 0x02, 0x03};

    Ieee1609Dot2Data_t inner;
    memset(&inner, 0, sizeof(inner));
    inner.protocolVersion = 3;
    Ieee1609Dot2Content_t inner_content;
    memset(&inner_content, 0, sizeof(inner_content));
    inner_content.present = Ieee1609Dot2Content_PR_unsecuredData;
    fill_octet(&inner_content.choice.unsecuredData, inner_payload, sizeof(inner_payload));
    inner.content = &inner_content;

    SignedDataPayload_t payload;
    memset(&payload, 0, sizeof(payload));
    payload.data = &inner;

    HeaderInfo_t hdr;
    memset(&hdr, 0, sizeof(hdr));
    hdr.psid = 36;

    ToBeSignedData_t tbs;
    memset(&tbs, 0, sizeof(tbs));
    tbs.payload = &payload;
    tbs.headerInfo = &hdr;

    SignerIdentifier_t signer;
    memset(&signer, 0, sizeof(signer));
    signer.present = SignerIdentifier_PR_self;

    EccP256CurvePoint_t r_point;
    memset(&r_point, 0, sizeof(r_point));
    r_point.present = EccP256CurvePoint_PR_x_only;
    fill_octet(&r_point.choice.x_only, dummy32, 32);

    EcdsaP256Signature_t ecdsa_sig;
    memset(&ecdsa_sig, 0, sizeof(ecdsa_sig));
    ecdsa_sig.rSig = &r_point;
    fill_octet(&ecdsa_sig.sSig, dummy32, 32);

    Signature_t sig;
    memset(&sig, 0, sizeof(sig));
    sig.present = Signature_PR_ecdsaNistP256Signature;
    sig.choice.ecdsaNistP256Signature = &ecdsa_sig;

    SignedData_t sd;
    memset(&sd, 0, sizeof(sd));
    sd.hashId = HashAlgorithm_sha256;
    sd.tbsData = &tbs;
    sd.signer = &signer;
    sd.signature = &sig;

    Ieee1609Dot2Content_t signed_content;
    memset(&signed_content, 0, sizeof(signed_content));
    signed_content.present = Ieee1609Dot2Content_PR_signedData;
    signed_content.choice.signedData = &sd;

    Ieee1609Dot2Data_t signed_data;
    memset(&signed_data, 0, sizeof(signed_data));
    signed_data.protocolVersion = 3;
    signed_data.content = &signed_content;

    ASSERT_TRUE(round_trip(&asn_DEF_Ieee1609Dot2Data, &signed_data, "EtsiTs102941Data.stub"));

    ASN_STRUCT_RESET(asn_DEF_Ieee1609Dot2Content, &inner_content);
    ASN_STRUCT_RESET(asn_DEF_EccP256CurvePoint, &r_point);
    free(ecdsa_sig.sSig.buf);
    ecdsa_sig.sSig.buf = nullptr;
}

// ========== TEST 10: Ieee1609Dot2Data signedData with compressed_y_0 ==========
TEST(RoundTrip, Ieee1609SignedCompressed) {
    uint8_t dummy32[32];
    memset(dummy32, 0xEE, sizeof(dummy32));
    uint8_t payload_bytes[] = {0xAA};

    Ieee1609Dot2Data_t inner_data;
    memset(&inner_data, 0, sizeof(inner_data));
    inner_data.protocolVersion = 3;
    Ieee1609Dot2Content_t inner_content;
    memset(&inner_content, 0, sizeof(inner_content));
    inner_content.present = Ieee1609Dot2Content_PR_unsecuredData;
    fill_octet(&inner_content.choice.unsecuredData, payload_bytes, sizeof(payload_bytes));
    inner_data.content = &inner_content;

    SignedDataPayload_t payload;
    memset(&payload, 0, sizeof(payload));
    payload.data = &inner_data;

    HeaderInfo_t hdr;
    memset(&hdr, 0, sizeof(hdr));
    hdr.psid = 36;

    ToBeSignedData_t tbs;
    memset(&tbs, 0, sizeof(tbs));
    tbs.payload = &payload;
    tbs.headerInfo = &hdr;

    SignerIdentifier_t signer;
    memset(&signer, 0, sizeof(signer));
    signer.present = SignerIdentifier_PR_self;

    EccP256CurvePoint_t r_point;
    memset(&r_point, 0, sizeof(r_point));
    r_point.present = EccP256CurvePoint_PR_compressed_y_0;
    fill_octet(&r_point.choice.compressed_y_0, dummy32, 32);

    EcdsaP256Signature_t ecdsa_sig;
    memset(&ecdsa_sig, 0, sizeof(ecdsa_sig));
    ecdsa_sig.rSig = &r_point;
    fill_octet(&ecdsa_sig.sSig, dummy32, 32);

    Signature_t sig;
    memset(&sig, 0, sizeof(sig));
    sig.present = Signature_PR_ecdsaNistP256Signature;
    sig.choice.ecdsaNistP256Signature = &ecdsa_sig;

    SignedData_t sd;
    memset(&sd, 0, sizeof(sd));
    sd.hashId = HashAlgorithm_sha256;
    sd.tbsData = &tbs;
    sd.signer = &signer;
    sd.signature = &sig;

    Ieee1609Dot2Content_t outer_content;
    memset(&outer_content, 0, sizeof(outer_content));
    outer_content.present = Ieee1609Dot2Content_PR_signedData;
    outer_content.choice.signedData = &sd;

    Ieee1609Dot2Data_t outer;
    memset(&outer, 0, sizeof(outer));
    outer.protocolVersion = 3;
    outer.content = &outer_content;

    ASSERT_TRUE(round_trip(&asn_DEF_Ieee1609Dot2Data, &outer,
                           "Ieee1609Dot2Data.signed.compressed_y_0"));

    ASN_STRUCT_RESET(asn_DEF_Ieee1609Dot2Content, &inner_content);
    ASN_STRUCT_RESET(asn_DEF_EccP256CurvePoint, &r_point);
    free(ecdsa_sig.sSig.buf);
    ecdsa_sig.sSig.buf = nullptr;
}

// ========== TEST 11: ToBeSignedCrl with many entries ==========
TEST(RoundTrip, CrlManyEntries) {
    ToBeSignedCrl_t crl;
    memset(&crl, 0, sizeof(crl));
    crl.version = 1;
    crl.thisUpdate = 1000000;
    crl.nextUpdate = 2000000;

    CrlEntry_t entries[10];
    for (int i = 0; i < 10; i++) {
        memset(&entries[i], 0, sizeof(CrlEntry_t));
        uint8_t hash[8];
        memset(hash, static_cast<uint8_t>(i + 1), 8);
        fill_octet(&entries[i], hash, 8);
        ASN_SEQUENCE_ADD(&crl.entries, &entries[i]);
    }

    ASSERT_TRUE(round_trip(&asn_DEF_ToBeSignedCrl, &crl, "ToBeSignedCrl.10_entries"));

    for (int i = 0; i < 10; i++) {
        free(entries[i].buf);
        entries[i].buf = nullptr;
    }
    free(crl.entries.list.array);
    crl.entries.list.array = nullptr;
}

// ========== TEST 12: Ieee1609Dot2Data with varied unsecured payloads ==========
TEST(RoundTrip, Ieee1609VariedPayloads) {
    const uint8_t patterns[] = {0x00, 0xFF, 0x55, 0xAA, 0x42};
    for (size_t i = 0; i < sizeof(patterns) / sizeof(patterns[0]); i++) {
        uint8_t payload_data[32];
        memset(payload_data, patterns[i], sizeof(payload_data));

        Ieee1609Dot2Data_t data;
        memset(&data, 0, sizeof(data));
        data.protocolVersion = 3;

        Ieee1609Dot2Content_t content;
        memset(&content, 0, sizeof(content));
        content.present = Ieee1609Dot2Content_PR_unsecuredData;
        fill_octet(&content.choice.unsecuredData, payload_data, sizeof(payload_data));
        data.content = &content;

        EXPECT_TRUE(round_trip(&asn_DEF_Ieee1609Dot2Data, &data, "Ieee1609Dot2Data.payload"))
            << "pattern=0x" << std::hex << static_cast<int>(patterns[i]);

        ASN_STRUCT_RESET(asn_DEF_Ieee1609Dot2Content, &content);
    }
}
