// Response authentication (TS 102 941 §6.2.3.2.2).

#include "internal/encrypted_data.hpp"
#include "v2xpki/crypto_ec.hpp"
#include "v2xpki/trust_chain.hpp"

#include <gtest/gtest.h>

extern "C" {
#include "EncryptedData.h"
#include "HashedId8.h"
#include "Ieee1609Dot2Content.h"
#include "Ieee1609Dot2Data.h"
#include "One28BitCcmCiphertext.h"
#include "RecipientInfo.h"
#include "SequenceOfRecipientInfo.h"
#include "SymmetricCiphertext.h"
#include "constr_TYPE.h"
}

#include <cstring>
#include <vector>

using namespace v2xpki;

namespace {

constexpr uint8_t kEnrolmentResponseTag = 0x81;

void fill_octet(OCTET_STRING_t *os, const std::vector<uint8_t> &data) {
    OCTET_STRING_fromBuf(os, reinterpret_cast<const char *>(data.data()),
                         static_cast<int>(data.size()));
}

std::vector<uint8_t> encode(const asn_TYPE_descriptor_t *td, void *sptr) {
    auto res = asn_encode_to_new_buffer(nullptr, ATS_CANONICAL_OER, td, sptr);
    EXPECT_GT(res.result.encoded, 0);
    auto *p = static_cast<uint8_t *>(res.buffer);
    std::vector<uint8_t> out(p, p + res.result.encoded);
    free(res.buffer);
    return out;
}

std::vector<uint8_t> unsecured_pdu(const std::vector<uint8_t> &payload) {
    Ieee1609Dot2Data_t data;
    memset(&data, 0, sizeof(data));
    data.protocolVersion = 3;

    Ieee1609Dot2Content_t content;
    memset(&content, 0, sizeof(content));
    content.present = Ieee1609Dot2Content_PR_unsecuredData;
    fill_octet(&content.choice.unsecuredData, payload);
    data.content = &content;

    auto out = encode(&asn_DEF_Ieee1609Dot2Data, &data);
    ASN_STRUCT_RESET(asn_DEF_Ieee1609Dot2Content, &content);
    return out;
}

std::vector<uint8_t> psk_encrypt(const std::vector<uint8_t> &plaintext,
                                 const std::vector<uint8_t> &aes_key) {
    std::vector<uint8_t> nonce(kAesCcmNonceLen, 0x5A);
    auto ccm_res = crypto::aes_128_ccm_encrypt(aes_key, nonce, plaintext);
    EXPECT_TRUE(ccm_res.has_value());

    std::vector<uint8_t> ct = ccm_res->ciphertext;
    ct.insert(ct.end(), ccm_res->tag.begin(), ccm_res->tag.end());

    RecipientInfo_t ri;
    memset(&ri, 0, sizeof(ri));
    ri.present = RecipientInfo_PR_pskRecipInfo;
    std::vector<uint8_t> psk_id(kHashedId8Len, 0x11);
    fill_octet(&ri.choice.pskRecipInfo, psk_id);

    SequenceOfRecipientInfo_t recipients;
    memset(&recipients, 0, sizeof(recipients));
    ASN_SEQUENCE_ADD(&recipients, &ri);

    One28BitCcmCiphertext_t ccm;
    memset(&ccm, 0, sizeof(ccm));
    fill_octet(&ccm.nonce, nonce);
    fill_octet(&ccm.ccmCiphertext, ct);

    SymmetricCiphertext_t sym;
    memset(&sym, 0, sizeof(sym));
    sym.present = SymmetricCiphertext_PR_aes128ccm;
    sym.choice.aes128ccm = &ccm;

    EncryptedData_t enc;
    memset(&enc, 0, sizeof(enc));
    enc.recipients = &recipients;
    enc.ciphertext = &sym;

    Ieee1609Dot2Content_t content;
    memset(&content, 0, sizeof(content));
    content.present = Ieee1609Dot2Content_PR_encryptedData;
    content.choice.encryptedData = &enc;

    Ieee1609Dot2Data_t outer;
    memset(&outer, 0, sizeof(outer));
    outer.protocolVersion = 3;
    outer.content = &content;

    auto out = encode(&asn_DEF_Ieee1609Dot2Data, &outer);

    free(ri.choice.pskRecipInfo.buf);
    free(recipients.list.array);
    free(ccm.nonce.buf);
    free(ccm.ccmCiphertext.buf);
    return out;
}

CertInfo signer_with_random_key() {
    CertInfo ci;
    auto kp = crypto::generate_keypair();
    EXPECT_TRUE(kp.has_value());
    ci.public_key = *StaticBytes<kP384PublicKeyLen>::from(kp->public_key.to_vector());
    ci.curve = Curve::NistP256;
    return ci;
}

} // namespace

TEST(ResponseAuth, UnsignedInnerPduIsRejected) {
    std::vector<uint8_t> aes_key(kAesKeyLen, 0x42);
    std::vector<uint8_t> inner_payload = {0x01, kEnrolmentResponseTag, 0xDE, 0xAD};

    auto response = psk_encrypt(unsecured_pdu(inner_payload), aes_key);
    auto out = enc::decrypt_and_unwrap(response, {}, aes_key, kEnrolmentResponseTag,
                                       signer_with_random_key());

    EXPECT_FALSE(out.has_value());
}

TEST(ResponseAuth, DecryptionAloneDoesNotAuthenticate) {
    std::vector<uint8_t> aes_key(kAesKeyLen, 0x42);
    std::vector<uint8_t> plaintext = {0xBE, 0xEF, 0xCA, 0xFE};

    auto response = psk_encrypt(plaintext, aes_key);
    auto out = enc::decrypt_and_unwrap(response, {}, aes_key, kEnrolmentResponseTag,
                                       signer_with_random_key());

    EXPECT_FALSE(out.has_value());
}

TEST(ResponseAuth, WrongPskFailsBeforeVerification) {
    std::vector<uint8_t> aes_key(kAesKeyLen, 0x42);
    std::vector<uint8_t> wrong_key(kAesKeyLen, 0x43);

    auto response = psk_encrypt(unsecured_pdu({0xAA, 0xBB}), aes_key);
    auto out = enc::decrypt_and_unwrap(response, {}, wrong_key, kEnrolmentResponseTag,
                                       signer_with_random_key());

    ASSERT_FALSE(out.has_value());
    EXPECT_EQ(out.error(), Error::Crypto);
}
