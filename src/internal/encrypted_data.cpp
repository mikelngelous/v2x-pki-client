// EncryptedData builder + response decrypt/unwrap.

#include "encrypted_data.hpp"
#include "asn_ptr.hpp"
#include "coer.hpp"
#include "signed_message.hpp"
#include "curve_point.hpp"
#include "v2xpki/sizes.hpp"

extern "C" {
#include "Ieee1609Dot2Data.h"
#include "Ieee1609Dot2Content.h"
#include "EncryptedData.h"
#include "SequenceOfRecipientInfo.h"
#include "RecipientInfo.h"
#include "PKRecipientInfo.h"
#include "EncryptedDataEncryptionKey.h"
#include "EciesP256EncryptedKey.h"
#include "SymmetricCiphertext.h"
#include "One28BitCcmCiphertext.h"
#include "SignedData.h"
#include "ToBeSignedData.h"
#include "SignedDataPayload.h"
}

namespace v2xpki::enc {

Ieee1609Dot2Data *build_encrypted_data(const crypto::EciesEncryptResult &ecies,
                                       const CertInfo &recipient_cert, Curve curve) {

    auto *wrapper = asn_calloc<Ieee1609Dot2Data_t>();
    wrapper->protocolVersion = kIeee1609Dot2Version;

    auto *enc_content = asn_calloc<Ieee1609Dot2Content_t>();
    enc_content->present = Ieee1609Dot2Content_PR_encryptedData;

    auto *enc_data = asn_calloc<EncryptedData_t>();

    auto *recipients = asn_calloc<SequenceOfRecipientInfo_t>();
    auto *ri = asn_calloc<RecipientInfo_t>();
    ri->present = RecipientInfo_PR_certRecipInfo;

    auto *pk_ri = asn_calloc<PKRecipientInfo_t>();
    octet::set(&pk_ri->recipientId, recipient_cert.hashed_id_8.data(), kHashedId8Len);

    auto *enc_key = asn_calloc<EncryptedDataEncryptionKey_t>();
    auto *ecies_k = asn_calloc<EciesP256EncryptedKey_t>();
    ecies_k->v = point::from_sec1(ecies.ephemeral_pubkey);
    octet::set(&ecies_k->c, ecies.encrypted_key.data(), ecies.encrypted_key.size());
    octet::set(&ecies_k->t, ecies.tag_kdf.data(), ecies.tag_kdf.size());
    // Brainpool certs use eciesBrainpoolP256r1; NIST uses eciesNistP256.
    // Both variants share the same EciesP256EncryptedKey structure.
    if (curve == Curve::BrainpoolP256r1 || curve == Curve::BrainpoolP384r1) {
        enc_key->present = EncryptedDataEncryptionKey_PR_eciesBrainpoolP256r1;
        enc_key->choice.eciesBrainpoolP256r1 = ecies_k;
    } else {
        enc_key->present = EncryptedDataEncryptionKey_PR_eciesNistP256;
        enc_key->choice.eciesNistP256 = ecies_k;
    }
    pk_ri->encKey = enc_key;
    ri->choice.certRecipInfo = pk_ri;
    ASN_SEQUENCE_ADD(&recipients->list, ri);
    enc_data->recipients = recipients;

    auto *ct = asn_calloc<SymmetricCiphertext_t>();
    ct->present = SymmetricCiphertext_PR_aes128ccm;
    auto *ccm = asn_calloc<One28BitCcmCiphertext_t>();
    octet::set(&ccm->nonce, ecies.nonce_ccm.data(), ecies.nonce_ccm.size());
    std::vector<uint8_t> ct_tag;
    ct_tag.insert(ct_tag.end(), ecies.ciphertext.begin(), ecies.ciphertext.end());
    ct_tag.insert(ct_tag.end(), ecies.tag_ccm.begin(), ecies.tag_ccm.end());
    octet::set(&ccm->ccmCiphertext, ct_tag.data(), ct_tag.size());
    ct->choice.aes128ccm = ccm;
    enc_data->ciphertext = ct;

    enc_content->choice.encryptedData = enc_data;
    wrapper->content = enc_content;
    return wrapper;
}

namespace {

// Extract plaintext from Ieee1609Dot2Data{encryptedData} via PSK or ECIES.
std::optional<std::vector<uint8_t>> decrypt_encrypted_content(const EncryptedData_t *enc,
                                                              const std::vector<uint8_t>
                                                                  &recipient_private_key,
                                                              const std::vector<uint8_t>
                                                                  &request_aes_key) {

    if (!enc || !enc->recipients || enc->recipients->list.count < 1 || !enc->ciphertext)
        return std::nullopt;

    if (enc->ciphertext->present != SymmetricCiphertext_PR_aes128ccm ||
        !enc->ciphertext->choice.aes128ccm)
        return std::nullopt;

    auto *ccm = enc->ciphertext->choice.aes128ccm;
    auto nonce = octet::bytes(&ccm->nonce);
    auto ct_with_tag = octet::bytes(&ccm->ccmCiphertext);
    if (ct_with_tag.size() < kAesCcmTagLen) return std::nullopt;

    std::vector<uint8_t> ciphertext(ct_with_tag.begin(), ct_with_tag.end() - kAesCcmTagLen);
    std::vector<uint8_t> tag_ccm(ct_with_tag.end() - kAesCcmTagLen, ct_with_tag.end());

    auto *ri0 = enc->recipients->list.array[0];

    if (ri0 && ri0->present == RecipientInfo_PR_pskRecipInfo && !request_aes_key.empty()) {
        return crypto::aes_128_ccm_decrypt(request_aes_key, nonce, ciphertext, tag_ccm);
    }

    if (ri0 && ri0->present == RecipientInfo_PR_certRecipInfo && ri0->choice.certRecipInfo) {
        auto *pk_ri = ri0->choice.certRecipInfo;
        if (!pk_ri->encKey) return std::nullopt;

        EciesP256EncryptedKey_t *ecies_key = nullptr;
        Curve ecies_curve = Curve::NistP256;

        if (pk_ri->encKey->present == EncryptedDataEncryptionKey_PR_eciesNistP256) {
            ecies_key = pk_ri->encKey->choice.eciesNistP256;
        } else if (pk_ri->encKey->present == EncryptedDataEncryptionKey_PR_eciesBrainpoolP256r1) {
            ecies_key = pk_ri->encKey->choice.eciesBrainpoolP256r1;
            ecies_curve = Curve::BrainpoolP256r1;
        }

        if (!ecies_key || !ecies_key->v) return std::nullopt;

        crypto::EciesEncryptResult ecies_params;
        ecies_params.ephemeral_pubkey = point::to_sec1(ecies_key->v);
        if (ecies_params.ephemeral_pubkey.empty()) return std::nullopt;

        ecies_params.encrypted_key = octet::bytes(&ecies_key->c);
        ecies_params.tag_kdf = octet::bytes(&ecies_key->t);
        ecies_params.nonce_ccm = nonce;
        ecies_params.ciphertext = ciphertext;
        ecies_params.tag_ccm = tag_ccm;

        return crypto::ecies_decrypt(recipient_private_key, ecies_params, {}, ecies_curve);
    }

    return std::nullopt;
}

}

Result<std::vector<uint8_t>> decrypt_and_unwrap(const std::vector<uint8_t> &response_bytes,
                                                const std::vector<uint8_t> &recipient_private_key,
                                                const std::vector<uint8_t> &request_aes_key,
                                                uint8_t etsi_response_tag,
                                                const CertInfo &signer_cert) {

    auto outer = asn_decode<Ieee1609Dot2Data_t>(asn_DEF_Ieee1609Dot2Data, response_bytes.data(),
                                                response_bytes.size());
    if (!outer) return Error::Decode;

    if (!outer->content || outer->content->present != Ieee1609Dot2Content_PR_encryptedData)
        return Error::Decode;

    auto plaintext = decrypt_encrypted_content(outer->content->choice.encryptedData,
                                               recipient_private_key, request_aes_key);
    if (!plaintext) return Error::Crypto;

    auto signed_inner = signed_msg::unwrap(*plaintext);
    if (!signed_inner) return Error::Decode;
    if (!signed_msg::verify(*signed_inner, signer_cert.public_key.to_vector(),
                            signer_cert.cert_bytes.to_vector()))
        return Error::SignatureInvalid;

    const auto &inner_bytes = signed_inner->payload_coer;

    // Strip EtsiTs102941Data prefix: version(0x01) + CHOICE tag
    if (inner_bytes.size() > 2 && inner_bytes[0] == 0x01 && inner_bytes[1] == etsi_response_tag) {
        return std::vector<uint8_t>(inner_bytes.begin() + 2, inner_bytes.end());
    }

    return inner_bytes;
}

} // namespace v2xpki::enc
