// ECIES IEEE 1609.2 §5.3.5 — KDF2, AES-128-CCM, KEM+DEM encrypt/decrypt.

#include "v2xpki/crypto_ec.hpp"

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#include <algorithm>
#include <cstring>
#include <memory>

#include "v2xpki/sizes.hpp"
#include "internal/openssl_ptr.hpp"

namespace v2xpki::crypto {

using namespace v2xpki::ssl;

// KDF2 (X9.63) with SHA-256: IEEE 1609.2 §5.3.5
std::vector<uint8_t> kdf2_sha256(const std::vector<uint8_t>& shared_secret,
                                 const std::vector<uint8_t>& p1, size_t out_len) {

    std::vector<uint8_t> result;
    result.reserve(out_len);
    uint32_t counter = 1;

    while (result.size() < out_len) {
        uint8_t ctr_bytes[4];
        ctr_bytes[0] = static_cast<uint8_t>((counter >> 24) & 0xFF);
        ctr_bytes[1] = static_cast<uint8_t>((counter >> 16) & 0xFF);
        ctr_bytes[2] = static_cast<uint8_t>((counter >> 8) & 0xFF);
        ctr_bytes[3] = static_cast<uint8_t>(counter & 0xFF);

        EvpMdCtxPtr ctx(EVP_MD_CTX_new());
        EVP_DigestInit_ex(ctx.get(), EVP_sha256(), nullptr);
        EVP_DigestUpdate(ctx.get(), shared_secret.data(), shared_secret.size());
        EVP_DigestUpdate(ctx.get(), ctr_bytes, 4);
        if (!p1.empty()) {
            EVP_DigestUpdate(ctx.get(), p1.data(), p1.size());
        }

        uint8_t hash[kSha256Len];
        unsigned int hash_len = 0;
        EVP_DigestFinal_ex(ctx.get(), hash, &hash_len);

        size_t to_copy = std::min(static_cast<size_t>(hash_len), out_len - result.size());
        result.insert(result.end(), hash, hash + to_copy);
        ++counter;
    }

    return result;
}

// ============ AES-128-CCM ============

std::optional<AesCcmResult> aes_128_ccm_encrypt(const std::vector<uint8_t>& key,
                                                const std::vector<uint8_t>& nonce,
                                                const std::vector<uint8_t>& plaintext) {

    if (key.size() != kAesKeyLen || nonce.size() != kAesCcmNonceLen) return std::nullopt;

    const int tag_len = 16;
    std::vector<uint8_t> ciphertext(plaintext.size());
    std::vector<uint8_t> tag(tag_len);

    EvpCipherCtxPtr ctx(EVP_CIPHER_CTX_new());
    if (!ctx) return std::nullopt;

    int ok = 1;
    ok = ok && EVP_EncryptInit_ex(ctx.get(), EVP_aes_128_ccm(), nullptr, nullptr, nullptr);
    ok = ok && EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_CCM_SET_IVLEN,
                                   static_cast<int>(nonce.size()), nullptr);
    ok = ok && EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_CCM_SET_TAG, tag_len, nullptr);
    ok = ok && EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), nonce.data());

    int outl = 0;
    ok = ok &&
         EVP_EncryptUpdate(ctx.get(), nullptr, &outl, nullptr, static_cast<int>(plaintext.size()));
    ok = ok && EVP_EncryptUpdate(ctx.get(), ciphertext.data(), &outl, plaintext.data(),
                                 static_cast<int>(plaintext.size()));

    int final_outl = 0;
    ok = ok && EVP_EncryptFinal_ex(ctx.get(), ciphertext.data() + outl, &final_outl);
    ok = ok && EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_CCM_GET_TAG, tag_len, tag.data());

    if (!ok) return std::nullopt;

    return AesCcmResult{std::move(ciphertext), std::move(tag)};
}

std::optional<std::vector<uint8_t>> aes_128_ccm_decrypt(const std::vector<uint8_t>& key,
                                                        const std::vector<uint8_t>& nonce,
                                                        const std::vector<uint8_t>& ciphertext,
                                                        const std::vector<uint8_t>& tag) {

    if (key.size() != kAesKeyLen || nonce.size() != kAesCcmNonceLen || tag.size() != kAesCcmTagLen)
        return std::nullopt;

    std::vector<uint8_t> plaintext(ciphertext.size());

    EvpCipherCtxPtr ctx(EVP_CIPHER_CTX_new());
    if (!ctx) return std::nullopt;

    int ok = 1;
    ok = ok && EVP_DecryptInit_ex(ctx.get(), EVP_aes_128_ccm(), nullptr, nullptr, nullptr);
    ok = ok && EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_CCM_SET_IVLEN,
                                   static_cast<int>(nonce.size()), nullptr);
    ok = ok && EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_CCM_SET_TAG, static_cast<int>(tag.size()),
                                   const_cast<uint8_t*>(tag.data()));
    ok = ok && EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), nonce.data());

    int outl = 0;
    ok = ok &&
         EVP_DecryptUpdate(ctx.get(), nullptr, &outl, nullptr, static_cast<int>(ciphertext.size()));
    int rv = EVP_DecryptUpdate(ctx.get(), plaintext.data(), &outl, ciphertext.data(),
                               static_cast<int>(ciphertext.size()));

    if (!ok || rv <= 0) return std::nullopt;

    plaintext.resize(outl);
    return plaintext;
}

// ============ ECIES IEEE 1609.2 §5.3.5 ============

std::optional<EciesEncryptResult> ecies_encrypt(const std::vector<uint8_t>& recipient_public_key,
                                                const std::vector<uint8_t>& plaintext,
                                                const std::vector<uint8_t>& p1) {
    return ecies_encrypt(recipient_public_key, plaintext, p1, Curve::NistP256);
}

std::optional<EciesEncryptResult> ecies_encrypt(const std::vector<uint8_t>& recipient_public_key,
                                                const std::vector<uint8_t>& plaintext,
                                                const std::vector<uint8_t>& p1, Curve curve) {

    auto eph = generate_keypair(curve);
    if (!eph) return std::nullopt;

    auto ss = ecdh_derive(eph->private_key, recipient_public_key, curve);
    if (!ss) return std::nullopt;

    auto kdf_out = kdf2_sha256(*ss, p1, kAesKeyLen + kP256ScalarLen);
    std::vector<uint8_t> k1(kdf_out.begin(), kdf_out.begin() + kAesKeyLen);
    std::vector<uint8_t> k2(kdf_out.begin() + kAesKeyLen, kdf_out.end());

    std::vector<uint8_t> k_aes(kAesKeyLen);
    RAND_bytes(k_aes.data(), kAesKeyLen);

    std::vector<uint8_t> c_encrypted(kAesKeyLen);
    for (int i = 0; i < static_cast<int>(kAesKeyLen); i++) {
        c_encrypted[i] = k1[i] ^ k_aes[i];
    }

    std::vector<uint8_t> hmac_full(kSha256Len);
    unsigned int hmac_len = 0;
    HMAC(EVP_sha256(), k2.data(), static_cast<int>(k2.size()), c_encrypted.data(),
         c_encrypted.size(), hmac_full.data(), &hmac_len);
    std::vector<uint8_t> tag_kdf(hmac_full.begin(), hmac_full.begin() + kAesKeyLen);

    std::vector<uint8_t> nonce(kAesCcmNonceLen);
    RAND_bytes(nonce.data(), kAesCcmNonceLen);

    auto ccm = aes_128_ccm_encrypt(k_aes, nonce, plaintext);
    if (!ccm) return std::nullopt;

    return EciesEncryptResult{eph->public_key,  std::move(c_encrypted),     std::move(tag_kdf),
                              std::move(nonce), std::move(ccm->ciphertext), std::move(ccm->tag),
                              std::move(k_aes)};
}

std::optional<std::vector<uint8_t>> ecies_decrypt(const std::vector<uint8_t>& recipient_private_key,
                                                  const EciesEncryptResult& enc,
                                                  const std::vector<uint8_t>& p1) {
    return ecies_decrypt(recipient_private_key, enc, p1, Curve::NistP256);
}

std::optional<std::vector<uint8_t>> ecies_decrypt(const std::vector<uint8_t>& recipient_private_key,
                                                  const EciesEncryptResult& enc,
                                                  const std::vector<uint8_t>& p1, Curve curve) {

    auto ss = ecdh_derive(recipient_private_key, enc.ephemeral_pubkey, curve);
    if (!ss) return std::nullopt;

    auto kdf_out = kdf2_sha256(*ss, p1, kAesKeyLen + kP256ScalarLen);
    std::vector<uint8_t> k1(kdf_out.begin(), kdf_out.begin() + kAesKeyLen);
    std::vector<uint8_t> k2(kdf_out.begin() + kAesKeyLen, kdf_out.end());

    std::vector<uint8_t> hmac_full(kSha256Len);
    unsigned int hmac_len = 0;
    HMAC(EVP_sha256(), k2.data(), static_cast<int>(k2.size()), enc.encrypted_key.data(),
         enc.encrypted_key.size(), hmac_full.data(), &hmac_len);

    if (enc.tag_kdf.size() != kAesKeyLen ||
        memcmp(hmac_full.data(), enc.tag_kdf.data(), kAesKeyLen) != 0) {
        return std::nullopt;
    }

    if (enc.encrypted_key.size() != kAesKeyLen) return std::nullopt;
    std::vector<uint8_t> k_aes(kAesKeyLen);
    for (int i = 0; i < static_cast<int>(kAesKeyLen); i++) {
        k_aes[i] = k1[i] ^ enc.encrypted_key[i];
    }

    return aes_128_ccm_decrypt(k_aes, enc.nonce_ccm, enc.ciphertext, enc.tag_ccm);
}

} // namespace v2xpki::crypto
