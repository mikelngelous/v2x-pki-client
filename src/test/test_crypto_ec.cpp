#include <gtest/gtest.h>

#include "v2xpki/crypto_ec.hpp"

using namespace v2xpki;
using namespace v2xpki::crypto;

// ===== P-256-only tests (original coverage, non-parameterized) =====

TEST(CryptoP256, Keygen) {
    auto kp = generate_keypair();
    ASSERT_TRUE(kp.has_value());
    EXPECT_EQ(kp->public_key.size(), 65u);
    EXPECT_EQ(kp->public_key[0], 0x04);
    EXPECT_EQ(kp->private_key.size(), 32u);
}

TEST(CryptoP256, SignVerifyA) {
    auto kp = generate_keypair();
    ASSERT_TRUE(kp.has_value());

    std::vector<uint8_t> msg = {0xDE, 0xAD, 0xBE, 0xEF};
    auto sig = ecdsa_sign(kp->private_key, msg);
    ASSERT_TRUE(sig.has_value());
    EXPECT_EQ(sig->r.size(), 32u);
    EXPECT_EQ(sig->s.size(), 32u);

    EXPECT_TRUE(ecdsa_verify(kp->public_key, msg, *sig));
}

TEST(CryptoP256, SignVerifyB) {
    auto kp = generate_keypair();
    ASSERT_TRUE(kp.has_value());

    std::vector<uint8_t> msg(256, 0x42);
    auto sig = ecdsa_sign(kp->private_key, msg);
    ASSERT_TRUE(sig.has_value());
    EXPECT_TRUE(ecdsa_verify(kp->public_key, msg, *sig));
}

TEST(CryptoP256, SignVerifyEmpty) {
    auto kp = generate_keypair();
    ASSERT_TRUE(kp.has_value());

    std::vector<uint8_t> msg;
    auto sig = ecdsa_sign(kp->private_key, msg);
    ASSERT_TRUE(sig.has_value());
    EXPECT_TRUE(ecdsa_verify(kp->public_key, msg, *sig));
}

TEST(CryptoP256, SignDifferentKeys) {
    auto kp1 = generate_keypair();
    auto kp2 = generate_keypair();
    ASSERT_TRUE(kp1.has_value() && kp2.has_value());

    std::vector<uint8_t> msg = {0x01, 0x02, 0x03};
    auto sig1 = ecdsa_sign(kp1->private_key, msg);
    auto sig2 = ecdsa_sign(kp2->private_key, msg);
    ASSERT_TRUE(sig1.has_value() && sig2.has_value());
    EXPECT_FALSE(sig1->r == sig2->r && sig1->s == sig2->s);
}

TEST(CryptoP256, VerifyWrongMessage) {
    auto kp = generate_keypair();
    ASSERT_TRUE(kp.has_value());

    std::vector<uint8_t> msg = {0xAA, 0xBB};
    auto sig = ecdsa_sign(kp->private_key, msg);
    ASSERT_TRUE(sig.has_value());

    std::vector<uint8_t> wrong = {0xCC, 0xDD};
    EXPECT_FALSE(ecdsa_verify(kp->public_key, wrong, *sig));
}

TEST(CryptoP256, VerifyWrongPubkey) {
    auto kp1 = generate_keypair();
    auto kp2 = generate_keypair();
    ASSERT_TRUE(kp1.has_value() && kp2.has_value());

    std::vector<uint8_t> msg = {0x11, 0x22, 0x33};
    auto sig = ecdsa_sign(kp1->private_key, msg);
    ASSERT_TRUE(sig.has_value());
    EXPECT_FALSE(ecdsa_verify(kp2->public_key, msg, *sig));
}

TEST(CryptoP256, EcdhConvergence) {
    auto alice = generate_keypair();
    auto bob = generate_keypair();
    ASSERT_TRUE(alice.has_value() && bob.has_value());

    auto ss_ab = ecdh_derive(alice->private_key, bob->public_key);
    auto ss_ba = ecdh_derive(bob->private_key, alice->public_key);
    ASSERT_TRUE(ss_ab.has_value() && ss_ba.has_value());
    EXPECT_EQ(*ss_ab, *ss_ba);
    EXPECT_EQ(ss_ab->size(), 32u);
}

TEST(CryptoP256, AesCcmRoundtrip) {
    std::vector<uint8_t> key(16, 0xAA);
    std::vector<uint8_t> nonce(12, 0xBB);
    std::vector<uint8_t> plaintext = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                                      0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10};

    auto enc = aes_128_ccm_encrypt(key, nonce, plaintext);
    ASSERT_TRUE(enc.has_value());
    EXPECT_EQ(enc->ciphertext.size(), plaintext.size());
    EXPECT_EQ(enc->tag.size(), 16u);

    auto dec = aes_128_ccm_decrypt(key, nonce, enc->ciphertext, enc->tag);
    ASSERT_TRUE(dec.has_value());
    EXPECT_EQ(*dec, plaintext);
}

TEST(CryptoP256, AesCcmTamper) {
    std::vector<uint8_t> key(16, 0xCC);
    std::vector<uint8_t> nonce(12, 0xDD);
    std::vector<uint8_t> plaintext(32, 0xEE);

    auto enc = aes_128_ccm_encrypt(key, nonce, plaintext);
    ASSERT_TRUE(enc.has_value());

    auto tampered = enc->ciphertext;
    tampered[0] ^= 0xFF;
    auto dec = aes_128_ccm_decrypt(key, nonce, tampered, enc->tag);
    EXPECT_FALSE(dec.has_value());
}

TEST(CryptoP256, Ecies16) {
    auto recipient = generate_keypair();
    ASSERT_TRUE(recipient.has_value());

    std::vector<uint8_t> plaintext(16, 0x42);
    auto enc = ecies_encrypt(recipient->public_key, plaintext);
    ASSERT_TRUE(enc.has_value());
    EXPECT_EQ(enc->ephemeral_pubkey.size(), 65u);

    auto dec = ecies_decrypt(recipient->private_key, *enc);
    ASSERT_TRUE(dec.has_value());
    EXPECT_EQ(*dec, plaintext);
}

TEST(CryptoP256, Ecies256) {
    auto recipient = generate_keypair();
    ASSERT_TRUE(recipient.has_value());

    std::vector<uint8_t> plaintext(256, 0xAB);
    auto enc = ecies_encrypt(recipient->public_key, plaintext);
    ASSERT_TRUE(enc.has_value());

    auto dec = ecies_decrypt(recipient->private_key, *enc);
    ASSERT_TRUE(dec.has_value());
    EXPECT_EQ(*dec, plaintext);
}

TEST(CryptoP256, Ecies1024) {
    auto recipient = generate_keypair();
    ASSERT_TRUE(recipient.has_value());

    std::vector<uint8_t> plaintext(1024);
    for (size_t i = 0; i < plaintext.size(); i++)
        plaintext[i] = static_cast<uint8_t>(i & 0xFF);

    auto enc = ecies_encrypt(recipient->public_key, plaintext);
    ASSERT_TRUE(enc.has_value());

    auto dec = ecies_decrypt(recipient->private_key, *enc);
    ASSERT_TRUE(dec.has_value());
    EXPECT_EQ(*dec, plaintext);
}

TEST(CryptoP256, EciesTamper) {
    auto recipient = generate_keypair();
    ASSERT_TRUE(recipient.has_value());

    std::vector<uint8_t> plaintext(64, 0x77);
    auto enc = ecies_encrypt(recipient->public_key, plaintext);
    ASSERT_TRUE(enc.has_value());

    auto tampered = *enc;
    tampered.encrypted_key[0] ^= 0xFF;
    auto dec = ecies_decrypt(recipient->private_key, tampered);
    EXPECT_FALSE(dec.has_value());
}

TEST(CryptoP256, HashSha256) {
    // SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    std::vector<uint8_t> empty;
    auto h = hash_sha256(empty);
    EXPECT_EQ(h.size(), 32u);
    EXPECT_EQ(h[0], 0xe3);
    EXPECT_EQ(h[1], 0xb0);
    EXPECT_EQ(h[2], 0xc4);
    EXPECT_EQ(h[31], 0x55);
}

// ===== Multi-curve parameterized tests (TEST_P) =====

class CryptoMultiCurve : public ::testing::TestWithParam<Curve> {};

TEST_P(CryptoMultiCurve, KeygenSizes) {
    Curve c = GetParam();
    auto kp = generate_keypair(c);
    ASSERT_TRUE(kp.has_value()) << "keygen failed for " << to_string(c);
    EXPECT_EQ(kp->public_key.size(), pubkey_len(c));
    EXPECT_EQ(kp->public_key[0], 0x04);
    EXPECT_EQ(kp->private_key.size(), scalar_len(c));
}

TEST_P(CryptoMultiCurve, SignVerifyDigest) {
    Curve c = GetParam();
    auto kp = generate_keypair(c);
    ASSERT_TRUE(kp.has_value());

    std::vector<uint8_t> msg = {0xDE, 0xAD, 0xBE, 0xEF};
    auto digest = hash_for_curve(msg, c);
    EXPECT_EQ(digest.size(), hash_len(c));

    auto sig = ecdsa_sign_digest(kp->private_key, digest, c);
    ASSERT_TRUE(sig.has_value()) << "sign failed for " << to_string(c);
    EXPECT_EQ(sig->r.size(), scalar_len(c));
    EXPECT_EQ(sig->s.size(), scalar_len(c));

    EXPECT_TRUE(ecdsa_verify_digest(kp->public_key, digest, *sig, c))
        << "verify failed for " << to_string(c);
}

TEST_P(CryptoMultiCurve, SignVerifyWrongDigestFails) {
    Curve c = GetParam();
    auto kp = generate_keypair(c);
    ASSERT_TRUE(kp.has_value());

    std::vector<uint8_t> msg = {0xAA, 0xBB};
    auto digest = hash_for_curve(msg, c);
    auto sig = ecdsa_sign_digest(kp->private_key, digest, c);
    ASSERT_TRUE(sig.has_value());

    std::vector<uint8_t> wrong_msg = {0xCC, 0xDD};
    auto wrong_digest = hash_for_curve(wrong_msg, c);
    EXPECT_FALSE(ecdsa_verify_digest(kp->public_key, wrong_digest, *sig, c));
}

TEST_P(CryptoMultiCurve, EcdhConvergence) {
    Curve c = GetParam();
    auto alice = generate_keypair(c);
    auto bob = generate_keypair(c);
    ASSERT_TRUE(alice.has_value() && bob.has_value());

    auto ss_ab = ecdh_derive(alice->private_key, bob->public_key, c);
    auto ss_ba = ecdh_derive(bob->private_key, alice->public_key, c);
    ASSERT_TRUE(ss_ab.has_value() && ss_ba.has_value());
    EXPECT_EQ(*ss_ab, *ss_ba);
    EXPECT_EQ(ss_ab->size(), scalar_len(c));
}

TEST_P(CryptoMultiCurve, EciesRoundTrip) {
    Curve c = GetParam();
    auto recipient = generate_keypair(c);
    ASSERT_TRUE(recipient.has_value());

    std::vector<uint8_t> plaintext(64, 0x42);
    auto enc = ecies_encrypt(recipient->public_key, plaintext, {}, c);
    ASSERT_TRUE(enc.has_value()) << "ECIES encrypt failed for " << to_string(c);
    EXPECT_EQ(enc->ephemeral_pubkey.size(), pubkey_len(c));

    auto dec = ecies_decrypt(recipient->private_key, *enc, {}, c);
    ASSERT_TRUE(dec.has_value()) << "ECIES decrypt failed for " << to_string(c);
    EXPECT_EQ(*dec, plaintext);
}

TEST_P(CryptoMultiCurve, EciesTamperFails) {
    Curve c = GetParam();
    auto recipient = generate_keypair(c);
    ASSERT_TRUE(recipient.has_value());

    std::vector<uint8_t> plaintext(32, 0x77);
    auto enc = ecies_encrypt(recipient->public_key, plaintext, {}, c);
    ASSERT_TRUE(enc.has_value());

    auto tampered = *enc;
    tampered.encrypted_key[0] ^= 0xFF;
    auto dec = ecies_decrypt(recipient->private_key, tampered, {}, c);
    EXPECT_FALSE(dec.has_value());
}

INSTANTIATE_TEST_SUITE_P(AllCurves, CryptoMultiCurve,
                         ::testing::Values(Curve::NistP256, Curve::BrainpoolP256r1,
                                           Curve::BrainpoolP384r1),
                         [](const ::testing::TestParamInfo<Curve>& info) {
                             switch (info.param) {
                                 case Curve::NistP256: return std::string("NistP256");
                                 case Curve::BrainpoolP256r1: return std::string("BrainpoolP256r1");
                                 case Curve::BrainpoolP384r1: return std::string("BrainpoolP384r1");
                             }
                             return std::string("Unknown");
                         });
