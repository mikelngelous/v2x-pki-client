#pragma once

// Elliptic curve primitives (IEEE 1609.2 §5.3.5).
// Supports NIST P-256, brainpoolP256r1, brainpoolP384r1.
// OpenSSL 3.x EVP backend, static dispatch via Curve enum.

#include <cstdint>
#include <optional>
#include <vector>

#include "v2xpki/key_store.hpp"
#include "v2xpki/sizes.hpp"

namespace v2xpki::crypto {

// --- Key generation ---
std::optional<KeyPair> generate_keypair();
std::optional<KeyPair> generate_keypair(Curve curve);

// --- ECDSA + hash-per-curve ---
std::optional<Signature> ecdsa_sign(const std::vector<uint8_t>& private_key,
                                    const std::vector<uint8_t>& message);

std::optional<Signature> ecdsa_sign_digest(const std::vector<uint8_t>& private_key,
                                           const std::vector<uint8_t>& digest);

// Curve-aware overloads
std::optional<Signature> ecdsa_sign_digest(const std::vector<uint8_t>& private_key,
                                           const std::vector<uint8_t>& digest, Curve curve);

bool ecdsa_verify(const std::vector<uint8_t>& public_key, const std::vector<uint8_t>& message,
                  const Signature& sig);

bool ecdsa_verify_digest(const std::vector<uint8_t>& public_key, const std::vector<uint8_t>& digest,
                         const Signature& sig);

// Curve-aware overload
bool ecdsa_verify_digest(const std::vector<uint8_t>& public_key, const std::vector<uint8_t>& digest,
                         const Signature& sig, Curve curve);

// --- ECDH ---
std::optional<std::vector<uint8_t>> ecdh_derive(const std::vector<uint8_t>& private_key,
                                                const std::vector<uint8_t>& peer_public_key);
std::optional<std::vector<uint8_t>> ecdh_derive(const std::vector<uint8_t>& private_key,
                                                const std::vector<uint8_t>& peer_public_key,
                                                Curve curve);

// --- Hashing (dispatch by curve) ---
std::vector<uint8_t> hash_sha256(const std::vector<uint8_t>& data);
std::vector<uint8_t> hash_sha384(const std::vector<uint8_t>& data);
std::vector<uint8_t> hash_for_curve(const std::vector<uint8_t>& data, Curve curve);

std::vector<uint8_t> kdf2_sha256(const std::vector<uint8_t>& shared_secret,
                                 const std::vector<uint8_t>& p1, size_t out_len);

// --- AES-128-CCM ---
struct AesCcmResult {
    std::vector<uint8_t> ciphertext;
    std::vector<uint8_t> tag; // 16 bytes
};

std::optional<AesCcmResult> aes_128_ccm_encrypt(const std::vector<uint8_t>& key, // 16 bytes
                                                const std::vector<uint8_t>& nonce, // 12 bytes
                                                const std::vector<uint8_t>& plaintext);

std::optional<std::vector<uint8_t>> aes_128_ccm_decrypt(const std::vector<uint8_t>& key, // 16 bytes
                                                        const std::vector<uint8_t>&
                                                            nonce, // 12 bytes
                                                        const std::vector<uint8_t>& ciphertext,
                                                        const std::vector<uint8_t>&
                                                            tag); // 16 bytes

// --- ECIES IEEE 1609.2 §5.3.5 (KEM + DEM) ---
struct EciesEncryptResult {
    std::vector<uint8_t> ephemeral_pubkey; // 65 bytes uncompressed
    std::vector<uint8_t> encrypted_key; // 16 bytes (C = K1 XOR k_aes)
    std::vector<uint8_t> tag_kdf; // 16 bytes (HMAC-SHA-256 truncated)
    std::vector<uint8_t> nonce_ccm; // 12 bytes
    std::vector<uint8_t> ciphertext; // same length as plaintext
    std::vector<uint8_t> tag_ccm; // 16 bytes
    std::vector<uint8_t> aes_key; // 16 bytes (k_aes, for PSK response decrypt)
};

std::optional<EciesEncryptResult> ecies_encrypt(const std::vector<uint8_t>& recipient_public_key,
                                                const std::vector<uint8_t>& plaintext,
                                                const std::vector<uint8_t>& p1 = {});

std::optional<EciesEncryptResult> ecies_encrypt(const std::vector<uint8_t>& recipient_public_key,
                                                const std::vector<uint8_t>& plaintext,
                                                const std::vector<uint8_t>& p1, Curve curve);

std::optional<std::vector<uint8_t>> ecies_decrypt(const std::vector<uint8_t>& recipient_private_key,
                                                  const EciesEncryptResult& encrypted,
                                                  const std::vector<uint8_t>& p1 = {});

std::optional<std::vector<uint8_t>> ecies_decrypt(const std::vector<uint8_t>& recipient_private_key,
                                                  const EciesEncryptResult& encrypted,
                                                  const std::vector<uint8_t>& p1, Curve curve);

// --- OpenSSL NID for curve ---
int curve_nid(Curve curve) noexcept;
const char* curve_group_name(Curve curve) noexcept;

} // namespace v2xpki::crypto
