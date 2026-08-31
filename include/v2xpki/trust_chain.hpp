#pragma once

#include <array>
#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <vector>

#include "v2xpki/sizes.hpp"
#include "v2xpki/static_bytes.hpp"

namespace v2xpki {

class RevocationStore;

int64_t current_tai_seconds();

struct CertInfo {
    StaticBytes<kMaxCoerMessageLen> cert_bytes; // COER-encoded cert (wire format)
    std::array<uint8_t, 8> hashed_id_8; // SHA-256(cert_bytes)[-8:]
    StaticBytes<kP384PublicKeyLen> public_key; // verification key uncompressed (65 or 97 bytes)
    StaticBytes<kP256PublicKeyLen>
        encryption_key; // ECIES encryption key uncompressed (always P-256 family); empty if none
    Curve
        enc_curve = Curve::NistP256; // encryption key curve (eciesNistP256 vs eciesBrainpoolP256r1)
    std::array<uint8_t, 8> issuer_hash_id_8; // issuer HID8 (0 if self-signed)
    bool is_self_signed = false;
    StaticBytes<kMaxCoerMessageLen> tbs_bytes; // toBeSigned COER (for signature verification)
    StaticBytes<kP384ScalarLen> signature_r; // 32 or 48 bytes
    StaticBytes<kP384ScalarLen> signature_s; // 32 or 48 bytes
    Curve curve = Curve::NistP256; // detected from PublicVerificationKey variant
    uint32_t validity_start = 0; // Time32, seconds since the TAI epoch
    // Zero = no usable duration, and reads as already expired (see cert_parse).
    uint64_t validity_duration_seconds = 0;
    std::string label; // descriptive name

    // TS 103 097 v2.2.1 §6: "start inclusive and the end exclusive". Not stated in v1.4.1.
    bool valid_at(int64_t tai_seconds) const {
        if (validity_duration_seconds == 0) return false;
        auto start = static_cast<int64_t>(validity_start);
        return tai_seconds >= start &&
               tai_seconds < start + static_cast<int64_t>(validity_duration_seconds);
    }
};

class TrustChain {
public:
    // Loads *.cert (COER) files; the filename prefix selects the role
    // (rca_*, aa_*, ea_*, tlm_*, at_*).
    bool load_from_directory(const std::string& certs_dir);

    bool add_cert(const CertInfo& ci);

    std::optional<CertInfo> find_by_hashed_id_8(const std::array<uint8_t, 8>& hid8) const;

    // Role-agnostic: an EC → EA → RCA chain validates like an AT → AA → RCA one.
    bool validate_chain(const CertInfo& at_cert, int64_t now_tai = current_tai_seconds()) const;

    std::vector<CertInfo> get_rcas() const;
    std::vector<CertInfo> get_aas() const;
    std::vector<CertInfo> get_eas() const;
    std::vector<CertInfo> get_tlms() const;

    size_t size() const { return certs_.size(); }

    // IEEE 1609.2 §5.3.1 certificate signature verification (double-hash).
    bool verify_cert_signature(const CertInfo& cert, const CertInfo& issuer) const;

    // Not owned; must outlive this TrustChain.
    void set_revocation_store(const RevocationStore* store) { revocation_ = store; }

private:
    std::map<std::array<uint8_t, 8>, CertInfo> certs_;
    const RevocationStore* revocation_ = nullptr;

    std::vector<CertInfo> get_by_prefix(const std::string& prefix) const;
    bool is_revoked_by_issuer(const CertInfo& cert, const CertInfo& issuer) const;
};

// Helpers to build synthetic cert pools for tests.
namespace cert_utils {

// Encode ToBeSignedCertificate to UPER bytes.
std::vector<uint8_t> encode_tbs_uper(const std::string& name,
                                     const std::vector<uint8_t>&
                                         public_key, // 65 bytes uncompressed
                                     bool is_ca, uint32_t start_time, uint16_t duration_years);

// Build full CertificateBase, sign with issuer key, encode COER → CertInfo
std::optional<CertInfo> build_signed_cert(const std::string& name,
                                          const std::vector<uint8_t>& subject_public_key,
                                          const std::vector<uint8_t>& issuer_private_key,
                                          const std::array<uint8_t, 8>& issuer_hid8, bool is_ca,
                                          bool is_self_signed,
                                          const std::vector<uint8_t>& issuer_cert_bytes = {});

// Build self-signed root cert
std::optional<CertInfo> build_root_cert(const std::string& name,
                                        const std::vector<uint8_t>& public_key,
                                        const std::vector<uint8_t>& private_key);

} // namespace cert_utils
} // namespace v2xpki
