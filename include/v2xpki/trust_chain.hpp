#pragma once

#include <array>
#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <vector>

namespace v2xpki {

struct CertInfo {
    std::vector<uint8_t> cert_bytes;          // COER-encoded cert (wire format)
    std::array<uint8_t, 8> hashed_id_8;       // SHA-256(cert_bytes)[-8:]
    std::vector<uint8_t> public_key;          // verification key P-256 uncompressed (65 bytes)
    std::vector<uint8_t> encryption_key;      // ECIES encryption key P-256 uncompressed (65 bytes); empty if cert has none
    std::array<uint8_t, 8> issuer_hash_id_8;  // issuer HID8 (0 if self-signed)
    bool is_self_signed;
    std::vector<uint8_t> tbs_bytes;           // toBeSigned COER (for signature verification)
    std::vector<uint8_t> signature_r;         // 32 bytes
    std::vector<uint8_t> signature_s;         // 32 bytes
    std::string label;                        // descriptive name
};

class TrustChain {
public:
    // Loads *.cert (COER) files; the filename prefix selects the role
    // (rca_*, aa_*, ea_*, tlm_*, at_*).
    bool load_from_directory(const std::string& certs_dir);

    bool add_cert(const CertInfo& ci);

    std::optional<CertInfo> find_by_hashed_id_8(const std::array<uint8_t, 8>& hid8) const;

    // Validates AT → AA → RCA.
    bool validate_chain(const CertInfo& at_cert) const;

    std::vector<CertInfo> get_rcas() const;
    std::vector<CertInfo> get_aas() const;
    std::vector<CertInfo> get_eas() const;
    std::vector<CertInfo> get_tlms() const;

    size_t size() const { return certs_.size(); }

private:
    std::map<std::array<uint8_t, 8>, CertInfo> certs_;

    bool verify_cert_signature(const CertInfo& cert, const CertInfo& issuer) const;
    std::vector<CertInfo> get_by_prefix(const std::string& prefix) const;
};

// Helpers to build synthetic cert pools for tests.
namespace cert_utils {

// Encode ToBeSignedCertificate to UPER bytes.
std::vector<uint8_t> encode_tbs_uper(
    const std::string& name,
    const std::vector<uint8_t>& public_key,  // 65 bytes uncompressed
    bool is_ca,
    uint32_t start_time,
    uint16_t duration_years);

// Build full CertificateBase, sign with issuer key, encode UPER → CertInfo
std::optional<CertInfo> build_signed_cert(
    const std::string& name,
    const std::vector<uint8_t>& subject_public_key,
    const std::vector<uint8_t>& issuer_private_key,
    const std::array<uint8_t, 8>& issuer_hid8,
    bool is_ca,
    bool is_self_signed);

// Build self-signed root cert
std::optional<CertInfo> build_root_cert(
    const std::string& name,
    const std::vector<uint8_t>& public_key,
    const std::vector<uint8_t>& private_key);

}  // namespace cert_utils
}  // namespace v2xpki
