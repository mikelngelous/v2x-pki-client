// CLI I/O helpers: hex formatting, file read/write, cert summary.

#include "io.hpp"
#include "v2xpki/crypto_ec.hpp"

#include "internal/cert_parse.hpp"
#include "v2xpki/sizes.hpp"

extern "C" {
#include "CertificateBase.h"
#include "SequenceOfPsidSsp.h"
#include "PsidSsp.h"
#include "asn_application.h"
}

#include <algorithm>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>

namespace v2xpki::cli {

std::string bytes_to_hex(const uint8_t *data, size_t len) {
    std::ostringstream oss;
    for (size_t i = 0; i < len; ++i)
        oss << std::hex << std::setfill('0') << std::setw(2) << std::uppercase
            << static_cast<int>(data[i]);
    return oss.str();
}

std::string hid8_hex(const std::array<uint8_t, 8> &h) {
    return bytes_to_hex(h.data(), kHashedId8Len);
}

std::array<uint8_t, 8> hex_to_hid8(const std::string &hex) {
    std::array<uint8_t, 8> out{};
    if (hex.size() < 16) return out;
    for (int i = 0; i < 8; ++i) {
        auto byte_str = hex.substr(static_cast<size_t>(i) * 2, 2);
        try {
            out[static_cast<size_t>(i)] = static_cast<uint8_t>(std::stoul(byte_str, nullptr, 16));
        } catch (...) {
            return {};
        }
    }
    return out;
}

std::string body_to_string(const std::vector<uint8_t> &body) { return {body.begin(), body.end()}; }

std::vector<uint8_t> read_file(const std::string &path) {
    std::ifstream ifs(path, std::ios::binary);
    if (!ifs) return {};
    return {std::istreambuf_iterator<char>(ifs), std::istreambuf_iterator<char>()};
}

bool write_file(const std::string &path, const std::vector<uint8_t> &data) {
    std::ofstream ofs(path, std::ios::binary);
    if (!ofs) return false;
    ofs.write(reinterpret_cast<const char *>(data.data()),
              static_cast<std::streamsize>(data.size()));
    return ofs.good();
}

std::array<uint8_t, 8> compute_hid8(const std::vector<uint8_t> &cert_coer) {
    return cert::compute_hid8(cert_coer);
}

CertSummary parse_cert_summary(const std::vector<uint8_t> &coer) {
    CertSummary s;
    s.size_bytes = coer.size();

    void *structure = nullptr;
    auto dr = asn_decode(nullptr, ATS_CANONICAL_OER, &asn_DEF_CertificateBase, &structure,
                         coer.data(), coer.size());
    if (dr.code != RC_OK || !structure) {
        if (structure) ASN_STRUCT_FREE(asn_DEF_CertificateBase, structure);
        return s;
    }

    auto *cert = static_cast<CertificateBase_t *>(structure);
    s.valid = true;
    s.hid8 = compute_hid8(coer);

    if (cert->issuer) {
        if (cert->issuer->present == IssuerIdentifier_PR_self) {
            s.self_signed = true;
        } else if (cert->issuer->present == IssuerIdentifier_PR_sha256AndDigest) {
            auto &d = cert->issuer->choice.sha256AndDigest;
            if (d.buf && d.size == 8) std::copy_n(d.buf, 8, s.issuer_hid8.begin());
        }
    }

    if (cert->toBeSigned && cert->toBeSigned->appPermissions) {
        auto *perms = cert->toBeSigned->appPermissions;
        for (int i = 0; i < perms->list.count; ++i) {
            if (perms->list.array[i])
                s.psids.push_back(static_cast<int64_t>(perms->list.array[i]->psid));
        }
    }

    ASN_STRUCT_FREE(asn_DEF_CertificateBase, structure);
    return s;
}

void print_cert_summary(const CertSummary &s, bool json) {
    if (json) {
        std::cout << "{\"hid8\":\"" << hid8_hex(s.hid8) << "\",\"issuer_hid8\":\""
                  << hid8_hex(s.issuer_hid8)
                  << "\",\"self_signed\":" << (s.self_signed ? "true" : "false")
                  << ",\"size\":" << s.size_bytes << ",\"psids\":[";
        for (size_t i = 0; i < s.psids.size(); ++i) {
            if (i > 0) std::cout << ",";
            std::cout << s.psids[i];
        }
        std::cout << "]}" << '\n';
    } else {
        std::cout << "  HID8:           " << hid8_hex(s.hid8) << "\n";
        if (s.self_signed)
            std::cout << "  Issuer:         self-signed\n";
        else
            std::cout << "  Issuer HID8:    " << hid8_hex(s.issuer_hid8) << "\n";
        std::cout << "  Size:           " << s.size_bytes << " bytes\n";
        if (!s.psids.empty()) {
            std::cout << "  PSIDs:          ";
            for (size_t i = 0; i < s.psids.size(); ++i) {
                if (i > 0) std::cout << ", ";
                std::cout << s.psids[i];
            }
            std::cout << "\n";
        }
    }
}

} // namespace v2xpki::cli
