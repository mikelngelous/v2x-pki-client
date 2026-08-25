// CLI subcommand handlers.

#include "commands.hpp"
#include "io.hpp"
#include "v2xpki/facade.hpp"
#include "v2xpki/version.hpp"
#include "v2xpki/crypto_ec.hpp"
#include "v2xpki/http_client.hpp"
#include "v2xpki/plaintext_file_key_store.hpp"
#include "v2xpki/trust_list.hpp"
#include "v2xpki/sizes.hpp"

extern "C" {
#include "Ieee1609Dot2Data.h"
#include "Ieee1609Dot2Content.h"
#include "SignedData.h"
#include "SignerIdentifier.h"
#include "asn_application.h"
}

#include <cctype>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>

using namespace std::chrono_literals;

namespace v2xpki::cli {

int cmd_healthz(const Args &a) {
    if (a.pki_url.empty()) {
        std::cerr << "error: --pki-url required\n";
        return 1;
    }
    HttpClient http(HttpClientConfig{"", 15s, true});
    auto resp = http.get(a.pki_url + "/healthz");
    if (!resp) {
        std::cerr << "error: request failed: " << to_string(resp.error()) << "\n";
        return 1;
    }
    if (resp->status_code != 200) {
        std::cerr << "error: HTTP " << resp->status_code << "\n";
        return 1;
    }
    std::cout << body_to_string(resp->body) << '\n';
    return 0;
}

int cmd_version(const Args &a) {
    if (a.pki_url.empty()) {
        std::cerr << "error: --pki-url required\n";
        return 1;
    }
    HttpClient http(HttpClientConfig{"", 15s, true});
    auto resp = http.get(a.pki_url + "/version");
    if (!resp) {
        std::cerr << "error: request failed: " << to_string(resp.error()) << "\n";
        return 1;
    }
    if (resp->status_code != 200) {
        std::cerr << "error: HTTP " << resp->status_code << "\n";
        return 1;
    }
    std::cout << body_to_string(resp->body) << '\n';
    return 0;
}

int cmd_info(const Args &a) {
    if (a.json) {
        std::cout << "{\"name\":\"v2x-pki-client\",\"version\":\"" << v2xpki::kVersion << "\""
                  << ",\"crypto\":\"NIST P-256 / brainpoolP256r1 / brainpoolP384r1\""
                  << ",\"encoding\":\"COER (TS 103 097 v1.3.1)\""
                  << ",\"specs\":\"TS 102 941 v2.2.1 / IEEE 1609.2\""
                  << ",\"keystore\":\"plaintext (DEV)\"}" << '\n';
    } else {
        std::cout << "v2x-pki-client v" << v2xpki::kVersion << "\n"
                  << "  Crypto:    NIST P-256 / brainpoolP256r1 / brainpoolP384r1\n"
                  << "  Encoding:  COER (TS 103 097 v1.3.1)\n"
                  << "  Specs:     TS 102 941 v2.2.1 / IEEE 1609.2\n"
                  << "  KeyStore:  plaintext (DEV ONLY)\n";
    }
    return 0;
}

int cmd_fetch_trust(const Args &a) {
    if (a.pki_url.empty() || a.out_dir.empty()) {
        std::cerr << "error: --pki-url and --out-dir required\n";
        return 1;
    }

    namespace fs = std::filesystem;
    fs::create_directories(a.out_dir);

    HttpClient http(HttpClientConfig{"", 15s, true});
    struct FetchItem {
        const char *endpoint;
        const char *filename;
        const char *label;
    };
    FetchItem items[] = {
        {"/trustanchor", "rca.cert", "RCA"},
        {"/tlm", "tlm.cert", "TLM"},
        {"/ma", "ma.cert", "MA"},
    };

    int errors = 0;
    for (const auto &item : items) {
        auto resp = http.get(a.pki_url + item.endpoint);
        if (!resp) {
            std::cerr << "error: failed to fetch " << item.label << ": " << to_string(resp.error())
                      << "\n";
            ++errors;
            continue;
        }
        if (resp->status_code != 200) {
            std::cerr << "error: failed to fetch " << item.label << " (HTTP " << resp->status_code
                      << ")\n";
            ++errors;
            continue;
        }

        auto path = (fs::path(a.out_dir) / item.filename).string();
        if (!write_file(path, resp->body)) {
            std::cerr << "error: failed to write " << path << "\n";
            ++errors;
            continue;
        }

        auto summary = parse_cert_summary(resp->body);
        if (a.json) {
            std::cout << "{\"cert\":\"" << item.label << "\",\"file\":\"" << path
                      << "\",\"size\":" << resp->body.size() << ",\"hid8\":\""
                      << hid8_hex(summary.hid8) << "\"}" << '\n';
        } else {
            std::cout << item.label << " -> " << path << " (" << resp->body.size() << "B)\n";
            if (summary.valid) print_cert_summary(summary, false);
        }
    }
    return errors > 0 ? 1 : 0;
}

int cmd_lookup_cert(const Args &a) {
    if (a.pki_url.empty() || a.hid8.empty()) {
        std::cerr << "error: --pki-url and --hid8 required\n";
        return 1;
    }

    HttpClient http(HttpClientConfig{"", 15s, true});
    auto resp = http.get(a.pki_url + "/lookup/" + a.hid8);
    if (!resp) {
        std::cerr << "error: lookup failed: " << to_string(resp.error()) << "\n";
        return 1;
    }
    if (resp->status_code != 200) {
        std::cerr << "error: lookup failed (HTTP " << resp->status_code << ")\n";
        return 1;
    }

    auto summary = parse_cert_summary(resp->body);
    if (!summary.valid) {
        std::cerr << "error: failed to parse cert COER\n";
        return 1;
    }

    if (!a.out.empty() && !write_file(a.out, resp->body)) {
        std::cerr << "error: cannot write " << a.out << "\n";
        return 1;
    }

    if (a.json) {
        print_cert_summary(summary, true);
    } else {
        std::cout << "Cert lookup " << a.hid8 << ":\n";
        print_cert_summary(summary, false);
        if (!a.out.empty()) std::cout << "  Saved:          " << a.out << "\n";
    }
    return 0;
}

int cmd_verify_hid8(const Args &a) {
    if (a.cert_path.empty()) {
        std::cerr << "error: --cert-path required\n";
        return 1;
    }

    auto data = read_file(a.cert_path);
    if (data.empty()) {
        std::cerr << "error: cannot read " << a.cert_path << "\n";
        return 1;
    }

    auto h = compute_hid8(data);
    auto summary = parse_cert_summary(data);
    auto actual = hid8_hex(h);

    // --hid8 pins an expected value: a mismatch must fail loudly. Without it the
    // command only reports what it computed.
    std::string expected;
    bool matches = true;
    if (!a.hid8.empty()) {
        expected = a.hid8;
        for (auto &c : expected)
            c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
        matches = (expected == actual);
    }

    if (a.json) {
        std::cout << "{\"file\":\"" << a.cert_path << "\",\"size\":" << data.size()
                  << ",\"hid8\":\"" << actual
                  << "\",\"valid\":" << (summary.valid ? "true" : "false");
        if (!expected.empty())
            std::cout << ",\"expected\":\"" << expected
                      << "\",\"match\":" << (matches ? "true" : "false");
        std::cout << "}" << '\n';
    } else {
        std::cout << "File:   " << a.cert_path << " (" << data.size() << "B)\n"
                  << "HID8:   " << actual << "\n"
                  << "Valid:  " << (summary.valid ? "yes" : "no") << "\n";
        if (!expected.empty())
            std::cout << "Expect: " << expected << "\n"
                      << "Match:  " << (matches ? "yes" : "NO") << "\n";
        if (summary.valid) print_cert_summary(summary, false);
    }

    if (!summary.valid) return 1;
    if (!matches) {
        std::cerr << "error: HashedId8 mismatch: expected " << expected << ", got " << actual
                  << "\n";
        return 1;
    }
    return 0;
}

int cmd_fetch_ectl(const Args &a) {
    if (a.pki_url.empty()) {
        std::cerr << "error: --pki-url required\n";
        return 1;
    }

    std::string ectl_url = a.tlm_hid8.empty() ? (a.pki_url + "/getectl")
                                              : (a.pki_url + "/getectl/" + a.tlm_hid8);

    HttpClient http(HttpClientConfig{"", 15s, true});
    auto resp = http.get(ectl_url);
    if (!resp) {
        std::cerr << "error: failed to fetch ECTL: " << to_string(resp.error()) << "\n";
        return 1;
    }
    if (resp->status_code != 200) {
        std::cerr << "error: failed to fetch ECTL (HTTP " << resp->status_code << ")\n";
        return 1;
    }

    void *structure = nullptr;
    auto dr = asn_decode(nullptr, ATS_CANONICAL_OER, &asn_DEF_Ieee1609Dot2Data, &structure,
                         resp->body.data(), resp->body.size());
    if (dr.code != RC_OK || !structure) {
        if (structure) ASN_STRUCT_FREE(asn_DEF_Ieee1609Dot2Data, structure);
        std::cerr << "error: failed to decode ECTL as Ieee1609Dot2Data\n";
        return 1;
    }

    auto *outer = static_cast<Ieee1609Dot2Data_t *>(structure);
    bool is_signed = outer->content && outer->content->present == Ieee1609Dot2Content_PR_signedData;

    if (a.json) {
        std::cout << "{\"size\":" << resp->body.size()
                  << ",\"protocol_version\":" << outer->protocolVersion
                  << ",\"is_signed\":" << (is_signed ? "true" : "false");
    } else {
        std::cout << "ECTL (" << resp->body.size() << "B)\n"
                  << "  Protocol:  " << outer->protocolVersion << "\n"
                  << "  Signed:    " << (is_signed ? "yes" : "no") << "\n";
    }

    if (is_signed && outer->content->choice.signedData) {
        auto *sd = outer->content->choice.signedData;
        if (sd->signer && sd->signer->present == SignerIdentifier_PR_digest) {
            auto &d = sd->signer->choice.digest;
            if (d.buf && d.size == 8) {
                std::string signer_hex = bytes_to_hex(d.buf, 8);
                if (a.json)
                    std::cout << ",\"signer_hid8\":\"" << signer_hex << "\"";
                else
                    std::cout << "  Signer:    " << signer_hex << "\n";
            }
        }

        if (!a.tlm_cert.empty()) {
            auto tlm_bytes = read_file(a.tlm_cert);
            if (!tlm_bytes.empty()) {
                parse_cert_summary(tlm_bytes);
                if (a.json)
                    std::cout << ",\"tlm_verify\":\"available\"";
                else
                    std::cout << "  TLM cert:  loaded (" << tlm_bytes.size() << "B)\n";
            }
        }
    }

    if (a.json) std::cout << "}" << '\n';

    if (!a.out.empty()) {
        write_file(a.out, resp->body);
        if (!a.json) std::cout << "  Saved:     " << a.out << "\n";
    }

    ASN_STRUCT_FREE(asn_DEF_Ieee1609Dot2Data, structure);
    return 0;
}

int cmd_discover(const Args &a) {
    if (a.pki_url.empty()) {
        std::cerr << "error: --pki-url required\n";
        return 1;
    }

    namespace fs = std::filesystem;
    std::string ks_dir = a.keystore_dir.empty() ? "/tmp/pki-discover" : a.keystore_dir;
    fs::create_directories(ks_dir);

    PkiClientConfig cfg;
    cfg.tlm_url = a.pki_url;
    cfg.tlm_hid8 = a.tlm_hid8;
    cfg.keystore_dir = ks_dir;
    cfg.timeout = 15s;
    cfg.verify_tls = true;

    PkiClient client(cfg);
    auto topo = client.discover_trust();
    if (!topo) {
        std::cerr << "error: trust discovery failed: " << to_string(topo.error()) << "\n";
        return 1;
    }

    if (a.json) {
        std::cout << "{\"status\":\"ok\"";
        if (topo->tlm)
            std::cout << ",\"tlm_hid8\":\"" << hid8_hex_upper(topo->tlm->hashed_id_8) << "\"";
        std::cout << ",\"rcas\":[";
        for (size_t i = 0; i < topo->rcas.size(); ++i) {
            if (i > 0) std::cout << ",";
            std::cout << "\"" << hid8_hex_upper(topo->rcas[i].hashed_id_8) << "\"";
        }
        std::cout << "],\"eas\":[";
        for (size_t i = 0; i < topo->eas.size(); ++i) {
            if (i > 0) std::cout << ",";
            std::cout << "{\"hid8\":\"" << hid8_hex_upper(topo->eas[i].cert.hashed_id_8)
                      << "\",\"its_access_point\":\"" << topo->eas[i].its_access_point
                      << "\",\"aa_access_point\":\"" << topo->eas[i].aa_access_point << "\"}";
        }
        std::cout << "],\"aas\":[";
        for (size_t i = 0; i < topo->aas.size(); ++i) {
            if (i > 0) std::cout << ",";
            std::cout << "{\"hid8\":\"" << hid8_hex_upper(topo->aas[i].cert.hashed_id_8)
                      << "\",\"access_point\":\"" << topo->aas[i].access_point << "\"}";
        }
        std::cout << "],\"dcs\":[";
        for (size_t i = 0; i < topo->dcs.size(); ++i) {
            if (i > 0) std::cout << ",";
            std::cout << "{\"url\":\"" << topo->dcs[i].url << "\"}";
        }
        std::cout << "]"
                  << ",\"ectl_sig_verified\":" << (topo->ectl_signature_verified ? "true" : "false")
                  << ",\"ctl_sig_verified\":" << (topo->ctl_signature_verified ? "true" : "false")
                  << "}" << '\n';
    } else {
        std::cout << "=== CCMS Trust Topology ===\n\n";

        if (topo->tlm) {
            std::cout << "TLM:\n"
                      << "  HID8:    " << hid8_hex_upper(topo->tlm->hashed_id_8) << "\n"
                      << "  Self:    " << (topo->tlm->is_self_signed ? "yes" : "no") << "\n"
                      << "  PubKey:  "
                      << (topo->tlm->public_key.size() == kP256PublicKeyLen ? "ok (65B)"
                                                                            : "missing")
                      << "\n\n";
        }

        std::cout << "RCA(s): " << topo->rcas.size() << "\n";
        for (const auto &rca : topo->rcas) {
            std::cout << "  HID8:    " << hid8_hex_upper(rca.hashed_id_8) << "\n"
                      << "  Self:    " << (rca.is_self_signed ? "yes" : "no") << "\n";
        }
        std::cout << "\n";

        std::cout << "EA(s): " << topo->eas.size() << "\n";
        for (const auto &ea : topo->eas) {
            std::cout << "  HID8:             " << hid8_hex_upper(ea.cert.hashed_id_8) << "\n"
                      << "  its_access_point: " << ea.its_access_point << "\n"
                      << "  aa_access_point:  " << ea.aa_access_point << "\n";
        }
        std::cout << "\n";

        std::cout << "AA(s): " << topo->aas.size() << "\n";
        for (const auto &aa : topo->aas) {
            std::cout << "  HID8:         " << hid8_hex_upper(aa.cert.hashed_id_8) << "\n"
                      << "  access_point: " << aa.access_point << "\n";
        }
        std::cout << "\n";

        std::cout << "DC(s): " << topo->dcs.size() << "\n";
        for (const auto &dc : topo->dcs) {
            std::cout << "  url:    " << dc.url << "\n"
                      << "  serves: ";
            for (size_t j = 0; j < dc.serves.size(); ++j) {
                if (j > 0) std::cout << ", ";
                std::cout << hid8_hex_upper(dc.serves[j]);
            }
            std::cout << "\n";
        }
        std::cout << "\n";

        std::cout << "Signature verification:\n"
                  << "  ECTL (TLM): "
                  << (topo->ectl_signature_verified ? "VERIFIED" : "not verified") << "\n"
                  << "  CTL  (RCA): "
                  << (topo->ctl_signature_verified ? "VERIFIED" : "not verified") << "\n";
    }

    return 0;
}

int cmd_enrol(const Args &a) {
    if (a.pki_url.empty() || a.keystore_dir.empty()) {
        std::cerr << "error: --pki-url and --keystore-dir required\n";
        return 1;
    }

    namespace fs = std::filesystem;
    fs::create_directories(a.keystore_dir);
    auto trust_dir = (fs::path(a.keystore_dir) / "trust").string();
    fs::create_directories(trust_dir);

    std::string ea_url = a.ea_url.empty() ? (a.pki_url + "/ec-request") : a.ea_url;

    HttpClient http(HttpClientConfig{"", 15s, true});
    auto ea_resp = http.get(a.pki_url + "/cert/ea");
    if (!ea_resp) {
        std::cerr << "error: failed to fetch EA cert: " << to_string(ea_resp.error()) << "\n";
        return 1;
    }
    if (ea_resp->status_code != 200) {
        std::cerr << "error: failed to fetch EA cert (HTTP " << ea_resp->status_code << ")\n";
        return 1;
    }
    write_file(trust_dir + "/ea.cert", ea_resp->body);

    if (!a.json) std::cout << "EA cert fetched (" << ea_resp->body.size() << "B)\n";

    PkiClientConfig cfg;
    cfg.ea_url = ea_url;
    cfg.tlm_url = a.pki_url;
    cfg.trust_dir = trust_dir;
    cfg.keystore_dir = a.keystore_dir;
    cfg.timeout = 15s;
    cfg.verify_tls = true;

    PkiClient client(cfg);

    Curve curve = parse_curve(a.curve_str);
    std::string key_id = a.canonical_key.empty() ? "canonical" : a.canonical_key;
    KeyHandle handle{key_id};
    auto existing = client.key_store().load_keypair(handle);
    KeyPair kp;
    if (existing) {
        kp = *existing;
        if (!a.json) std::cout << "Canonical key loaded: " << key_id << "\n";
    } else {
        auto gen = crypto::generate_keypair(curve);
        if (!gen) {
            std::cerr << "error: keygen failed\n";
            return 1;
        }
        kp = *gen;
        client.key_store().store_keypair(handle, kp);
        if (!a.json)
            std::cout << "Canonical key generated: " << key_id << " (" << to_string(curve) << ")\n";
    }

    auto ea_hid8 = compute_hid8(ea_resp->body);
    if (!a.json) std::cout << "EA HID8: " << hid8_hex(ea_hid8) << "\n";

    std::string canonical_id = a.canonical_id_set ? a.canonical_id : "v2xpki-its-s";
    if (canonical_id.empty() || canonical_id.size() > 64) {
        std::cerr << "error: canonical-id must be 1-64 bytes\n";
        return 1;
    }

    {
        auto cid_path = (fs::path(a.keystore_dir) / "canonical.id").string();
        std::ofstream ofs(cid_path, std::ios::binary);
        if (ofs) ofs.write(canonical_id.data(), static_cast<std::streamsize>(canonical_id.size()));
    }

    EcRecord rec;
    rec.canonical_public_key = kp.public_key;
    rec.ea_hashed_id_8 = ea_hid8;
    rec.requested_psids = {36};
    rec.validity_period_days = 30;
    rec.curve = curve;
    rec.its_id = canonical_id;

    if (!a.json)
        std::cout << "Sending EC request to " << ea_url << " (canonical-id: " << canonical_id
                  << ")...\n";
    auto result = client.request_enrolment_credential(handle, rec);
    if (!result) {
        std::cerr << "error: enrolment request failed: " << to_string(result.error()) << "\n";
        return 1;
    }

    auto ec_path = a.out.empty() ? (a.keystore_dir + "/ec.cert") : a.out;
    if (!write_file(ec_path, result->cert_bytes)) {
        std::cerr << "error: cannot write " << ec_path << "\n";
        return 1;
    }

    auto ec_hid8 = compute_hid8(result->cert_bytes);
    if (a.json) {
        std::cout << "{\"status\":\"ok\",\"ec_cert\":\"" << ec_path << "\",\"hid8\":\""
                  << hid8_hex(ec_hid8) << "\"}" << '\n';
    } else {
        std::cout << "EC cert received -> " << ec_path << "\n";
        std::cout << "  HID8: " << hid8_hex(ec_hid8) << "\n";
    }
    return 0;
}

int cmd_request_at(const Args &a) {
    if (a.pki_url.empty() || a.keystore_dir.empty()) {
        std::cerr << "error: --pki-url and --keystore-dir required\n";
        return 1;
    }

    namespace fs = std::filesystem;
    auto trust_dir = (fs::path(a.keystore_dir) / "trust").string();
    std::string out_dir = a.out_dir.empty() ? a.keystore_dir : a.out_dir;
    std::string aa_url = a.aa_url.empty() ? (a.pki_url + "/at-request") : a.aa_url;

    HttpClient http(HttpClientConfig{"", 15s, true});
    auto aa_resp = http.get(a.pki_url + "/cert/aa");
    auto ea_resp = http.get(a.pki_url + "/cert/ea");
    if (!aa_resp) {
        std::cerr << "error: failed to fetch AA cert: " << to_string(aa_resp.error()) << "\n";
        return 1;
    }
    if (aa_resp->status_code != 200) {
        std::cerr << "error: failed to fetch AA cert (HTTP " << aa_resp->status_code << ")\n";
        return 1;
    }
    fs::create_directories(trust_dir);
    write_file(trust_dir + "/aa.cert", aa_resp->body);
    if (ea_resp && ea_resp->status_code == 200) write_file(trust_dir + "/ea.cert", ea_resp->body);

    std::string canonical_id;
    if (a.canonical_id_set) {
        canonical_id = a.canonical_id;
    } else {
        auto cid_path = (fs::path(a.keystore_dir) / "canonical.id").string();
        std::ifstream ifs(cid_path, std::ios::binary);
        if (ifs)
            canonical_id.assign(std::istreambuf_iterator<char>(ifs),
                                std::istreambuf_iterator<char>());
    }
    if (canonical_id.empty()) canonical_id = "v2xpki-its-s";
    if (canonical_id.size() > 64) {
        std::cerr << "error: canonical-id must be 1-64 bytes\n";
        return 1;
    }
    if (!a.json) std::cout << "Canonical ID: " << canonical_id << "\n";

    std::string ec_key_id = a.canonical_key.empty() ? "canonical" : a.canonical_key;

    std::string ec_cert_path = a.ec_cert.empty() ? (a.keystore_dir + "/ec.cert") : a.ec_cert;
    auto ec_cert_bytes = read_file(ec_cert_path);
    if (ec_cert_bytes.empty()) {
        std::cerr << "error: cannot read EC cert from " << ec_cert_path << "\n";
        return 1;
    }

    PkiClientConfig cfg;
    cfg.aa_url = aa_url;
    cfg.tlm_url = a.pki_url;
    cfg.trust_dir = trust_dir;
    cfg.keystore_dir = a.keystore_dir;
    cfg.timeout = 15s;
    cfg.verify_tls = true;

    PkiClient client(cfg);

    KeyHandle handle{ec_key_id};
    auto kp = client.key_store().load_keypair(handle);
    if (!kp) {
        std::cerr << "error: cannot load EC key '" << ec_key_id << "'\n";
        return 1;
    }

    CertInfo ec_ci;
    ec_ci.cert_bytes = ec_cert_bytes;
    auto ec_h = compute_hid8(ec_cert_bytes);
    ec_ci.hashed_id_8 = ec_h;
    ec_ci.public_key = kp->public_key;

    if (!a.json)
        std::cout << "EC cert loaded: " << ec_cert_path << " (" << ec_cert_bytes.size() << "B"
                  << ", HID8 " << hid8_hex(ec_h) << ")\n";

    auto aa_hid8 = compute_hid8(aa_resp->body);
    auto ea_hid8_val = ea_resp ? compute_hid8(ea_resp->body) : std::array<uint8_t, 8>{};

    Curve curve = parse_curve(a.curve_str);

    AtRecord rec;
    rec.at_public_key = kp->public_key;
    rec.aa_hashed_id_8 = aa_hid8;
    rec.ea_hashed_id_8 = ea_hid8_val;
    rec.requested_psids = {36};
    rec.validity_period_hours = 24;
    rec.curve = curve;

    if (!a.json) std::cout << "Sending AT request to " << aa_url << "...\n";
    auto result = client.request_authorization_ticket(handle, ec_ci, rec);
    if (!result) {
        std::cerr << "error: AT request failed: " << to_string(result.error()) << "\n";
        return 1;
    }

    auto at_path = a.out.empty() ? (out_dir + "/at.cert") : a.out;
    if (!write_file(at_path, result->cert_bytes)) {
        std::cerr << "error: cannot write " << at_path << "\n";
        return 1;
    }

    auto at_hid8 = compute_hid8(result->cert_bytes);
    if (a.json) {
        std::cout << "{\"status\":\"ok\",\"at_cert\":\"" << at_path << "\",\"hid8\":\""
                  << hid8_hex(at_hid8) << "\"}" << '\n';
    } else {
        std::cout << "AT cert received -> " << at_path << "\n";
        std::cout << "  HID8: " << hid8_hex(at_hid8) << "\n";
    }
    return 0;
}

} // namespace v2xpki::cli
