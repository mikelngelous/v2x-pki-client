// PkiClient facade implementation.

#include "v2xpki/facade.hpp"
#include "v2xpki/plaintext_file_key_store.hpp"
#include "v2xpki/trust_list.hpp"
#include "v2xpki/sizes.hpp"

#include <algorithm>
#include <chrono>
#include <iomanip>
#include <iostream>
#include <sstream>

extern "C" {
#include "CertificateBase.h"
#include "asn_application.h"
}

#include "internal/coer.hpp"
#include "internal/cert_parse.hpp"

namespace v2xpki {

namespace {

std::string hid8_to_hex(const std::array<uint8_t, 8>& hid8) {
    std::ostringstream oss;
    for (auto b : hid8) {
        oss << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(b);
    }
    return oss.str();
}

// Find DC URL for a given HID8 from DcInfo list, falling back to base_url.
std::string find_dc_url(const std::vector<DcInfo>& dcs, const std::array<uint8_t, 8>& hid8,
                        const std::string& fallback_url) {
    for (const auto& dc : dcs) {
        for (const auto& served : dc.serves) {
            if (served == hid8) {
                auto url = dc.url;
                if (!url.empty() && url.back() == '/') url.pop_back();
                return url;
            }
        }
    }
    return fallback_url;
}

}

// Distinguishes "the caller's trust_dir is missing an anchor" from "the signature is bad".
// Both make validate_chain return false, but they send an integrator to opposite places.
bool issuer_chain_present(const TrustChain& trust, const CertInfo& cert) {
    auto issuer = trust.find_by_hashed_id_8(cert.issuer_hash_id_8);
    if (!issuer) return false;
    if (issuer->is_self_signed) return true;
    return trust.find_by_hashed_id_8(issuer->issuer_hash_id_8).has_value();
}

struct PkiClient::Impl {
    PkiClientConfig config;
    HttpClient http;
    TrustChain trust;
    PlaintextFileKeyStore keystore;
    RevocationStore revocation;
    std::optional<TrustTopology> topology;

    Impl(const PkiClientConfig& cfg)
        : config(cfg)
        , http(HttpClientConfig{cfg.ca_bundle_path, cfg.timeout, cfg.verify_tls})
        , keystore(cfg.keystore_dir) {
        trust.set_revocation_store(&revocation);
        if (!cfg.trust_dir.empty()) {
            trust.load_from_directory(cfg.trust_dir);
        }
    }
};

PkiClient::PkiClient(const PkiClientConfig& cfg)
    : impl_(std::make_unique<Impl>(cfg)) {}

PkiClient::~PkiClient() = default;

const TrustChain& PkiClient::trust_chain() const { return impl_->trust; }
KeyStore& PkiClient::key_store() { return impl_->keystore; }

Result<CertInfo> PkiClient::request_enrolment_credential(const KeyHandle& canonical,
                                                         const EcRecord& rec) {

    std::string err;
    if (!validate_ec_record(rec, &err)) return Error::InvalidArgument;

    auto kp = impl_->keystore.load_keypair(canonical);
    if (!kp) return Error::KeyStore;

    auto ea_opt = impl_->trust.find_by_hashed_id_8(rec.ea_hashed_id_8);
    if (!ea_opt) return Error::NotFound;

    auto desc = assemble_ec_request(rec, std::chrono::system_clock::now());
    auto req_result = encode_ec_request(desc, *ea_opt, kp->private_key.to_vector());
    if (!req_result) return req_result.error();

    auto resp = impl_->http.post(impl_->config.ea_url, req_result->encoded.to_vector());
    if (!resp) return resp.error();
    if (resp->status_code != 200) return Error::HttpStatus;

    auto ec_resp = decode_ec_response(resp->body, kp->private_key.to_vector(),
                                      req_result->request_aes_key.to_vector(),
                                      req_result->encoded.to_vector());
    if (!ec_resp) return ec_resp.error();
    if (ec_resp->response_code != EnrolmentResponseCode::Ok) return Error::Protocol;

    if (!ec_resp->certificate) return Error::Protocol;

    auto ec_cert = *ec_resp->certificate;
    ec_cert.label = "ec";
    if (!issuer_chain_present(impl_->trust, ec_cert)) return Error::NotFound;
    if (!impl_->trust.validate_chain(ec_cert)) return Error::SignatureInvalid;
    impl_->trust.add_cert(ec_cert);
    return ec_cert;
}

Result<CertInfo> PkiClient::request_authorization_ticket(const KeyHandle& ec_handle,
                                                         const CertInfo& ec_cert,
                                                         const KeyHandle& at_handle,
                                                         const AtRecord& rec) {

    std::string err;
    if (!validate_at_record(rec, &err)) return Error::InvalidArgument;

    auto kp = impl_->keystore.load_keypair(ec_handle);
    if (!kp) return Error::KeyStore;

    auto aa_opt = impl_->trust.find_by_hashed_id_8(rec.aa_hashed_id_8);
    if (!aa_opt) return Error::NotFound;

    auto ea_opt = impl_->trust.find_by_hashed_id_8(rec.ea_hashed_id_8);
    if (!ea_opt) return Error::NotFound;

    auto at_kp = impl_->keystore.load_keypair(at_handle);
    if (!at_kp) return Error::KeyStore;

    auto desc = assemble_at_request(rec, std::chrono::system_clock::now());
    desc.verification_key = at_kp->public_key;
    auto req_result = encode_at_request(desc, *aa_opt, *ea_opt, ec_cert,
                                        kp->private_key.to_vector(),
                                        at_kp->private_key.to_vector());
    if (!req_result) return req_result.error();

    auto resp = impl_->http.post(impl_->config.aa_url, req_result->encoded.to_vector());
    if (!resp) return resp.error();
    if (resp->status_code != 200) return Error::HttpStatus;

    auto at_resp = decode_at_response(resp->body, at_kp->private_key.to_vector(),
                                      req_result->request_aes_key.to_vector(),
                                      req_result->encoded.to_vector());
    if (!at_resp) return at_resp.error();
    if (at_resp->response_code != AuthorizationResponseCode::Ok) return Error::Protocol;

    if (!at_resp->certificate) return Error::Protocol;

    auto at_cert = *at_resp->certificate;
    at_cert.label = "at";
    if (!issuer_chain_present(impl_->trust, at_cert)) return Error::NotFound;
    if (!impl_->trust.validate_chain(at_cert)) return Error::SignatureInvalid;
    impl_->trust.add_cert(at_cert);
    return at_cert;
}

Result<CertInfo> PkiClient::fetch_trust_anchor() {
    auto resp = impl_->http.get(impl_->config.tlm_url + "/trustanchor");
    if (!resp) return resp.error();
    if (resp->status_code != 200) return Error::HttpStatus;

    auto ci = cert::from_coer(resp->body);
    if (ci.cert_bytes.empty()) return Error::Decode;
    ci.label = "trustanchor";
    impl_->trust.add_cert(ci);
    return ci;
}

Result<CertInfo> PkiClient::fetch_cert_by_name(const std::string& name) {
    auto resp = impl_->http.get(impl_->config.tlm_url + "/cert/" + name);
    if (!resp) return resp.error();
    if (resp->status_code != 200) return Error::HttpStatus;

    auto ci = cert::from_coer(resp->body);
    if (ci.cert_bytes.empty()) return Error::Decode;
    ci.label = name;
    impl_->trust.add_cert(ci);
    return ci;
}

Result<CertInfo> PkiClient::fetch_cert_by_hashed_id_8(const std::array<uint8_t, 8>& hid8) {
    auto hex = hid8_to_hex(hid8);
    auto resp = impl_->http.get(impl_->config.tlm_url + "/lookup/" + hex);
    if (!resp) return resp.error();
    if (resp->status_code != 200) return Error::HttpStatus;

    auto ci = cert::from_coer(resp->body);
    if (ci.cert_bytes.empty()) return Error::Decode;
    ci.label = "lookup_" + hex;
    impl_->trust.add_cert(ci);
    return ci;
}

Result<TrustTopology> PkiClient::discover_trust() {
    std::string base_url = impl_->config.tlm_url;
    std::string tlm_hid8_hex = impl_->config.tlm_hid8;

    // Obtain TLM cert and HID8
    CertInfo tlm_cert;
    if (!tlm_hid8_hex.empty()) {
        // Canonical: GET /gettlmcertificate/{TLM_HID8}
        std::cerr << "[discover] GET " << base_url << "/gettlmcertificate/" << tlm_hid8_hex << "\n";
        auto resp = impl_->http.get(base_url + "/gettlmcertificate/" + tlm_hid8_hex);
        if (!resp) {
            std::cerr << "[discover] failed to fetch TLM cert: " << to_string(resp.error()) << "\n";
            return resp.error();
        }
        if (resp->status_code != 200) {
            std::cerr << "[discover] failed to fetch TLM cert (HTTP " << resp->status_code << ")\n";
            return Error::HttpStatus;
        }
        auto ci = cert::from_coer(resp->body);
        if (ci.cert_bytes.empty()) return Error::Decode;
        ci.label = "tlm";
        tlm_cert = ci;
    } else {
        // Bootstrap: try /tlm endpoint (testbed shortcut) to get TLM cert
        std::cerr << "[discover] no --tlm-hid8, bootstrapping via /tlm\n";
        auto resp = impl_->http.get(base_url + "/tlm");
        if (!resp) {
            std::cerr << "[discover] /tlm failed: " << to_string(resp.error())
                      << ", cannot bootstrap TLM. Provide --tlm-hid8.\n";
            return resp.error();
        }
        if (resp->status_code != 200) {
            std::cerr << "[discover] /tlm failed (HTTP " << resp->status_code
                      << "), cannot bootstrap TLM. Provide --tlm-hid8.\n";
            return Error::HttpStatus;
        }
        auto ci = cert::from_coer(resp->body);
        if (ci.cert_bytes.empty()) return Error::Decode;
        ci.label = "tlm";
        tlm_cert = ci;
        tlm_hid8_hex = hid8_hex_upper(tlm_cert.hashed_id_8);
        std::cerr << "[discover] TLM HID8 bootstrapped: " << tlm_hid8_hex << "\n";
    }

    impl_->trust.add_cert(tlm_cert);

    // Fetch ECTL via canonical GET /getectl/{TLM_HID8}
    std::cerr << "[discover] GET " << base_url << "/getectl/" << tlm_hid8_hex << "\n";
    auto ectl_resp = impl_->http.get(base_url + "/getectl/" + tlm_hid8_hex);
    if (!ectl_resp) {
        std::cerr << "[discover] ECTL fetch failed: " << to_string(ectl_resp.error()) << "\n";
        return ectl_resp.error();
    }
    if (ectl_resp->status_code != 200) {
        std::cerr << "[discover] ECTL fetch failed (HTTP " << ectl_resp->status_code << ")\n";
        return Error::HttpStatus;
    }

    auto ectl_topo = decode_ectl(ectl_resp->body, tlm_cert.public_key.to_vector(),
                                 tlm_cert.cert_bytes.to_vector());
    if (!ectl_topo) {
        std::cerr << "[discover] ECTL decode failed\n";
        return ectl_topo.error();
    }
    if (!ectl_topo->ectl_signature_verified) {
        std::cerr << "[discover] ECTL signature verification failed — refusing to trust it\n";
        return Error::SignatureInvalid;
    }

    TrustTopology result = *ectl_topo;
    result.tlm = tlm_cert;

    for (auto& rca : result.rcas)
        impl_->trust.add_cert(rca);

    // For each RCA, find its DC URL and fetch the RCA CTL
    result.ctl_signature_verified = true; // AND identity; will &= per RCA
    for (auto& rca : result.rcas) {
        auto dc_url = find_dc_url(result.dcs, rca.hashed_id_8, base_url);
        auto rca_hid8_hex = hid8_hex_upper(rca.hashed_id_8);
        std::cerr << "[discover] GET " << dc_url << "/getctl/" << rca_hid8_hex << "\n";
        auto ctl_resp = impl_->http
                            .get(std::string(dc_url).append("/getctl/").append(rca_hid8_hex));
        if (!ctl_resp || ctl_resp->status_code != 200) {
            std::cerr << "[discover] CTL fetch failed for RCA " << rca_hid8_hex << " (HTTP "
                      << (ctl_resp ? ctl_resp->status_code : 0) << ")\n";
            continue;
        }

        auto ctl_topo = decode_rca_ctl(ctl_resp->body, rca.public_key.to_vector(),
                                       rca.cert_bytes.to_vector());
        if (!ctl_topo) {
            std::cerr << "[discover] CTL decode failed for RCA " << rca_hid8_hex << "\n";
            result.ctl_signature_verified = false;
            continue;
        }
        if (!ctl_topo->ctl_signature_verified) {
            std::cerr << "[discover] CTL signature verification failed for RCA " << rca_hid8_hex
                      << " — skipping its EA/AA/DC\n";
            result.ctl_signature_verified = false;
            continue;
        }

        for (const auto& ea : ctl_topo->eas) {
            impl_->trust.add_cert(ea.cert);
            result.eas.push_back(ea);
        }
        for (const auto& aa : ctl_topo->aas) {
            impl_->trust.add_cert(aa.cert);
            result.aas.push_back(aa);
        }
        for (const auto& dc : ctl_topo->dcs)
            result.dcs.push_back(dc);
    }

    if (!result.ctl_signature_verified) {
        std::cerr << "[discover] one or more RCA CTLs failed signature verification\n";
        return Error::SignatureInvalid;
    }

    if (!result.eas.empty()) {
        auto& ea = result.eas[0];
        if (!ea.its_access_point.empty()) impl_->config.ea_url = ea.its_access_point;
    }
    if (!result.aas.empty()) impl_->config.aa_url = result.aas[0].access_point;

    impl_->topology = result;
    return result;
}

Result<std::vector<CertInfo>> PkiClient::fetch_ectl() {
    // Use canonical path if TLM HID8 is available
    std::string tlm_hex = impl_->config.tlm_hid8;
    if (tlm_hex.empty() && impl_->topology && impl_->topology->tlm)
        tlm_hex = hid8_hex_upper(impl_->topology->tlm->hashed_id_8);

    std::string url = tlm_hex.empty() ? (impl_->config.tlm_url + "/ectl")
                                      : (impl_->config.tlm_url + "/getectl/" + tlm_hex);

    auto resp = impl_->http.get(url);
    if (!resp) return resp.error();
    if (resp->status_code != 200) return Error::HttpStatus;

    auto topo = decode_ectl(resp->body);
    if (!topo) return topo.error();

    std::vector<CertInfo> certs;
    for (const auto& rca : topo->rcas)
        certs.push_back(rca);
    for (const auto& ea : topo->eas)
        certs.push_back(ea.cert);
    for (const auto& aa : topo->aas)
        certs.push_back(aa.cert);
    return certs;
}

Result<CrlContents> PkiClient::fetch_crl(const std::array<uint8_t, 8>& rca_hid8) {
    auto hex = hid8_hex_upper(rca_hid8);
    auto dc_url = impl_->topology
                      ? find_dc_url(impl_->topology->dcs, rca_hid8, impl_->config.tlm_url)
                      : impl_->config.tlm_url;

    auto resp = impl_->http.get(dc_url + "/getcrl/" + hex);
    if (!resp) return resp.error();
    if (resp->status_code != 200) return Error::HttpStatus;

    auto rca = impl_->trust.find_by_hashed_id_8(rca_hid8);
    if (!rca) return Error::NotFound;

    auto crl = decode_crl(resp->body, rca->public_key.to_vector(), rca->cert_bytes.to_vector());
    if (!crl) return crl.error();

    if (!impl_->revocation.apply(*crl)) return Error::Protocol; // stale CRL
    return *crl;
}

} // namespace v2xpki
