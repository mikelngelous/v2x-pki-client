// Provisioning flow: CCMS trust discovery, EC enrolment, AT rotation.

#include "flow.hpp"

#include "key_pem.hpp"

#include "v2xpki/at_request.hpp"
#include "v2xpki/crypto_ec.hpp"
#include "v2xpki/ec_request.hpp"
#include "v2xpki/facade.hpp"
#include "v2xpki/sizes.hpp"
#include "v2xpki/trust_list.hpp"

#include <algorithm>
#include <chrono>
#include <cstdio>

using namespace v2xpki;

namespace {

std::array<uint8_t, 8> hid8_of(const std::vector<uint8_t>& cert_bytes) {
    auto hash = crypto::hash_sha256(cert_bytes);
    std::array<uint8_t, 8> hid8{};
    std::copy_n(hash.end() - kHashedId8Len, kHashedId8Len, hid8.begin());
    return hid8;
}

// PKI rejection bodies are JSON; print only when the payload is text.
void log_text_body(const std::vector<uint8_t>& body) {
    if (body.empty()) return;
    for (auto b : body)
        if (b < 9 || (b > 13 && b < 32)) return;
    fprintf(stderr, "[pki-provisioner] Body: %s\n", std::string(body.begin(), body.end()).c_str());
}

} // namespace

namespace provisioning {

std::optional<TrustAnchors> discover(const std::string& base_url, const std::string& tlm_hid8,
                                     const std::string& work_dir) {
    PkiClientConfig cfg;
    cfg.tlm_url = base_url;
    cfg.tlm_hid8 = tlm_hid8;
    cfg.keystore_dir = work_dir;
    cfg.timeout = std::chrono::seconds{30};
    cfg.verify_tls = true;

    PkiClient client(cfg);
    auto topo = client.discover_trust();
    if (!topo) {
        fprintf(stderr, "[pki-provisioner] FATAL: trust discovery failed: %s\n",
                to_string(topo.error()));
        return std::nullopt;
    }
    if (!topo->ectl_signature_verified || !topo->ctl_signature_verified) {
        fprintf(stderr, "[pki-provisioner] FATAL: trust signatures unverified (ECTL %s, CTL %s)\n",
                topo->ectl_signature_verified ? "ok" : "FAIL",
                topo->ctl_signature_verified ? "ok" : "FAIL");
        return std::nullopt;
    }
    if (topo->eas.empty() || topo->aas.empty() || topo->rcas.empty()) {
        fprintf(stderr, "[pki-provisioner] FATAL: incomplete topology (EA %zu, AA %zu, RCA %zu)\n",
                topo->eas.size(), topo->aas.size(), topo->rcas.size());
        return std::nullopt;
    }

    TrustAnchors ta;
    ta.ea = topo->eas[0].cert;
    ta.aa = topo->aas[0].cert;
    ta.rca = topo->rcas[0];
    ta.ec_url = topo->eas[0].its_access_point.empty() ? (base_url + "/ec-request")
                                                      : topo->eas[0].its_access_point;
    ta.at_url = topo->aas[0].access_point.empty() ? (base_url + "/at-request")
                                                  : topo->aas[0].access_point;

    if (ta.ea.encryption_key.empty() || ta.aa.encryption_key.empty()) {
        fprintf(stderr, "[pki-provisioner] FATAL: EA/AA cert has no encryption key\n");
        return std::nullopt;
    }

    printf("[pki-provisioner] Trust discovered (ECTL + CTL verified)\n");
    printf("[pki-provisioner] EA HID8: %s  -> %s\n", hex8(ta.ea.hashed_id_8).c_str(),
           ta.ec_url.c_str());
    printf("[pki-provisioner] AA HID8: %s  -> %s\n", hex8(ta.aa.hashed_id_8).c_str(),
           ta.at_url.c_str());
    printf("[pki-provisioner] RCA HID8: %s\n", hex8(ta.rca.hashed_id_8).c_str());
    return ta;
}

bool write_anchors(const TrustAnchors& ta, const std::string& output_dir) {
    if (!atomic_write(output_dir + "/AA.coer", ta.aa.cert_bytes)) {
        fprintf(stderr, "[pki-provisioner] FATAL: cannot write AA.coer\n");
        return false;
    }
    printf("[pki-provisioner] Wrote AA.coer (%zuB)\n", ta.aa.cert_bytes.size());

    if (!atomic_write(output_dir + "/RCA.coer", ta.rca.cert_bytes)) {
        fprintf(stderr, "[pki-provisioner] FATAL: cannot write RCA.coer\n");
        return false;
    }
    printf("[pki-provisioner] Wrote RCA.coer (%zuB)\n", ta.rca.cert_bytes.size());
    return true;
}

std::optional<EnrolledEc> enrol_ec(HttpClient& http, const TrustAnchors& ta,
                                   const std::vector<int64_t>& psids, int64_t validity_days) {
    auto canonical_kp = crypto::generate_keypair();
    if (!canonical_kp) {
        fprintf(stderr, "[pki-provisioner] FATAL: EC keygen failed\n");
        return std::nullopt;
    }

    EcRecord rec;
    rec.canonical_public_key = canonical_kp->public_key;
    rec.ea_hashed_id_8 = ta.ea.hashed_id_8;
    rec.requested_psids = psids;
    rec.validity_period_days = validity_days;

    auto desc = assemble_ec_request(rec, std::chrono::system_clock::now());
    auto req = encode_ec_request(desc, ta.ea, canonical_kp->private_key);
    if (!req) {
        fprintf(stderr, "[pki-provisioner] FATAL: encode_ec_request: %s\n", to_string(req.error()));
        return std::nullopt;
    }
    printf("[pki-provisioner] EC request: %zuB\n", req->encoded.size());

    auto http_resp = http.post(ta.ec_url, req->encoded);
    if (!http_resp) {
        fprintf(stderr, "[pki-provisioner] FATAL: POST EC: %s\n", to_string(http_resp.error()));
        return std::nullopt;
    }
    printf("[pki-provisioner] EC HTTP status: %d\n", http_resp->status_code);
    if (http_resp->status_code != 200) {
        fprintf(stderr, "[pki-provisioner] FATAL: EC enrollment failed (HTTP %d)\n",
                http_resp->status_code);
        log_text_body(http_resp->body);
        return std::nullopt;
    }

    auto resp = decode_ec_response(http_resp->body, canonical_kp->private_key, req->request_aes_key);
    if (!resp) {
        fprintf(stderr, "[pki-provisioner] FATAL: EC response decode failed: %s\n",
                to_string(resp.error()));
        return std::nullopt;
    }
    if (resp->response_code != EnrolmentResponseCode::Ok || !resp->certificate) {
        fprintf(stderr, "[pki-provisioner] FATAL: EC response rejected (code=%d)\n",
                static_cast<int>(resp->response_code));
        return std::nullopt;
    }

    EnrolledEc ec;
    ec.cert.cert_bytes = resp->certificate->cert_bytes;
    ec.cert.hashed_id_8 = hid8_of(ec.cert.cert_bytes);
    ec.cert.public_key = canonical_kp->public_key;
    ec.canonical_kp = *canonical_kp;

    printf("[pki-provisioner] EC enrolled OK! cert: %zuB  HID8: %s\n", ec.cert.cert_bytes.size(),
           hex8(ec.cert.hashed_id_8).c_str());
    return ec;
}

std::optional<std::array<uint8_t, 8>> rotate_at(HttpClient& http, const TrustAnchors& ta,
                                                const EnrolledEc& ec,
                                                const std::vector<int64_t>& psids,
                                                int64_t validity_hours,
                                                const std::string& output_dir) {
    auto at_kp = crypto::generate_keypair();
    if (!at_kp) {
        fprintf(stderr, "[pki-provisioner] ERROR: AT keygen failed\n");
        return std::nullopt;
    }

    AtRecord rec;
    rec.at_public_key = at_kp->public_key;
    rec.aa_hashed_id_8 = ta.aa.hashed_id_8;
    rec.ea_hashed_id_8 = ta.ea.hashed_id_8;
    rec.requested_psids = psids;
    rec.validity_period_hours = validity_hours;

    auto desc = assemble_at_request(rec, std::chrono::system_clock::now());
    auto req = encode_at_request(desc, ta.aa, ta.ea, ec.cert, ec.canonical_kp.private_key,
                                 at_kp->private_key);
    if (!req) {
        fprintf(stderr, "[pki-provisioner] ERROR: encode_at_request: %s\n", to_string(req.error()));
        return std::nullopt;
    }
    printf("[pki-provisioner] AT request: %zuB\n", req->encoded.size());

    auto http_resp = http.post(ta.at_url, req->encoded);
    if (!http_resp) {
        fprintf(stderr, "[pki-provisioner] ERROR: POST AT: %s\n", to_string(http_resp.error()));
        return std::nullopt;
    }
    printf("[pki-provisioner] AT HTTP status: %d  body: %zuB\n", http_resp->status_code,
           http_resp->body.size());
    if (http_resp->status_code != 200 || http_resp->body.empty()) {
        fprintf(stderr, "[pki-provisioner] ERROR: AT request failed (HTTP %d)\n",
                http_resp->status_code);
        return std::nullopt;
    }

    auto resp = decode_at_response(http_resp->body, at_kp->private_key, req->request_aes_key);
    if (!resp) {
        fprintf(stderr, "[pki-provisioner] ERROR: decode_at_response: %s\n", to_string(resp.error()));
        return std::nullopt;
    }
    if (resp->response_code != AuthorizationResponseCode::Ok) {
        fprintf(stderr, "[pki-provisioner] ERROR: AT rejected (code=%d)\n",
                static_cast<int>(resp->response_code));
        return std::nullopt;
    }
    if (!resp->certificate) {
        fprintf(stderr, "[pki-provisioner] ERROR: AT response has no certificate\n");
        return std::nullopt;
    }

    auto hid8 = hid8_of(resp->certificate->cert_bytes);

    if (!atomic_write(output_dir + "/AT.coer", resp->certificate->cert_bytes)) {
        fprintf(stderr, "[pki-provisioner] ERROR: cannot write AT.coer\n");
        return std::nullopt;
    }
    if (!atomic_write_key_pem(output_dir + "/AT.key", at_kp->private_key)) {
        fprintf(stderr, "[pki-provisioner] ERROR: cannot write AT.key\n");
        return std::nullopt;
    }

    printf("[pki-provisioner] AT cert: %zuB  HID8: %s\n", resp->certificate->cert_bytes.size(),
           hex8(hid8).c_str());
    printf("[pki-provisioner] Wrote AT.coer (%zuB) + AT.key (PEM SEC1)\n",
           resp->certificate->cert_bytes.size());
    return hid8;
}

} // namespace provisioning
