// trust_list.cpp — decode ECTL/CTL (CtlFormat) from signed Ieee1609Dot2Data.
// Implements TS 102 941 Annex D trust list decoding for CCMS conformance.
//
// Wire format: Ieee1609Dot2Data(signed) → unsecuredData(Opaque) contains
// COER-encoded EtsiTs102941Data { version, content: EtsiTs102941DataContent }
// where content is certificateTrustListTlm (ECTL) or certificateTrustListRca (CTL),
// each containing CtlFormat.

#include "v2xpki/trust_list.hpp"
#include "v2xpki/sizes.hpp"
#include "v2xpki/crypto_ec.hpp"

#include <algorithm>
#include <cstring>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <sstream>

extern "C" {
#include "CertificateBase.h"
#include "CtlFormat.h"
#include "CtlCommand.h"
#include "CtlEntry.h"
#include "RootCaEntry.h"
#include "EaEntry.h"
#include "AaEntry.h"
#include "DcEntry.h"
#include "TlmEntry.h"
#include "EtsiTs103097Certificate.h"
#include "Ieee1609Dot2Data.h"
#include "Ieee1609Dot2Content.h"
#include "SignedData.h"
#include "ToBeSignedData.h"
#include "SignedDataPayload.h"
#include "SignerIdentifier.h"
#include "Signature.h"
#include "EcdsaP256Signature.h"
#include "EccP256CurvePoint.h"
#include "IssuerIdentifier.h"
#include "VerificationKeyIndicator.h"
#include "PublicVerificationKey.h"
#include "BasePublicEncryptionKey.h"
#include "ToBeSignedCertificate.h"
#include "EtsiTs102941MessagesCa_EtsiTs102941Data.h"
#include "EtsiTs102941MessagesCa_EtsiTs102941DataContent.h"
#include "asn_application.h"
}

#include "internal/coer.hpp"
#include "internal/asn_ptr.hpp"
#include "internal/curve_point.hpp"
#include "internal/cert_parse.hpp"

namespace v2xpki {

namespace {

std::string url_from_ia5(const OCTET_STRING_t *s) {
    if (!s || !s->buf || s->size == 0) return {};
    return {reinterpret_cast<const char *>(s->buf), static_cast<size_t>(s->size)};
}

// --- Certificate conversion ---

// The memory layout is identical (CertificateBase_t).
std::optional<CertInfo> cert_ptr_to_info(const void *cert_void, const std::string &label) {
    if (!cert_void) return std::nullopt;

    auto cert_coer = coer::encode(&asn_DEF_EtsiTs103097Certificate, cert_void);
    if (cert_coer.empty()) return std::nullopt;

    auto ci = cert::from_struct(static_cast<const CertificateBase_t *>(cert_void), cert_coer);
    ci.label = label;
    return ci;
}

// --- Signed data envelope ---

struct SignedCtlData {
    std::vector<uint8_t> payload_coer; // raw EtsiTs102941Data COER
    std::vector<uint8_t> tbs_coer;
    std::array<uint8_t, 8> signer_hid8{};
    std::vector<uint8_t> sig_r;
    std::vector<uint8_t> sig_s;
    Curve sig_curve = Curve::NistP256;
    bool has_signer_digest = false;
};

std::optional<SignedCtlData> unwrap_signed_ctl(const std::vector<uint8_t> &coer) {
    auto outer = asn_decode_fallback<Ieee1609Dot2Data_t>(asn_DEF_Ieee1609Dot2Data, coer.data(),
                                                         coer.size());
    if (!outer) return std::nullopt;

    if (!outer->content || outer->content->present != Ieee1609Dot2Content_PR_signedData) {
        return std::nullopt;
    }

    auto *sd = outer->content->choice.signedData;
    if (!sd || !sd->tbsData || !sd->tbsData->payload) {
        return std::nullopt;
    }

    SignedCtlData result;

    // TBS COER for signature verification
    result.tbs_coer = coer::encode(&asn_DEF_ToBeSignedData, sd->tbsData);

    // Signer HID8
    if (sd->signer && sd->signer->present == SignerIdentifier_PR_digest) {
        auto d = octet::bytes(&sd->signer->choice.digest);
        if (d.size() == kHashedId8Len) {
            std::copy_n(d.begin(), kHashedId8Len, result.signer_hid8.begin());
            result.has_signer_digest = true;
        }
    }

    // Signature r, s — detect curve from signature variant
    point::SigRS rs;
    if (point::extract_sig(sd->signature, rs)) {
        result.sig_r = std::move(rs.r);
        result.sig_s = std::move(rs.s);
        result.sig_curve = rs.curve;
    }

    // Contains COER-encoded EtsiTs102941Data (version + EtsiTs102941DataContent)
    auto *payload = sd->tbsData->payload;
    if (!payload->data || !payload->data->content ||
        payload->data->content->present != Ieee1609Dot2Content_PR_unsecuredData) {
        return std::nullopt;
    }

    result.payload_coer = octet::bytes(&payload->data->content->choice.unsecuredData);

    if (result.payload_coer.empty()) return std::nullopt;
    return result;
}

// IEEE 1609.2 §5.3.1 signed data verification (multi-curve).
// Hash algorithm matches signature curve: SHA-256 for P-256/BP256, SHA-384 for BP384.
// signedDataHash = H( H(COER(tbsData)) || H(signerIdentifierInput) )
bool verify_signed_data(const SignedCtlData &data, const std::vector<uint8_t> &verifier_pubkey,
                        const std::vector<uint8_t> &signer_cert_coer) {
    if (verifier_pubkey.empty() || data.tbs_coer.empty()) return false;
    auto slen = scalar_len(data.sig_curve);
    if (data.sig_r.size() != slen || data.sig_s.size() != slen) return false;

    // Verify signer HID8 from wire matches the actual signer cert.
    if (data.has_signer_digest) {
        auto computed_hid8 = cert::compute_hid8(signer_cert_coer);
        if (computed_hid8 != data.signer_hid8) return false;
    }

    auto tbs_hash = crypto::hash_for_curve(data.tbs_coer, data.sig_curve);
    auto signer_hash = crypto::hash_for_curve(signer_cert_coer, data.sig_curve);

    std::vector<uint8_t> concat;
    concat.reserve(tbs_hash.size() + signer_hash.size());
    concat.insert(concat.end(), tbs_hash.begin(), tbs_hash.end());
    concat.insert(concat.end(), signer_hash.begin(), signer_hash.end());
    auto signed_data_hash = crypto::hash_for_curve(concat, data.sig_curve);

    v2xpki::Signature sig;
    sig.r = data.sig_r;
    sig.s = data.sig_s;

    return crypto::ecdsa_verify_digest(verifier_pubkey, signed_data_hash, sig, data.sig_curve);
}

// TAI epoch: 2004-01-01T00:00:00 UTC in Unix time.
constexpr int64_t kTaiEpochUnix = 1072915200;

// Parse CtlFormat entries into TrustTopology.
void parse_ctl_entries(const CtlFormat_t *ctl, TrustTopology &topo, bool is_ectl) {
    // Store nextUpdate (Time32 = seconds since TAI epoch 2004-01-01).
    uint32_t next_update = static_cast<uint32_t>(ctl->nextUpdate);
    if (is_ectl)
        topo.ectl_next_update = next_update;
    else
        topo.ctl_next_update = next_update;

    // Check freshness: warn if expired, but do NOT reject.
    if (next_update > 0) {
        auto now_tai = static_cast<int64_t>(time(nullptr)) - kTaiEpochUnix;
        if (now_tai > static_cast<int64_t>(next_update)) {
            if (is_ectl) {
                topo.ectl_expired = true;
                std::cerr << "[trust_list] WARNING: ECTL nextUpdate expired\n";
            } else {
                topo.ctl_expired = true;
                std::cerr << "[trust_list] WARNING: CTL nextUpdate expired\n";
            }
        }
    }

    // TODO: delta CTL (delete commands) + link certificates (successorTo) + isFullCtl.
    for (int i = 0; i < ctl->ctlCommands.list.count; ++i) {
        auto *cmd = ctl->ctlCommands.list.array[i];
        if (!cmd || cmd->present != CtlCommand_PR_add || !cmd->choice.add) continue;

        auto *entry = cmd->choice.add;

        switch (entry->present) {
            case CtlEntry_PR_rca: {
                if (!entry->choice.rca || !entry->choice.rca->selfsignedRootCa) break;
                auto ci = cert_ptr_to_info(entry->choice.rca->selfsignedRootCa, "rca");
                if (ci) topo.rcas.push_back(std::move(*ci));
                break;
            }
            case CtlEntry_PR_ea: {
                auto *ea = entry->choice.ea;
                if (!ea || !ea->eaCertificate) break;
                auto ci = cert_ptr_to_info(ea->eaCertificate, "ea");
                if (!ci) break;
                EaInfo info;
                info.cert = std::move(*ci);
                info.aa_access_point = url_from_ia5(&ea->aaAccessPoint);
                if (ea->itsAccessPoint) info.its_access_point = url_from_ia5(ea->itsAccessPoint);
                topo.eas.push_back(std::move(info));
                break;
            }
            case CtlEntry_PR_aa: {
                auto *aa = entry->choice.aa;
                if (!aa || !aa->aaCertificate) break;
                auto ci = cert_ptr_to_info(aa->aaCertificate, "aa");
                if (!ci) break;
                AaInfo info;
                info.cert = std::move(*ci);
                info.access_point = url_from_ia5(&aa->accessPoint);
                topo.aas.push_back(std::move(info));
                break;
            }
            case CtlEntry_PR_dc: {
                auto *dc = entry->choice.dc;
                if (!dc) break;
                DcInfo info;
                info.url = url_from_ia5(&dc->url);
                for (int j = 0; j < dc->cert.list.count; ++j) {
                    auto *hid8_os = dc->cert.list.array[j];
                    if (hid8_os && hid8_os->buf && hid8_os->size == kHashedId8Len) {
                        std::array<uint8_t, 8> h{};
                        std::copy_n(hid8_os->buf, kHashedId8Len, h.begin());
                        info.serves.push_back(h);
                    }
                }
                topo.dcs.push_back(std::move(info));
                break;
            }
            case CtlEntry_PR_tlm: {
                auto *tlm = entry->choice.tlm;
                if (!tlm || !tlm->selfSignedTLMCertificate) break;
                auto ci = cert_ptr_to_info(tlm->selfSignedTLMCertificate, "tlm");
                if (ci) topo.tlm = std::move(*ci);
                break;
            }
            default: break;
        }
    }
}

// Extract CtlFormat from EtsiTs102941Data payload.
// The unsecuredData Opaque contains COER(EtsiTs102941Data { version, content }),
// where content is a CHOICE with certificateTrustListTlm or certificateTrustListRca.
const CtlFormat_t *extract_ctl_from_etsi_data(const EtsiTs102941MessagesCa_EtsiTs102941Data_t *data,
                                              bool is_ectl) {
    if (!data || !data->content) return nullptr;

    using PR = EtsiTs102941MessagesCa_EtsiTs102941DataContent_PR;
    const auto *content = reinterpret_cast<
        const EtsiTs102941MessagesCa_EtsiTs102941DataContent_t *>(data->content);

    if (is_ectl) {
        if (content->present !=
            PR::EtsiTs102941MessagesCa_EtsiTs102941DataContent_PR_certificateTrustListTlm)
            return nullptr;
        // certificateTrustListTlm is struct ToBeSignedTlmCtl* = CtlFormat_t*
        return static_cast<const CtlFormat_t *>(
            static_cast<const void *>(content->choice.certificateTrustListTlm));
    } else {
        if (content->present !=
            PR::EtsiTs102941MessagesCa_EtsiTs102941DataContent_PR_certificateTrustListRca)
            return nullptr;
        return static_cast<const CtlFormat_t *>(
            static_cast<const void *>(content->choice.certificateTrustListRca));
    }
}

Result<TrustTopology> decode_ctl_common(const std::vector<uint8_t> &coer,
                                        const std::vector<uint8_t> &verifier_pubkey,
                                        const std::vector<uint8_t> &signer_cert_coer,
                                        bool is_ectl) {

    auto signed_data = unwrap_signed_ctl(coer);
    if (!signed_data) return Error::Decode;

    // Decode the payload as EtsiTs102941Data (version + DataContent CHOICE).
    auto etsi_data = asn_decode_fallback<
        EtsiTs102941MessagesCa_EtsiTs102941Data_t>(asn_DEF_EtsiTs102941MessagesCa_EtsiTs102941Data,
                                                   signed_data->payload_coer.data(),
                                                   signed_data->payload_coer.size());
    if (!etsi_data) return Error::Decode;

    const CtlFormat_t *ctl = extract_ctl_from_etsi_data(etsi_data.get(), is_ectl);
    if (!ctl) {
        return Error::Decode;
    }

    TrustTopology topo;
    parse_ctl_entries(ctl, topo, is_ectl);

    if (!verifier_pubkey.empty() && !signer_cert_coer.empty()) {
        bool verified = verify_signed_data(*signed_data, verifier_pubkey, signer_cert_coer);
        if (is_ectl)
            topo.ectl_signature_verified = verified;
        else
            topo.ctl_signature_verified = verified;
    }

    return topo;
}

}

// --- Public API ---

Result<TrustTopology> decode_ectl(const std::vector<uint8_t> &coer,
                                  const std::vector<uint8_t> &tlm_pubkey,
                                  const std::vector<uint8_t> &tlm_cert_coer) {
    return decode_ctl_common(coer, tlm_pubkey, tlm_cert_coer, true);
}

Result<TrustTopology> decode_rca_ctl(const std::vector<uint8_t> &coer,
                                     const std::vector<uint8_t> &rca_pubkey,
                                     const std::vector<uint8_t> &rca_cert_coer) {
    return decode_ctl_common(coer, rca_pubkey, rca_cert_coer, false);
}

std::string hid8_hex_upper(const std::array<uint8_t, 8> &hid8) {
    std::ostringstream oss;
    for (auto b : hid8)
        oss << std::hex << std::setfill('0') << std::setw(2) << std::uppercase
            << static_cast<int>(b);
    return oss.str();
}

std::optional<std::array<uint8_t, 8>> parse_hid8_hex(const std::string &hex) {
    if (hex.size() < 16) return std::nullopt;
    std::array<uint8_t, 8> out{};
    for (int i = 0; i < 8; ++i) {
        auto byte_str = hex.substr(static_cast<size_t>(i) * 2, 2);
        try {
            out[static_cast<size_t>(i)] = static_cast<uint8_t>(std::stoul(byte_str, nullptr, 16));
        } catch (...) {
            return std::nullopt;
        }
    }
    return out;
}

} // namespace v2xpki
