// CRL decode + revocation lookup. TS 102 941 §6.3.3.

#include "v2xpki/revocation.hpp"

#include <algorithm>

extern "C" {
#include "EtsiTs102941MessagesCa_EtsiTs102941Data.h"
#include "EtsiTs102941MessagesCa_EtsiTs102941DataContent.h"
#include "ToBeSignedCrl.h"
#include "asn_application.h"
}

#include "internal/asn_ptr.hpp"
#include "internal/coer.hpp"
#include "internal/signed_message.hpp"

namespace v2xpki {

Result<CrlContents> decode_crl(const std::vector<uint8_t>& coer,
                               const std::vector<uint8_t>& rca_pubkey,
                               const std::vector<uint8_t>& rca_cert_coer) {

    auto msg = signed_msg::unwrap(coer);
    if (!msg) return Error::Decode;

    if (rca_pubkey.empty() || rca_cert_coer.empty()) return Error::InvalidArgument;
    if (!signed_msg::verify(*msg, rca_pubkey, rca_cert_coer)) return Error::SignatureInvalid;

    auto etsi_data = asn_decode_fallback<
        EtsiTs102941MessagesCa_EtsiTs102941Data_t>(asn_DEF_EtsiTs102941MessagesCa_EtsiTs102941Data,
                                                   msg->payload_coer.data(),
                                                   msg->payload_coer.size());
    if (!etsi_data || !etsi_data->content) return Error::Decode;

    using PR = EtsiTs102941MessagesCa_EtsiTs102941DataContent_PR;
    const auto* content = reinterpret_cast<
        const EtsiTs102941MessagesCa_EtsiTs102941DataContent_t*>(etsi_data->content);
    if (content->present !=
        PR::EtsiTs102941MessagesCa_EtsiTs102941DataContent_PR_certificateRevocationList)
        return Error::Decode;

    const auto* crl = content->choice.certificateRevocationList;
    if (!crl) return Error::Decode;

    // The revocation store is keyed by the issuer, and without a digest there is no identity.
    // TODO: derive the issuer from the embedded cert when signer=certificate.
    if (!msg->has_signer_digest) return Error::Decode;

    CrlContents out;
    out.issuer_hid8 = msg->signer_hid8;
    out.this_update = static_cast<uint32_t>(crl->thisUpdate);
    out.next_update = static_cast<uint32_t>(crl->nextUpdate);

    for (int i = 0; i < crl->entries.list.count; ++i) {
        const auto* e = crl->entries.list.array[i];
        if (!e || !e->buf || e->size != static_cast<int>(kHashedId8Len)) continue;
        std::array<uint8_t, 8> h{};
        std::copy_n(e->buf, kHashedId8Len, h.begin());
        out.revoked.push_back(h);
    }
    return out;
}

bool RevocationStore::apply(const CrlContents& crl, int64_t now_tai) {
    if (crl.next_update > 0 && now_tai > static_cast<int64_t>(crl.next_update)) return false;

    std::set<std::array<uint8_t, 8>> entries(crl.revoked.begin(), crl.revoked.end());
    revoked_[crl.issuer_hid8] = std::move(entries);
    return true;
}

bool RevocationStore::is_revoked(const std::array<uint8_t, 8>& issuer_hid8,
                                 const std::array<uint8_t, 8>& cert_hid8) const {
    auto it = revoked_.find(issuer_hid8);
    if (it == revoked_.end()) return false;
    return it->second.count(cert_hid8) > 0;
}

} // namespace v2xpki
