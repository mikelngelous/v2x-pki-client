// Wire artefacts of one provisioning run, for external conformance tooling.
// Key dumping is off by default: it makes the dump directory as sensitive as a private key.

#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace provisioning {

class WireDump {
public:
    WireDump(std::string dir, bool with_keys)
        : dir_(std::move(dir))
        , with_keys_(with_keys) {}

    bool enabled() const { return !dir_.empty(); }
    bool with_keys() const { return with_keys_; }

    void record_key(const std::string& name, const std::vector<uint8_t>& key,
                    const std::string& note);

    // direction: "sent" (what we POSTed), "received" (raw HTTP body), "static" (trust anchors).
    void record(const std::string& step, const std::string& direction,
                const std::vector<uint8_t>& bytes, const std::string& note = {},
                int http_status = 0, const std::string& content_type = {});

    void meta(const std::string& key, const std::string& value);

    // Ends the dump: later artefacts are ignored, so a rotating provisioner cannot keep growing it.
    bool flush();

private:
    struct Entry {
        std::string step;
        std::string direction;
        std::string file;
        std::string note;
        size_t size;
        std::string sha256;
        int http_status;
        std::string content_type;
    };

    std::string dir_;
    bool with_keys_ = false;
    std::vector<Entry> entries_;
    std::vector<std::pair<std::string, std::string>> meta_;
    std::vector<std::vector<uint8_t>> blobs_;
};

} // namespace provisioning
