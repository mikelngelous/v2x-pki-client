#include "pki-provisioner/wire_dump.hpp"

#include "v2xpki/crypto_ec.hpp"

#include <cstdio>
#include <ctime>
#include <fstream>
#include <sys/stat.h>

namespace provisioning {

namespace {

std::string hex(const std::vector<uint8_t>& b) {
    static const char* d = "0123456789abcdef";
    std::string out;
    out.reserve(b.size() * 2);
    for (auto c : b) {
        out.push_back(d[c >> 4]);
        out.push_back(d[c & 0x0F]);
    }
    return out;
}

// Values are ours, but escape anyway so no surprise can produce malformed JSON.
std::string json_escape(const std::string& s) {
    std::string out;
    for (char c : s) {
        if (c == '"' || c == '\\')
            out += '\\';
        else if (c == '\n') {
            out += "\\n";
            continue;
        }
        out += c;
    }
    return out;
}

bool write_file(const std::string& path, const std::vector<uint8_t>& bytes) {
    std::ofstream ofs(path, std::ios::binary | std::ios::trunc);
    if (!ofs) return false;
    if (!bytes.empty())
        ofs.write(reinterpret_cast<const char*>(bytes.data()),
                  static_cast<std::streamsize>(bytes.size()));
    return ofs.good();
}

} // namespace

void WireDump::record(const std::string& step, const std::string& direction,
                      const std::vector<uint8_t>& bytes, const std::string& note, int http_status,
                      const std::string& content_type) {
    if (!enabled()) return;

    Entry e;
    e.step = step;
    e.direction = direction;
    e.file = step + ".coer";
    e.note = note;
    e.size = bytes.size();
    e.sha256 = hex(v2xpki::crypto::hash_sha256(bytes));
    e.http_status = http_status;
    e.content_type = content_type;
    entries_.push_back(std::move(e));
    blobs_.push_back(bytes);
}

void WireDump::record_key(const std::string& name, const std::vector<uint8_t>& key,
                          const std::string& note) {
    if (!enabled() || !with_keys_) return;
    record(name, "key-material", key, note);
}

void WireDump::meta(const std::string& key, const std::string& value) {
    if (!enabled()) return;
    meta_.emplace_back(key, value);
}

bool WireDump::flush() {
    if (!enabled()) return true;

    // Consumers need this to tell an expired corpus from a failing check.
    time_t now = time(nullptr);
    char stamp[32];
    strftime(stamp, sizeof(stamp), "%Y-%m-%dT%H:%M:%SZ", gmtime(&now));
    meta_.emplace_back("dumped_at_utc", stamp);
    if (with_keys_)
        meta_.emplace_back("warning",
                           "CONTAINS PRIVATE KEY MATERIAL. Disposable test station against a "
                           "testbed; never reuse this station, never publish this directory.");

    mkdir(dir_.c_str(), 0755);

    for (size_t i = 0; i < entries_.size(); ++i) {
        if (!write_file(dir_ + "/" + entries_[i].file, blobs_[i])) {
            fprintf(stderr, "[pki-provisioner] ERROR: cannot write %s\n", entries_[i].file.c_str());
            return false;
        }
    }

    std::ofstream m(dir_ + "/manifest.json", std::ios::trunc);
    if (!m) return false;

    m << "{\n";
    for (const auto& [k, v] : meta_)
        m << "  \"" << json_escape(k) << "\": \"" << json_escape(v) << "\",\n";
    m << "  \"artefacts\": [\n";
    for (size_t i = 0; i < entries_.size(); ++i) {
        const auto& e = entries_[i];
        m << "    {\"step\": \"" << e.step << "\", \"direction\": \"" << e.direction
          << "\", \"file\": \"" << e.file << "\", \"size\": " << e.size << ", \"sha256\": \""
          << e.sha256 << "\"";
        if (e.http_status != 0) m << ", \"http_status\": " << e.http_status;
        if (!e.content_type.empty())
            m << ", \"content_type\": \"" << json_escape(e.content_type) << "\"";
        if (!e.note.empty()) m << ", \"note\": \"" << json_escape(e.note) << "\"";
        m << "}" << (i + 1 < entries_.size() ? "," : "") << "\n";
    }
    m << "  ]\n}\n";

    if (!m.good()) return false;
    printf("[pki-provisioner] Wire dump: %zu artefacts -> %s\n", entries_.size(), dir_.c_str());
    dir_.clear();
    return true;
}

} // namespace provisioning
