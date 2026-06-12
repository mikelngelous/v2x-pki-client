#include "v2xpki/http_client.hpp"

#include <curl/curl.h>

#include <chrono>
#include <cstring>
#include <mutex>
#include <thread>

namespace v2xpki {

namespace {

size_t write_callback(char *ptr, size_t size, size_t nmemb, void *userdata) {
    auto *buf = static_cast<std::vector<uint8_t> *>(userdata);
    size_t total = size * nmemb;
    buf->insert(buf->end(), ptr, ptr + total);
    return total;
}

size_t header_callback(char *ptr, size_t size, size_t nmemb, void *userdata) {
    auto *headers = static_cast<std::map<std::string, std::string> *>(userdata);
    size_t total = size * nmemb;
    std::string line(ptr, total);

    auto colon = line.find(':');
    if (colon != std::string::npos) {
        auto key = line.substr(0, colon);
        auto val = line.substr(colon + 1);
        // trim whitespace
        while (!val.empty() && (val.front() == ' ' || val.front() == '\t'))
            val.erase(val.begin());
        while (!val.empty() && (val.back() == '\r' || val.back() == '\n'))
            val.pop_back();
        (*headers)[key] = val;
    }
    return total;
}

// transient network conditions.
bool is_transient(CURLcode c) {
    switch (c) {
        case CURLE_COULDNT_CONNECT:
        case CURLE_COULDNT_RESOLVE_HOST:
        case CURLE_COULDNT_RESOLVE_PROXY:
        case CURLE_OPERATION_TIMEDOUT:
        case CURLE_GOT_NOTHING:
        case CURLE_SEND_ERROR:
        case CURLE_RECV_ERROR:
        case CURLE_PARTIAL_FILE: return true;
        default: return false;
    }
}

// Apply the shared TLS/timeout/redirect options from cfg to an easy handle.
void apply_common_opts(CURL *curl, const HttpClientConfig &cfg) {
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, header_callback);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, static_cast<long>(cfg.timeout.count()));
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, static_cast<long>(cfg.connect_timeout.count()));
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 10L);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "v2xpki/0.1");

    if (cfg.verify_tls) {
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
        if (!cfg.ca_bundle_path.empty()) {
            curl_easy_setopt(curl, CURLOPT_CAINFO, cfg.ca_bundle_path.c_str());
        }
    } else {
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    }
}

// Run a configured easy handle, retrying transient failures (network errors,
// HTTP 5xx, HTTP 429) with exponential backoff. The handle is reused across
// attempts (curl reuses the connection). Returns nullopt only if no response
// was ever obtained.
Result<HttpResponse> perform_with_retry(CURL *curl, const HttpClientConfig &cfg) {
    HttpResponse resp;
    for (unsigned attempt = 0;; ++attempt) {
        resp.body.clear();
        resp.headers.clear();
        resp.status_code = 0;
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &resp.body);
        curl_easy_setopt(curl, CURLOPT_HEADERDATA, &resp.headers);

        CURLcode res = curl_easy_perform(curl);
        if (res == CURLE_OK) {
            long code = 0;
            curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
            resp.status_code = static_cast<int>(code);
            // Retry only server-side transients; success and client errors are final.
            if (resp.status_code < 500 && resp.status_code != 429) return resp;
        } else if (!is_transient(res)) {
            return Error::Network; // permanent (TLS, malformed URL, ...)
        }

        if (attempt >= cfg.max_retries) break;
        std::this_thread::sleep_for(cfg.retry_backoff * (1u << attempt));
    }
    // Retries exhausted: return the last response if we got one, else nullopt.
    return resp.status_code != 0 ? Result<HttpResponse>(resp)
                                 : Result<HttpResponse>(Error::Network);
}

}

struct HttpClient::Impl {
    HttpClientConfig config;
};

HttpClient::HttpClient(const HttpClientConfig &cfg)
    : impl_(std::make_unique<Impl>(Impl{cfg})) {
    static std::once_flag curl_once;
    std::call_once(curl_once, [] { curl_global_init(CURL_GLOBAL_DEFAULT); });
}

HttpClient::~HttpClient() = default;

Result<HttpResponse> HttpClient::get(const std::string &url) {
    CURL *curl = curl_easy_init();
    if (!curl) return Error::Network;

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    apply_common_opts(curl, impl_->config);

    auto resp = perform_with_retry(curl, impl_->config);
    curl_easy_cleanup(curl);
    return resp;
}

Result<HttpResponse> HttpClient::post(const std::string &url, const std::vector<uint8_t> &body,
                                      const std::string &content_type) {

    CURL *curl = curl_easy_init();
    if (!curl) return Error::Network;

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body.data());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, static_cast<long>(body.size()));
    apply_common_opts(curl, impl_->config);

    struct curl_slist *headers = nullptr;
    std::string ct_header = "Content-Type: " + content_type;
    headers = curl_slist_append(headers, ct_header.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    auto resp = perform_with_retry(curl, impl_->config);

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    return resp;
}

} // namespace v2xpki
