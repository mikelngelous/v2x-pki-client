#pragma once

#include <chrono>
#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "v2xpki/result.hpp"

namespace v2xpki {

struct HttpResponse {
    int status_code;
    std::vector<uint8_t> body;
    std::map<std::string, std::string> headers;
};

struct HttpClientConfig {
    std::string ca_bundle_path;
    std::chrono::seconds timeout{30}; // total transfer timeout
    bool verify_tls = true;
    std::chrono::seconds connect_timeout{10}; // connection-phase timeout
    unsigned max_retries = 2; // extra attempts on transient failures
    std::chrono::milliseconds retry_backoff{500}; // base backoff; doubles each retry (exponential)
};

// Thread-safety: an HttpClient instance is NOT thread-safe — use one per thread.
// The one-time global libcurl init is synchronised (std::call_once) and safe
// across instances. PkiClient owns an HttpClient and inherits this contract.
//
// Transient failures (connect/resolve/timeout/reset, HTTP 5xx, HTTP 429) are
// retried up to max_retries with exponential backoff. Client errors (4xx other
// than 429) and TLS/certificate errors fail immediately.
class HttpClient {
public:
    explicit HttpClient(const HttpClientConfig& cfg);
    ~HttpClient();

    HttpClient(const HttpClient&) = delete;
    HttpClient& operator=(const HttpClient&) = delete;

    Result<HttpResponse> get(const std::string& url);
    Result<HttpResponse> post(const std::string& url, const std::vector<uint8_t>& body,
                              const std::string& content_type = "application/x-its-request");

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace v2xpki
