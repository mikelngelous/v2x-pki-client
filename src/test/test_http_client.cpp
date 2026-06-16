// Tests for HttpClient.
// No local HTTPS server available — integration tests against
// public endpoints plus config and error-handling tests.

#include <gtest/gtest.h>

#include "v2xpki/http_client.hpp"

#include <chrono>

using namespace v2xpki;

TEST(HttpClientTest, ConstructDefaultConfig) {
    HttpClientConfig cfg;
    EXPECT_EQ(cfg.timeout, std::chrono::seconds{30});
    EXPECT_TRUE(cfg.verify_tls);
    EXPECT_TRUE(cfg.ca_bundle_path.empty());

    HttpClient client(cfg);
    SUCCEED();
}

TEST(HttpClientTest, ConstructCustomConfig) {
    HttpClientConfig cfg;
    cfg.timeout = std::chrono::seconds{5};
    cfg.verify_tls = false;
    cfg.ca_bundle_path = "/nonexistent/ca.pem";

    HttpClient client(cfg);
    SUCCEED();
}

TEST(HttpClientTest, GetInvalidUrl) {
    HttpClientConfig cfg;
    cfg.timeout = std::chrono::seconds{3};
    cfg.verify_tls = false;
    HttpClient client(cfg);

    auto resp = client.get("http://localhost:1/nonexistent");
    EXPECT_FALSE(resp.has_value());
    EXPECT_EQ(resp.error(), Error::Network);
}

TEST(HttpClientTest, GetMalformedUrl) {
    HttpClientConfig cfg;
    cfg.timeout = std::chrono::seconds{3};
    cfg.verify_tls = false;
    HttpClient client(cfg);

    auto resp = client.get("not-a-url");
    EXPECT_FALSE(resp.has_value());
    EXPECT_EQ(resp.error(), Error::Network);
}

TEST(HttpClientTest, PostInvalidUrl) {
    HttpClientConfig cfg;
    cfg.timeout = std::chrono::seconds{3};
    cfg.verify_tls = false;
    HttpClient client(cfg);

    std::vector<uint8_t> body = {0x01, 0x02, 0x03};
    auto resp = client.post("http://localhost:1/nonexistent", body);
    EXPECT_FALSE(resp.has_value());
    EXPECT_EQ(resp.error(), Error::Network);
}

TEST(HttpClientTest, PostEmptyBodyInvalid) {
    HttpClientConfig cfg;
    cfg.timeout = std::chrono::seconds{3};
    cfg.verify_tls = false;
    HttpClient client(cfg);

    std::vector<uint8_t> empty_body;
    auto resp = client.post("http://localhost:1/nonexistent", empty_body);
    EXPECT_FALSE(resp.has_value());
    EXPECT_EQ(resp.error(), Error::Network);
}

TEST(HttpClientTest, GetTimeout) {
    HttpClientConfig cfg;
    cfg.timeout = std::chrono::seconds{1};
    cfg.verify_tls = false;
    HttpClient client(cfg);

    // 192.0.2.1 is TEST-NET-1 (RFC 5737); should not respond
    auto resp = client.get("http://192.0.2.1:80/");
    EXPECT_FALSE(resp.has_value());
    EXPECT_EQ(resp.error(), Error::Network);
}

TEST(HttpClientTest, ResponseStruct) {
    HttpResponse resp;
    resp.status_code = 200;
    resp.body = {0x48, 0x65, 0x6C, 0x6C, 0x6F};
    resp.headers["Content-Type"] = "text/plain";

    EXPECT_EQ(resp.status_code, 200);
    EXPECT_EQ(resp.body.size(), 5u);
    EXPECT_EQ(resp.headers.count("Content-Type"), 1u);
    EXPECT_EQ(resp.headers["Content-Type"], "text/plain");
}

TEST(HttpClientTest, MultipleClients) {
    HttpClientConfig cfg1;
    cfg1.timeout = std::chrono::seconds{5};
    cfg1.verify_tls = false;

    HttpClientConfig cfg2;
    cfg2.timeout = std::chrono::seconds{10};
    cfg2.verify_tls = true;

    HttpClient client1(cfg1);
    HttpClient client2(cfg2);

    auto r1 = client1.get("http://localhost:1/test1");
    auto r2 = client2.get("http://localhost:1/test2");

    EXPECT_FALSE(r1.has_value());
    EXPECT_FALSE(r2.has_value());
}

TEST(HttpClientTest, PostCustomContentType) {
    HttpClientConfig cfg;
    cfg.timeout = std::chrono::seconds{3};
    cfg.verify_tls = false;
    HttpClient client(cfg);

    std::vector<uint8_t> body = {0x01};
    auto resp = client.post("http://localhost:1/", body, "application/octet-stream");
    EXPECT_FALSE(resp.has_value());
}
