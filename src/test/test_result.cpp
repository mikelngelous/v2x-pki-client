// Unit tests for Result<T> template and Error enum.

#include <gtest/gtest.h>

#include "v2xpki/result.hpp"
#include "v2xpki/trust_list.hpp"

#include <cstring>
#include <string>
#include <vector>

using namespace v2xpki;

TEST(ResultTest, SuccessInt) {
    Result<int> r(42);
    EXPECT_TRUE(r.has_value());
    EXPECT_TRUE(static_cast<bool>(r));
    EXPECT_EQ(r.value(), 42);
    EXPECT_EQ(*r, 42);
    EXPECT_EQ(r.error(), Error::None);
}

TEST(ResultTest, FailureInt) {
    Result<int> r(Error::Network);
    EXPECT_FALSE(r.has_value());
    EXPECT_FALSE(static_cast<bool>(r));
    EXPECT_EQ(r.error(), Error::Network);
}

TEST(ResultTest, SuccessString) {
    Result<std::string> r(std::string("hello"));
    EXPECT_TRUE(r.has_value());
    EXPECT_EQ(r.value(), "hello");
    EXPECT_EQ(r->size(), 5u);
    EXPECT_EQ(*r, "hello");
    EXPECT_EQ(r.error(), Error::None);
}

TEST(ResultTest, SuccessVector) {
    std::vector<uint8_t> data = {0x01, 0x02, 0x03};
    Result<std::vector<uint8_t>> r(data);
    EXPECT_TRUE(r.has_value());
    EXPECT_EQ(r->size(), 3u);
    EXPECT_EQ(r.error(), Error::None);
}

TEST(ResultTest, StatusSuccess) {
    Status s(std::monostate{});
    EXPECT_TRUE(s.has_value());
    EXPECT_TRUE(static_cast<bool>(s));
    EXPECT_EQ(s.error(), Error::None);
}

TEST(ResultTest, StatusFailure) {
    Status s(Error::KeyStore);
    EXPECT_FALSE(s.has_value());
    EXPECT_FALSE(static_cast<bool>(s));
    EXPECT_EQ(s.error(), Error::KeyStore);
}

TEST(ResultTest, ToStringAll) {
    EXPECT_STREQ(to_string(Error::None), "none");
    EXPECT_STREQ(to_string(Error::InvalidArgument), "invalid argument");
    EXPECT_STREQ(to_string(Error::Network), "network");
    EXPECT_STREQ(to_string(Error::HttpStatus), "http status");
    EXPECT_STREQ(to_string(Error::Decode), "decode");
    EXPECT_STREQ(to_string(Error::Encode), "encode");
    EXPECT_STREQ(to_string(Error::Crypto), "crypto");
    EXPECT_STREQ(to_string(Error::SignatureInvalid), "signature invalid");
    EXPECT_STREQ(to_string(Error::NotFound), "not found");
    EXPECT_STREQ(to_string(Error::KeyStore), "keystore");
    EXPECT_STREQ(to_string(Error::Protocol), "protocol");
}

TEST(ResultTest, ErrorDistinct) {
    Result<int> r1(Error::Network);
    Result<int> r2(Error::Decode);
    Result<int> r3(Error::Crypto);
    EXPECT_NE(r1.error(), r2.error());
    EXPECT_NE(r2.error(), r3.error());
    EXPECT_NE(r1.error(), r3.error());
}

TEST(ResultTest, DecodeGarbageError) {
    std::vector<uint8_t> garbage = {0x00, 0x01, 0x02, 0x03};
    auto result = decode_ectl(garbage);
    EXPECT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), Error::Decode);
}

TEST(ResultTest, ResultStruct) {
    struct TestStruct {
        int code;
        std::string msg;
    };
    Result<TestStruct> r(TestStruct{200, "OK"});
    EXPECT_TRUE(r.has_value());
    EXPECT_EQ(r->code, 200);
    EXPECT_EQ(r->msg, "OK");

    Result<TestStruct> err(Error::Protocol);
    EXPECT_FALSE(err.has_value());
    EXPECT_EQ(err.error(), Error::Protocol);
}
