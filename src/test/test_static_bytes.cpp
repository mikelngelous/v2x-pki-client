// Unit tests for StaticBytes<N>.

#include <gtest/gtest.h>

#include "v2xpki/static_bytes.hpp"

#include <vector>

using namespace v2xpki;

TEST(StaticBytesTest, FromFitsExactly) {
    uint8_t raw[4] = {1, 2, 3, 4};
    auto b = StaticBytes<4>::from(raw, 4);
    ASSERT_TRUE(b.has_value());
    EXPECT_EQ(b->size(), 4u);
    EXPECT_EQ(StaticBytes<4>::capacity(), 4u);
    EXPECT_EQ(std::vector<uint8_t>(b->begin(), b->end()), std::vector<uint8_t>({1, 2, 3, 4}));
}

TEST(StaticBytesTest, FromShorterThanCapacity) {
    uint8_t raw[2] = {9, 8};
    auto b = StaticBytes<8>::from(raw, 2);
    ASSERT_TRUE(b.has_value());
    EXPECT_EQ(b->size(), 2u);
    EXPECT_FALSE(b->empty());
}

TEST(StaticBytesTest, FromEmpty) {
    auto b = StaticBytes<8>::from(nullptr, 0);
    ASSERT_TRUE(b.has_value());
    EXPECT_TRUE(b->empty());
    EXPECT_EQ(b->size(), 0u);
}

TEST(StaticBytesTest, FromOverflowRejected) {
    uint8_t raw[5] = {1, 2, 3, 4, 5};
    auto b = StaticBytes<4>::from(raw, 5);
    EXPECT_FALSE(b.has_value());
}

TEST(StaticBytesTest, FromVector) {
    std::vector<uint8_t> v = {1, 2, 3};
    auto b = StaticBytes<16>::from(v);
    ASSERT_TRUE(b.has_value());
    EXPECT_EQ(b->size(), 3u);
    EXPECT_EQ(b->to_vector(), v);
}

TEST(StaticBytesTest, FromVectorOverflowRejected) {
    std::vector<uint8_t> v(17, 0x42);
    auto b = StaticBytes<16>::from(v);
    EXPECT_FALSE(b.has_value());
}

TEST(StaticBytesTest, Equality) {
    auto a = StaticBytes<4>::from(std::vector<uint8_t>{1, 2});
    auto b = StaticBytes<4>::from(std::vector<uint8_t>{1, 2});
    auto c = StaticBytes<4>::from(std::vector<uint8_t>{1, 3});
    auto d = StaticBytes<4>::from(std::vector<uint8_t>{1, 2, 3});
    ASSERT_TRUE(a.has_value() && b.has_value() && c.has_value() && d.has_value());
    EXPECT_EQ(*a, *b);
    EXPECT_NE(*a, *c);
    EXPECT_NE(*a, *d);
}

TEST(StaticBytesTest, DefaultConstructedIsEmpty) {
    StaticBytes<8> b;
    EXPECT_TRUE(b.empty());
    EXPECT_EQ(b.size(), 0u);
}
