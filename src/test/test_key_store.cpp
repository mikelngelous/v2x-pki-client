#include <gtest/gtest.h>

#include "v2xpki/plaintext_file_key_store.hpp"
#include "v2xpki/crypto_ec.hpp"

#include <filesystem>

using namespace v2xpki;
using namespace v2xpki::crypto;

class KeyStoreTest : public ::testing::Test {
protected:
    std::filesystem::path dir_;
    void SetUp() override {
        dir_ = std::filesystem::temp_directory_path() / "v2xpki_keystore_test";
        std::filesystem::create_directories(dir_);
    }
    void TearDown() override { std::filesystem::remove_all(dir_); }
};

TEST_F(KeyStoreTest, StoreLoadRoundTrip) {
    PlaintextFileKeyStore ks(dir_);
    auto kp = generate_keypair();
    ASSERT_TRUE(kp.has_value());

    auto h = *KeyHandle::from("test_key_01");
    ASSERT_TRUE(ks.store_keypair(h, *kp));

    auto loaded = ks.load_keypair(h);
    ASSERT_TRUE(loaded.has_value());
    EXPECT_EQ(loaded->public_key, kp->public_key);
    EXPECT_EQ(loaded->private_key, kp->private_key);
}

TEST_F(KeyStoreTest, LoadMissing) {
    PlaintextFileKeyStore ks(dir_);
    auto h = *KeyHandle::from("nonexistent_key");
    auto loaded = ks.load_keypair(h);
    EXPECT_FALSE(loaded.has_value());
}

TEST_F(KeyStoreTest, DistinctHandles) {
    PlaintextFileKeyStore ks(dir_);
    auto kp1 = generate_keypair();
    auto kp2 = generate_keypair();
    ASSERT_TRUE(kp1.has_value() && kp2.has_value());

    auto h1 = *KeyHandle::from("key_alpha");
    auto h2 = *KeyHandle::from("key_beta");
    ks.store_keypair(h1, *kp1);
    ks.store_keypair(h2, *kp2);

    auto loaded1 = ks.load_keypair(h1);
    auto loaded2 = ks.load_keypair(h2);
    ASSERT_TRUE(loaded1.has_value() && loaded2.has_value());
    EXPECT_EQ(loaded1->private_key, kp1->private_key);
    EXPECT_EQ(loaded2->private_key, kp2->private_key);
    EXPECT_NE(loaded1->private_key, loaded2->private_key);
}

TEST_F(KeyStoreTest, SignViaKeystore) {
    PlaintextFileKeyStore ks(dir_);
    auto kp = generate_keypair();
    ASSERT_TRUE(kp.has_value());

    auto h = *KeyHandle::from("sign_key");
    ks.store_keypair(h, *kp);

    std::vector<uint8_t> msg = {0xCA, 0xFE, 0xBA, 0xBE};
    auto sig = ks.sign(h, msg);
    ASSERT_TRUE(sig.has_value());

    EXPECT_TRUE(ecdsa_verify(kp->public_key.to_vector(), msg, *sig));
}

TEST_F(KeyStoreTest, EcdhViaKeystore) {
    PlaintextFileKeyStore ks(dir_);
    auto alice = generate_keypair();
    auto bob = generate_keypair();
    ASSERT_TRUE(alice.has_value() && bob.has_value());

    auto h_alice = *KeyHandle::from("alice");
    auto h_bob = *KeyHandle::from("bob");
    ks.store_keypair(h_alice, *alice);
    ks.store_keypair(h_bob, *bob);

    auto ss_ab = ks.derive_shared_secret(h_alice, bob->public_key.to_vector());
    auto ss_ba = ks.derive_shared_secret(h_bob, alice->public_key.to_vector());
    ASSERT_TRUE(ss_ab.has_value() && ss_ba.has_value());
    EXPECT_EQ(*ss_ab, *ss_ba);
}

TEST_F(KeyStoreTest, SignMissing) {
    PlaintextFileKeyStore ks(dir_);
    auto h = *KeyHandle::from("ghost");
    std::vector<uint8_t> msg = {0x01};
    auto sig = ks.sign(h, msg);
    EXPECT_FALSE(sig.has_value());
}

TEST_F(KeyStoreTest, Overwrite) {
    PlaintextFileKeyStore ks(dir_);
    auto kp1 = generate_keypair();
    auto kp2 = generate_keypair();
    ASSERT_TRUE(kp1.has_value() && kp2.has_value());

    auto h = *KeyHandle::from("overwrite_me");
    ks.store_keypair(h, *kp1);
    ks.store_keypair(h, *kp2);

    auto loaded = ks.load_keypair(h);
    ASSERT_TRUE(loaded.has_value());
    EXPECT_EQ(loaded->private_key, kp2->private_key);
}

TEST(KeyHandleTest, RejectsPathTraversal) {
    EXPECT_FALSE(KeyHandle::from("../../etc/cron.d/evil").has_value());
    EXPECT_FALSE(KeyHandle::from("..").has_value());
}

TEST(KeyHandleTest, RejectsPathSeparators) {
    EXPECT_FALSE(KeyHandle::from("foo/bar").has_value());
    EXPECT_FALSE(KeyHandle::from("foo\\bar").has_value());
}

TEST(KeyHandleTest, RejectsEmpty) { EXPECT_FALSE(KeyHandle::from("").has_value()); }

TEST(KeyHandleTest, RejectsOverLength) {
    EXPECT_FALSE(KeyHandle::from(std::string(65, 'a')).has_value());
    EXPECT_TRUE(KeyHandle::from(std::string(64, 'a')).has_value());
}

TEST(KeyHandleTest, AcceptsValidCharset) {
    EXPECT_TRUE(KeyHandle::from("canonical-at_01").has_value());
}
