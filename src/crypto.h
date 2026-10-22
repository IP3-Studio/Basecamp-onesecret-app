// Qt-free cryptographic helpers for Onesecret, over OpenSSL 3 (libcrypto).
// Every function that handles key material works on std::vector<uint8_t>
// buffers that the caller wipes with osc::wipe() when done.
#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace osc {

using Bytes = std::vector<uint8_t>;

// ---- buffers ----------------------------------------------------------------
Bytes randomBytes(size_t n);        // RAND_priv_bytes; throws std::runtime_error
void wipe(Bytes& b);                // OPENSSL_cleanse, then clear
void wipe(std::string& s);
Bytes fromString(const std::string& s);
std::string toString(const Bytes& b);
Bytes concat(const Bytes& a, const Bytes& b);
Bytes concat(const Bytes& a, const Bytes& b, const Bytes& c);
Bytes concat(const Bytes& a, const Bytes& b, const Bytes& c, const Bytes& d);

// ---- hashing, KDF, MAC -------------------------------------------------------
Bytes sha256(const Bytes& data);
Bytes hkdfSha256(const Bytes& ikm, const Bytes& salt, const std::string& info, size_t len);
Bytes hmacSha256(const Bytes& key, const Bytes& data);
bool constantTimeEqual(const Bytes& a, const Bytes& b);
// Argon2id, t=2, m=64 MiB, p=1, 32-byte output. nullopt when libcrypto lacks it.
std::optional<Bytes> argon2id(const std::string& passphrase, const Bytes& salt16);

// ---- AEAD -------------------------------------------------------------------
// AES-256-GCM. seal returns ciphertext || 16-byte tag; open verifies the tag.
Bytes aesGcmSeal(const Bytes& key32, const Bytes& iv12, const Bytes& plain, const Bytes& aad);
std::optional<Bytes> aesGcmOpen(const Bytes& key32, const Bytes& iv12, const Bytes& ctTag,
                                const Bytes& aad);

// ---- X25519 ------------------------------------------------------------------
struct KeyPair {
    Bytes priv;
    Bytes pub;
};
KeyPair x25519Generate();
std::optional<Bytes> x25519Derive(const Bytes& priv32, const Bytes& peerPub32);

// ---- encodings --------------------------------------------------------------
std::string base64url(const Bytes& b);                   // unpadded
std::optional<Bytes> fromBase64url(const std::string& s);
std::string base32(const Bytes& b);                      // RFC 4648 lowercase, unpadded
std::string hex(const Bytes& b);
uint8_t crc8(const Bytes& b);                             // CRC-8/ATM, poly 0x07

// ---- the Onesecret link -----------------------------------------------------
// "os1_" + base64url(0x01 || K_link[32] || SHA-256(C)[0..8] || crc8) = 56 chars.
constexpr uint8_t kLinkVersion = 1;
constexpr const char* kLinkPrefix = "os1_";
struct LinkParts {
    Bytes kLink;    // 32
    Bytes commit;   // 8
};
std::string encodeLink(const Bytes& kLink32, const Bytes& commit8);
std::optional<LinkParts> decodeLink(const std::string& link);

// ---- protocol derivations ---------------------------------------------------
struct Derived {
    std::string id;      // 26 chars base32 of HKDF(K_link, "id", 16)
    std::string topic;   // /logos-onesecret/1/s-<id>/json
    Bytes kClaim;        // HKDF(K_link, "claim", 32): HMAC key for claim/gone
};
Derived deriveFromLink(const Bytes& kLink32);
// Data-encryption key: HKDF(salt = K_link || argon2(passphrase), ikm = K_rel).
Bytes dataKey(const Bytes& kLink32, const Bytes& kRel32, const Bytes& passKeyOrEmpty);
Bytes commitment(const Bytes& ciphertext);   // SHA-256(C)[0..8]

// Self-test used by the backend at start (and by tests/crypto_selftest.cpp).
// Returns an empty string on success, otherwise the first failing check.
std::string selfTest();

} // namespace osc
