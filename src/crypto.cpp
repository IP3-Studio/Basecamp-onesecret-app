#include "crypto.h"

#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include <cctype>
#include <cstring>
#include <memory>
#include <stdexcept>

namespace osc {

namespace {

struct KdfCtxDeleter { void operator()(EVP_KDF_CTX* p) const { EVP_KDF_CTX_free(p); } };
struct KdfDeleter { void operator()(EVP_KDF* p) const { EVP_KDF_free(p); } };
struct MacCtxDeleter { void operator()(EVP_MAC_CTX* p) const { EVP_MAC_CTX_free(p); } };
struct MacDeleter { void operator()(EVP_MAC* p) const { EVP_MAC_free(p); } };
struct CipherCtxDeleter { void operator()(EVP_CIPHER_CTX* p) const { EVP_CIPHER_CTX_free(p); } };
struct PkeyDeleter { void operator()(EVP_PKEY* p) const { EVP_PKEY_free(p); } };
struct PkeyCtxDeleter { void operator()(EVP_PKEY_CTX* p) const { EVP_PKEY_CTX_free(p); } };

const char kB64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const char kB32[] = "abcdefghijklmnopqrstuvwxyz234567";

int b64Value(char c)
{
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '-') return 62;
    if (c == '_') return 63;
    return -1;
}

} // namespace

// ---- buffers ----------------------------------------------------------------

Bytes randomBytes(size_t n)
{
    Bytes out(n);
    if (n > 0 && RAND_priv_bytes(out.data(), static_cast<int>(n)) != 1)
        throw std::runtime_error("RAND_priv_bytes failed");
    return out;
}

void wipe(Bytes& b)
{
    if (!b.empty())
        OPENSSL_cleanse(b.data(), b.size());
    b.clear();
    b.shrink_to_fit();
}

void wipe(std::string& s)
{
    if (!s.empty())
        OPENSSL_cleanse(s.data(), s.size());
    s.clear();
    s.shrink_to_fit();
}

Bytes fromString(const std::string& s) { return Bytes(s.begin(), s.end()); }
std::string toString(const Bytes& b) { return std::string(b.begin(), b.end()); }

Bytes concat(const Bytes& a, const Bytes& b)
{
    Bytes out;
    out.reserve(a.size() + b.size());
    out.insert(out.end(), a.begin(), a.end());
    out.insert(out.end(), b.begin(), b.end());
    return out;
}
Bytes concat(const Bytes& a, const Bytes& b, const Bytes& c) { return concat(concat(a, b), c); }
Bytes concat(const Bytes& a, const Bytes& b, const Bytes& c, const Bytes& d)
{
    return concat(concat(a, b), concat(c, d));
}

// ---- hashing, KDF, MAC -------------------------------------------------------

Bytes sha256(const Bytes& data)
{
    Bytes out(SHA256_DIGEST_LENGTH);
    unsigned int len = 0;
    if (EVP_Digest(data.data(), data.size(), out.data(), &len, EVP_sha256(), nullptr) != 1)
        throw std::runtime_error("EVP_Digest failed");
    out.resize(len);
    return out;
}

Bytes hkdfSha256(const Bytes& ikm, const Bytes& salt, const std::string& info, size_t len)
{
    std::unique_ptr<EVP_KDF, KdfDeleter> kdf(EVP_KDF_fetch(nullptr, "HKDF", nullptr));
    if (!kdf)
        throw std::runtime_error("HKDF unavailable");
    std::unique_ptr<EVP_KDF_CTX, KdfCtxDeleter> ctx(EVP_KDF_CTX_new(kdf.get()));
    if (!ctx)
        throw std::runtime_error("EVP_KDF_CTX_new failed");
    char digest[] = "SHA256";
    // OpenSSL rejects a null pointer even with length 0, so an empty salt or
    // info is simply left out of the parameter list (HKDF treats a missing
    // salt as all-zero, per RFC 5869).
    OSSL_PARAM params[5];
    int n = 0;
    params[n++] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, digest, 0);
    params[n++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY,
                                                    const_cast<uint8_t*>(ikm.data()), ikm.size());
    if (!salt.empty())
        params[n++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT,
                                                        const_cast<uint8_t*>(salt.data()), salt.size());
    if (!info.empty())
        params[n++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO,
                                                        const_cast<char*>(info.data()), info.size());
    params[n] = OSSL_PARAM_construct_end();
    Bytes out(len);
    if (ikm.empty() || EVP_KDF_derive(ctx.get(), out.data(), len, params) != 1)
        throw std::runtime_error("HKDF derive failed");
    return out;
}

Bytes hmacSha256(const Bytes& key, const Bytes& data)
{
    std::unique_ptr<EVP_MAC, MacDeleter> mac(EVP_MAC_fetch(nullptr, "HMAC", nullptr));
    if (!mac)
        throw std::runtime_error("HMAC unavailable");
    std::unique_ptr<EVP_MAC_CTX, MacCtxDeleter> ctx(EVP_MAC_CTX_new(mac.get()));
    if (!ctx)
        throw std::runtime_error("EVP_MAC_CTX_new failed");
    char digest[] = "SHA256";
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, digest, 0),
        OSSL_PARAM_construct_end(),
    };
    if (EVP_MAC_init(ctx.get(), key.data(), key.size(), params) != 1)
        throw std::runtime_error("EVP_MAC_init failed");
    if (EVP_MAC_update(ctx.get(), data.data(), data.size()) != 1)
        throw std::runtime_error("EVP_MAC_update failed");
    Bytes out(EVP_MAX_MD_SIZE);
    size_t len = 0;
    if (EVP_MAC_final(ctx.get(), out.data(), &len, out.size()) != 1)
        throw std::runtime_error("EVP_MAC_final failed");
    out.resize(len);
    return out;
}

bool constantTimeEqual(const Bytes& a, const Bytes& b)
{
    if (a.size() != b.size())
        return false;
    if (a.empty())
        return true;
    return CRYPTO_memcmp(a.data(), b.data(), a.size()) == 0;
}

std::optional<Bytes> argon2id(const std::string& passphrase, const Bytes& salt16)
{
    std::unique_ptr<EVP_KDF, KdfDeleter> kdf(EVP_KDF_fetch(nullptr, "ARGON2ID", nullptr));
    if (!kdf)
        return std::nullopt;
    std::unique_ptr<EVP_KDF_CTX, KdfCtxDeleter> ctx(EVP_KDF_CTX_new(kdf.get()));
    if (!ctx)
        return std::nullopt;
    uint32_t iter = 2;
    uint32_t memcost = 64 * 1024;   // KiB -> 64 MiB
    uint32_t lanes = 1;
    uint32_t threads = 1;
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_PASSWORD,
                                          const_cast<char*>(passphrase.data()),
                                          passphrase.size()),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT,
                                          const_cast<uint8_t*>(salt16.data()), salt16.size()),
        OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ITER, &iter),
        OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ARGON2_MEMCOST, &memcost),
        OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ARGON2_LANES, &lanes),
        OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_THREADS, &threads),
        OSSL_PARAM_construct_end(),
    };
    Bytes out(32);
    if (EVP_KDF_derive(ctx.get(), out.data(), out.size(), params) != 1)
        return std::nullopt;
    return out;
}

// ---- AEAD -------------------------------------------------------------------

Bytes aesGcmSeal(const Bytes& key32, const Bytes& iv12, const Bytes& plain, const Bytes& aad)
{
    if (key32.size() != 32 || iv12.size() != 12)
        throw std::runtime_error("aesGcmSeal: bad key or iv length");
    std::unique_ptr<EVP_CIPHER_CTX, CipherCtxDeleter> ctx(EVP_CIPHER_CTX_new());
    if (!ctx)
        throw std::runtime_error("EVP_CIPHER_CTX_new failed");
    if (EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1)
        throw std::runtime_error("EncryptInit failed");
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) != 1)
        throw std::runtime_error("set ivlen failed");
    if (EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, key32.data(), iv12.data()) != 1)
        throw std::runtime_error("EncryptInit key failed");
    int len = 0;
    if (!aad.empty() && EVP_EncryptUpdate(ctx.get(), nullptr, &len, aad.data(),
                                          static_cast<int>(aad.size())) != 1)
        throw std::runtime_error("aad failed");
    Bytes out(plain.size() + 16);
    int total = 0;
    if (!plain.empty()) {
        if (EVP_EncryptUpdate(ctx.get(), out.data(), &len, plain.data(),
                              static_cast<int>(plain.size())) != 1)
            throw std::runtime_error("EncryptUpdate failed");
        total = len;
    }
    if (EVP_EncryptFinal_ex(ctx.get(), out.data() + total, &len) != 1)
        throw std::runtime_error("EncryptFinal failed");
    total += len;
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, 16, out.data() + total) != 1)
        throw std::runtime_error("get tag failed");
    out.resize(static_cast<size_t>(total) + 16);
    return out;
}

std::optional<Bytes> aesGcmOpen(const Bytes& key32, const Bytes& iv12, const Bytes& ctTag,
                                const Bytes& aad)
{
    if (key32.size() != 32 || iv12.size() != 12 || ctTag.size() < 16)
        return std::nullopt;
    std::unique_ptr<EVP_CIPHER_CTX, CipherCtxDeleter> ctx(EVP_CIPHER_CTX_new());
    if (!ctx)
        return std::nullopt;
    if (EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1)
        return std::nullopt;
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) != 1)
        return std::nullopt;
    if (EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr, key32.data(), iv12.data()) != 1)
        return std::nullopt;
    int len = 0;
    if (!aad.empty() && EVP_DecryptUpdate(ctx.get(), nullptr, &len, aad.data(),
                                          static_cast<int>(aad.size())) != 1)
        return std::nullopt;
    const size_t ctLen = ctTag.size() - 16;
    Bytes out(ctLen);
    int total = 0;
    if (ctLen > 0) {
        if (EVP_DecryptUpdate(ctx.get(), out.data(), &len, ctTag.data(),
                              static_cast<int>(ctLen)) != 1) {
            wipe(out);
            return std::nullopt;
        }
        total = len;
    }
    Bytes tag(ctTag.end() - 16, ctTag.end());
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, 16, tag.data()) != 1) {
        wipe(out);
        return std::nullopt;
    }
    if (EVP_DecryptFinal_ex(ctx.get(), out.data() + total, &len) != 1) {
        wipe(out);
        return std::nullopt;
    }
    total += len;
    out.resize(static_cast<size_t>(total));
    return out;
}

// ---- X25519 ------------------------------------------------------------------

KeyPair x25519Generate()
{
    std::unique_ptr<EVP_PKEY_CTX, PkeyCtxDeleter> ctx(
        EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr));
    if (!ctx || EVP_PKEY_keygen_init(ctx.get()) != 1)
        throw std::runtime_error("X25519 keygen init failed");
    EVP_PKEY* raw = nullptr;
    if (EVP_PKEY_keygen(ctx.get(), &raw) != 1 || !raw)
        throw std::runtime_error("X25519 keygen failed");
    std::unique_ptr<EVP_PKEY, PkeyDeleter> key(raw);
    KeyPair kp;
    size_t len = 32;
    kp.priv.resize(32);
    if (EVP_PKEY_get_raw_private_key(key.get(), kp.priv.data(), &len) != 1 || len != 32)
        throw std::runtime_error("X25519 private export failed");
    len = 32;
    kp.pub.resize(32);
    if (EVP_PKEY_get_raw_public_key(key.get(), kp.pub.data(), &len) != 1 || len != 32)
        throw std::runtime_error("X25519 public export failed");
    return kp;
}

std::optional<Bytes> x25519Derive(const Bytes& priv32, const Bytes& peerPub32)
{
    if (priv32.size() != 32 || peerPub32.size() != 32)
        return std::nullopt;
    std::unique_ptr<EVP_PKEY, PkeyDeleter> me(EVP_PKEY_new_raw_private_key(
        EVP_PKEY_X25519, nullptr, priv32.data(), priv32.size()));
    std::unique_ptr<EVP_PKEY, PkeyDeleter> peer(EVP_PKEY_new_raw_public_key(
        EVP_PKEY_X25519, nullptr, peerPub32.data(), peerPub32.size()));
    if (!me || !peer)
        return std::nullopt;
    std::unique_ptr<EVP_PKEY_CTX, PkeyCtxDeleter> ctx(EVP_PKEY_CTX_new(me.get(), nullptr));
    if (!ctx || EVP_PKEY_derive_init(ctx.get()) != 1)
        return std::nullopt;
    if (EVP_PKEY_derive_set_peer(ctx.get(), peer.get()) != 1)
        return std::nullopt;
    size_t len = 0;
    if (EVP_PKEY_derive(ctx.get(), nullptr, &len) != 1 || len == 0)
        return std::nullopt;
    Bytes out(len);
    if (EVP_PKEY_derive(ctx.get(), out.data(), &len) != 1) {
        wipe(out);
        return std::nullopt;
    }
    out.resize(len);
    // RFC 7748: reject the all-zero shared secret (low-order peer point).
    bool allZero = true;
    for (uint8_t v : out)
        allZero = allZero && v == 0;
    if (allZero) {
        wipe(out);
        return std::nullopt;
    }
    return out;
}

// ---- encodings --------------------------------------------------------------

std::string base64url(const Bytes& b)
{
    std::string out;
    out.reserve((b.size() + 2) / 3 * 4);
    size_t i = 0;
    while (i + 2 < b.size()) {
        const uint32_t v = (uint32_t(b[i]) << 16) | (uint32_t(b[i + 1]) << 8) | b[i + 2];
        out += kB64[(v >> 18) & 63];
        out += kB64[(v >> 12) & 63];
        out += kB64[(v >> 6) & 63];
        out += kB64[v & 63];
        i += 3;
    }
    if (i + 1 == b.size()) {
        const uint32_t v = uint32_t(b[i]) << 16;
        out += kB64[(v >> 18) & 63];
        out += kB64[(v >> 12) & 63];
    } else if (i + 2 == b.size()) {
        const uint32_t v = (uint32_t(b[i]) << 16) | (uint32_t(b[i + 1]) << 8);
        out += kB64[(v >> 18) & 63];
        out += kB64[(v >> 12) & 63];
        out += kB64[(v >> 6) & 63];
    }
    return out;
}

std::optional<Bytes> fromBase64url(const std::string& s)
{
    Bytes out;
    out.reserve(s.size() * 3 / 4);
    uint32_t acc = 0;
    int bits = 0;
    for (char c : s) {
        if (c == '=')
            break;
        const int v = b64Value(c);
        if (v < 0)
            return std::nullopt;
        acc = (acc << 6) | uint32_t(v);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(static_cast<uint8_t>((acc >> bits) & 0xFF));
        }
    }
    // A dangling group of 1 char (6 bits) can never be valid.
    if (bits >= 6)
        return std::nullopt;
    return out;
}

std::string base32(const Bytes& b)
{
    std::string out;
    uint32_t acc = 0;
    int bits = 0;
    for (uint8_t v : b) {
        acc = (acc << 8) | v;
        bits += 8;
        while (bits >= 5) {
            bits -= 5;
            out += kB32[(acc >> bits) & 31];
        }
    }
    if (bits > 0)
        out += kB32[(acc << (5 - bits)) & 31];
    return out;
}

std::string hex(const Bytes& b)
{
    static const char* d = "0123456789abcdef";
    std::string out;
    out.reserve(b.size() * 2);
    for (uint8_t v : b) {
        out += d[v >> 4];
        out += d[v & 15];
    }
    return out;
}

uint8_t crc8(const Bytes& b)
{
    uint8_t crc = 0;
    for (uint8_t v : b) {
        crc ^= v;
        for (int i = 0; i < 8; ++i)
            crc = (crc & 0x80) ? static_cast<uint8_t>((crc << 1) ^ 0x07)
                               : static_cast<uint8_t>(crc << 1);
    }
    return crc;
}

// ---- link -------------------------------------------------------------------

std::string encodeLink(const Bytes& kLink32, const Bytes& commit8)
{
    if (kLink32.size() != 32 || commit8.size() != 8)
        throw std::runtime_error("encodeLink: bad lengths");
    Bytes body;
    body.reserve(42);
    body.push_back(kLinkVersion);
    body.insert(body.end(), kLink32.begin(), kLink32.end());
    body.insert(body.end(), commit8.begin(), commit8.end());
    body.push_back(crc8(body));
    const std::string out = std::string(kLinkPrefix) + base64url(body);
    return out;
}

std::optional<LinkParts> decodeLink(const std::string& linkIn)
{
    // Tolerate surrounding whitespace and a trailing full stop from chat clients.
    size_t a = 0;
    size_t z = linkIn.size();
    while (a < z && std::isspace(static_cast<unsigned char>(linkIn[a])))
        ++a;
    while (z > a && (std::isspace(static_cast<unsigned char>(linkIn[z - 1])) || linkIn[z - 1] == '.'))
        --z;
    const std::string link = linkIn.substr(a, z - a);
    const std::string prefix(kLinkPrefix);
    if (link.size() != prefix.size() + 56 || link.compare(0, prefix.size(), prefix) != 0)
        return std::nullopt;
    const auto body = fromBase64url(link.substr(prefix.size()));
    if (!body || body->size() != 42 || (*body)[0] != kLinkVersion)
        return std::nullopt;
    const Bytes head(body->begin(), body->end() - 1);
    if (crc8(head) != body->back())
        return std::nullopt;
    LinkParts parts;
    parts.kLink.assign(body->begin() + 1, body->begin() + 33);
    parts.commit.assign(body->begin() + 33, body->begin() + 41);
    return parts;
}

// ---- protocol derivations ---------------------------------------------------

Derived deriveFromLink(const Bytes& kLink32)
{
    Derived d;
    const Bytes noSalt;
    d.id = base32(hkdfSha256(kLink32, noSalt, "onesecret/v1/id", 16));
    d.topic = "/logos-onesecret/1/s-" + d.id + "/json";
    d.kClaim = hkdfSha256(kLink32, noSalt, "onesecret/v1/claim", 32);
    return d;
}

Bytes dataKey(const Bytes& kLink32, const Bytes& kRel32, const Bytes& passKeyOrEmpty)
{
    const Bytes salt = concat(kLink32, passKeyOrEmpty);
    return hkdfSha256(kRel32, salt, "onesecret/v1/dek", 32);
}

Bytes commitment(const Bytes& ciphertext)
{
    const Bytes h = sha256(ciphertext);
    return Bytes(h.begin(), h.begin() + 8);
}

// ---- self-test --------------------------------------------------------------

std::string selfTest()
{
    try {
        // RFC 5869 test case 1
        const Bytes ikm(22, 0x0b);
        Bytes salt;
        for (uint8_t i = 0; i < 13; ++i) salt.push_back(i);
        Bytes info;
        for (uint8_t i = 0xf0; i < 0xfa; ++i) info.push_back(i);
        const Bytes okm = hkdfSha256(ikm, salt, std::string(info.begin(), info.end()), 42);
        if (hex(okm).substr(0, 16) != "3cb25f25faacd57a")
            return "hkdf";
        // HMAC RFC 4231 case 2 ("Jefe", "what do ya want for nothing?")
        const Bytes mac = hmacSha256(fromString("Jefe"), fromString("what do ya want for nothing?"));
        if (hex(mac).substr(0, 16) != "5bdcc146bf60754e")
            return "hmac";
        // AES-GCM round trip + tamper
        const Bytes key = randomBytes(32), iv = randomBytes(12);
        const Bytes pt = fromString("the quick brown fox"), aad = fromString("aad");
        Bytes ct = aesGcmSeal(key, iv, pt, aad);
        auto back = aesGcmOpen(key, iv, ct, aad);
        if (!back || *back != pt)
            return "gcm-roundtrip";
        ct[0] ^= 1;
        if (aesGcmOpen(key, iv, ct, aad))
            return "gcm-tamper";
        // X25519 agreement
        const KeyPair a = x25519Generate(), b = x25519Generate();
        const auto s1 = x25519Derive(a.priv, b.pub), s2 = x25519Derive(b.priv, a.pub);
        if (!s1 || !s2 || *s1 != *s2 || s1->size() != 32)
            return "x25519";
        // base64url round trip, all lengths 0..9
        for (size_t n = 0; n < 10; ++n) {
            const Bytes r = randomBytes(n);
            const auto d = fromBase64url(base64url(r));
            if (!d || *d != r)
                return "base64url";
        }
        // link encode/decode, CRC catches a typo
        const Bytes kl = randomBytes(32), cm = randomBytes(8);
        std::string link = encodeLink(kl, cm);
        if (link.size() != 60)
            return "link-length";
        auto parts = decodeLink("  " + link + ".\n");
        if (!parts || parts->kLink != kl || parts->commit != cm)
            return "link-decode";
        link[10] = (link[10] == 'A') ? 'B' : 'A';
        if (decodeLink(link))
            return "link-crc";
        // id is 26 chars of base32
        const Derived dv = deriveFromLink(kl);
        if (dv.id.size() != 26 || dv.kClaim.size() != 32)
            return "derive";
        // argon2id present and deterministic
        const Bytes asalt = randomBytes(16);
        const auto p1 = argon2id("correct horse", asalt), p2 = argon2id("correct horse", asalt);
        if (!p1 || !p2 || *p1 != *p2 || p1->size() != 32)
            return "argon2id";
    } catch (const std::exception& e) {
        return std::string("exception: ") + e.what();
    }
    return std::string();
}

} // namespace osc
