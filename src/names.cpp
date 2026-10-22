#include "names.h"

#include <algorithm>

namespace osc::names {

namespace {

constexpr size_t kMaxNameLength = 32;
const char* kInfoName = "onesecret/v1/name";

bool isNameChar(char c) { return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-'; }
bool isSeparator(char c) { return c == ' ' || c == ',' || c == '\n' || c == '\r' || c == '\t'; }

bool startsWith(std::string_view s, std::string_view p) { return s.substr(0, p.size()) == p; }
bool endsWith(std::string_view s, std::string_view p)
{
    return s.size() >= p.size() && s.substr(s.size() - p.size()) == p;
}

int hexValue(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

std::optional<Bytes> fromHex(std::string_view s)
{
    if (s.size() % 2) return std::nullopt;
    Bytes out;
    out.reserve(s.size() / 2);
    for (size_t i = 0; i < s.size(); i += 2) {
        const int hi = hexValue(s[i]), lo = hexValue(s[i + 1]);
        if (hi < 0 || lo < 0) return std::nullopt;
        out.push_back(static_cast<uint8_t>(hi * 16 + lo));
    }
    return out;
}

Bytes tagAad(const std::string& id, const Bytes& R) { return concat(fromString("name|" + id), R); }

} // namespace

std::optional<std::string> normalise(std::string_view input)
{
    while (!input.empty() && isSeparator(input.front())) input.remove_prefix(1);
    while (!input.empty() && isSeparator(input.back())) input.remove_suffix(1);
    std::string s(input);
    // ASCII only: a Unicode case fold would turn the Kelvin sign into "k".
    for (char& c : s)
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
    std::string_view v(s);
    if (startsWith(v, "lns:")) v.remove_prefix(4);
    if (startsWith(v, "@")) v.remove_prefix(1);
    if (endsWith(v, ".lez")) v.remove_suffix(4);
    if (v.empty() || v.size() > kMaxNameLength || v.front() == '-' || v.back() == '-')
        return std::nullopt;
    if (!std::all_of(v.begin(), v.end(), isNameChar))
        return std::nullopt;
    return std::string(v);
}

Bytes sealTag(const Bytes& kClaim, const std::string& id, const Bytes& R, const Tag& tag)
{
    Bytes key = hkdfSha256(kClaim, Bytes(), kInfoName, 32);
    Bytes plain = concat(tag.N, fromString(tag.name));
    const Bytes iv = randomBytes(12);
    Bytes out = concat(iv, aesGcmSeal(key, iv, plain, tagAad(id, R)));
    wipe(key);
    wipe(plain);
    return out;
}

std::optional<Tag> openTag(const Bytes& kClaim, const std::string& id, const Bytes& R, const Bytes& sealed)
{
    if (sealed.size() < 12 + 32 + 16 || sealed.size() > 12 + 32 + kMaxNameLength + 16)
        return std::nullopt;
    Bytes key = hkdfSha256(kClaim, Bytes(), kInfoName, 32);
    const Bytes iv(sealed.begin(), sealed.begin() + 12);
    const Bytes body(sealed.begin() + 12, sealed.end());
    auto plain = aesGcmOpen(key, iv, body, tagAad(id, R));
    wipe(key);
    if (!plain)
        return std::nullopt;
    Tag tag;
    tag.N.assign(plain->begin(), plain->begin() + 32);
    const std::string raw(plain->begin() + 32, plain->end());
    wipe(*plain);
    if (raw.empty())
        return tag;   // an anonymous profile
    const auto name = normalise(raw);
    if (!name || *name != raw)
        return std::nullopt;
    tag.name = *name;
    return tag;
}

std::vector<Bytes> listedKeys(std::string_view entry)
{
    std::vector<Bytes> keys;
    size_t i = 0;
    while (i < entry.size()) {
        while (i < entry.size() && isSeparator(entry[i])) ++i;
        size_t end = i;
        while (end < entry.size() && !isSeparator(entry[end])) ++end;
        const std::string_view token = entry.substr(i, end - i);
        if (token.size() == 64)
            if (auto key = fromHex(token))
                keys.push_back(std::move(*key));
        i = end;
    }
    return keys;
}

bool lists(std::string_view entry, const Bytes& key)
{
    const auto keys = listedKeys(entry);
    return key.size() == 32 && std::find(keys.begin(), keys.end(), key) != keys.end();
}

std::string selfTest()
{
    if (normalise("Alice") != std::optional<std::string>("alice")) return "names: lowercase";
    if (normalise("lns:@bob.lez") != std::optional<std::string>("bob")) return "names: prefixes";
    if (normalise("@jef.lez") != std::optional<std::string>("jef")) return "names: @ and .lez";
    if (normalise("-a") || normalise("a-") || normalise("") || normalise("a b") || normalise("a.b"))
        return "names: rejects malformed";
    if (normalise(std::string(33, 'a'))) return "names: length";
    if (normalise("\xE2\x84\xAA" "ate")) return "names: non-ASCII (Kelvin sign)";

    const Bytes kClaim = randomBytes(32), R = randomBytes(32);
    const Tag tag{"alice", x25519Generate().pub};
    const Bytes sealed = sealTag(kClaim, "abc", R, tag);
    const auto back = openTag(kClaim, "abc", R, sealed);
    if (!back || back->name != "alice" || back->N != tag.N) return "names: tag round trip";
    if (openTag(kClaim, "abd", R, sealed)) return "names: tag bound to id";
    if (openTag(kClaim, "abc", randomBytes(32), sealed)) return "names: tag bound to R";
    if (openTag(randomBytes(32), "abc", R, sealed)) return "names: tag needs K_claim";
    const auto anon = openTag(kClaim, "abc", R, sealTag(kClaim, "abc", R, Tag{"", tag.N}));
    if (!anon || !anon->name.empty() || anon->N != tag.N) return "names: anonymous profile tag";

    const std::string h = hex(tag.N);
    if (!lists("zz " + h + ",deadbeef", tag.N)) return "names: entry lists key";
    if (lists(h.substr(2), tag.N)) return "names: short token";
    if (lists("", tag.N)) return "names: empty entry";
    return std::string();
}

} // namespace osc::names
