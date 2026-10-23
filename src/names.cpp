#include "names.h"

#include <algorithm>
#include <cctype>

namespace osc::names {

namespace {

constexpr size_t kMaxPlainLength = 32;
constexpr size_t kMaxLabelLength = 63;
const char* kInfoName = "onesecret/v1/name";

bool isNameChar(char c) { return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-'; }
bool isSpace(char c) { return c == ' ' || c == '\t' || c == '\r' || c == '\n'; }

int hexValue(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

std::optional<Bytes> fromHex(std::string_view s)
{
    if (s.size() % 2)
        return std::nullopt;
    Bytes out;
    out.reserve(s.size() / 2);
    for (size_t i = 0; i < s.size(); i += 2) {
        const int hi = hexValue(s[i]), lo = hexValue(s[i + 1]);
        if (hi < 0 || lo < 0)
            return std::nullopt;
        out.push_back(static_cast<uint8_t>(hi * 16 + lo));
    }
    return out;
}

bool validLabel(std::string_view l)
{
    if (l.empty() || l.size() > kMaxLabelLength || l.front() == '-' || l.back() == '-')
        return false;
    return std::all_of(l.begin(), l.end(), isNameChar);
}

Bytes tagAad(const std::string& id, const Bytes& R) { return concat(fromString("name|" + id), R); }

std::vector<std::string_view> split(std::string_view s, char sep)
{
    std::vector<std::string_view> out;
    size_t start = 0;
    for (size_t i = 0; i <= s.size(); ++i) {
        if (i == s.size() || s[i] == sep) {
            out.push_back(s.substr(start, i - start));
            start = i + 1;
        }
    }
    return out;
}

} // namespace

std::optional<Name> normalise(std::string_view input)
{
    while (!input.empty() && isSpace(input.front())) input.remove_prefix(1);
    while (!input.empty() && isSpace(input.back())) input.remove_suffix(1);
    std::string s(input);
    for (char& c : s) {
        if (static_cast<unsigned char>(c) >= 0x80)
            return std::nullopt;   // ASCII only; IDN must arrive in ACE form
        if (c >= 'A' && c <= 'Z')
            c = static_cast<char>(c - 'A' + 'a');
    }
    if (!s.empty() && s.back() == '.')
        s.pop_back();
    if (s.empty() || s.size() > kMaxNameLength)
        return std::nullopt;
    Name n;
    if (s.find('.') != std::string::npos) {
        const auto labels = split(s, '.');
        if (labels.size() < 2)
            return std::nullopt;
        for (const auto& l : labels)
            if (!validLabel(l))
                return std::nullopt;
        n.kind = Kind::Domain;
    } else {
        if (s.size() > kMaxPlainLength || !validLabel(s))
            return std::nullopt;
        n.kind = Kind::Plain;
    }
    n.value = s;
    return n;
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
    if (!plain || plain->size() < 32)
        return std::nullopt;
    Tag tag;
    tag.N.assign(plain->begin(), plain->begin() + 32);
    const std::string raw(plain->begin() + 32, plain->end());
    wipe(*plain);
    if (raw.empty())
        return tag;   // an anonymous profile
    const auto name = normalise(raw);
    if (!name || name->value != raw)
        return std::nullopt;   // not canonical: refuse rather than guess
    tag.name = name->value;
    return tag;
}

std::vector<Bytes> listedKeys(const std::vector<std::string>& records)
{
    std::vector<Bytes> keys;
    for (const std::string& record : records) {
        std::vector<std::string_view> tokens;
        std::string_view v(record);
        size_t i = 0;
        while (i < v.size()) {
            while (i < v.size() && (isSpace(v[i]) || v[i] == ';')) ++i;
            size_t end = i;
            while (end < v.size() && !isSpace(v[end]) && v[end] != ';') ++end;
            if (end > i)
                tokens.push_back(v.substr(i, end - i));
            i = end;
        }
        if (std::find(tokens.begin(), tokens.end(), std::string_view(kRecordVersion)) == tokens.end())
            continue;
        for (const auto& t : tokens) {
            if (t.size() == 2 + 64 && (t.substr(0, 2) == "k=" || t.substr(0, 2) == "K="))
                if (auto key = fromHex(t.substr(2)))
                    keys.push_back(std::move(*key));
        }
    }
    return keys;
}

bool lists(const std::vector<std::string>& records, const Bytes& key)
{
    if (key.size() != 32)
        return false;
    const auto keys = listedKeys(records);
    return std::find(keys.begin(), keys.end(), key) != keys.end();
}

std::vector<Bytes> listedKeysBare(std::string_view entry)
{
    std::vector<Bytes> keys;
    size_t i = 0;
    while (i < entry.size()) {
        while (i < entry.size() && (isSpace(entry[i]) || entry[i] == ',')) ++i;
        size_t end = i;
        while (end < entry.size() && !isSpace(entry[end]) && entry[end] != ',') ++end;
        const std::string_view token = entry.substr(i, end - i);
        if (token.size() == 64)
            if (auto key = fromHex(token))
                keys.push_back(std::move(*key));
        i = end;
    }
    return keys;
}

std::string commandFor(const std::string& name, const Bytes& readerPub)
{
    return "names set-text " + name + " " + kLogosKeyEntry + " " + hex(readerPub);
}

std::string recordFor(const std::string& domain, const Bytes& readerPub)
{
    return std::string(kRecordPrefix) + domain + "  TXT  \"" + kRecordVersion + " k=" + hex(readerPub) + "\"";
}

std::string selfTest()
{
    auto n = normalise("Alice.Example.COM.");
    if (!n || n->kind != Kind::Domain || n->value != "alice.example.com") return "names: domain";
    n = normalise("  bob  ");
    if (!n || n->kind != Kind::Plain || n->value != "bob") return "names: plain";
    if (normalise("-a.example") || normalise("a-.example") || normalise("a..b") || normalise(".a") || normalise("")
        || normalise("a b") || normalise("a_b.c") || normalise("a-") || normalise(std::string(33, 'a')))
        return "names: rejects malformed";
    if (normalise(std::string(64, 'a') + ".example")) return "names: label length";
    if (normalise("\xE2\x84\xAA" "ate.example")) return "names: non-ASCII";

    const Bytes kClaim = randomBytes(32), R = randomBytes(32);
    const Tag tag{x25519Generate().pub, "alice.example.com"};
    const Bytes sealed = sealTag(kClaim, "abc", R, tag);
    const auto back = openTag(kClaim, "abc", R, sealed);
    if (!back || back->name != tag.name || back->N != tag.N) return "names: tag round trip";
    if (openTag(kClaim, "abd", R, sealed)) return "names: tag bound to id";
    if (openTag(kClaim, "abc", randomBytes(32), sealed)) return "names: tag bound to R";
    if (openTag(randomBytes(32), "abc", R, sealed)) return "names: tag needs K_claim";
    const auto anon = openTag(kClaim, "abc", R, sealTag(kClaim, "abc", R, Tag{tag.N, ""}));
    if (!anon || !anon->name.empty() || anon->N != tag.N) return "names: anonymous tag";
    if (openTag(kClaim, "abc", R, sealTag(kClaim, "abc", R, Tag{tag.N, "Alice"}))) return "names: non-canonical name refused";

    const std::string h = hex(tag.N);
    if (!lists({"v=onesecret1 k=" + h}, tag.N)) return "names: record lists key";
    if (!lists({"junk", "v=onesecret1 k=deadbeef k=" + h + " ; comment"}, tag.N)) return "names: record with extras";
    if (lists({"k=" + h}, tag.N)) return "names: record needs version tag";
    if (lists({"v=onesecret1 k=" + h.substr(2)}, tag.N)) return "names: short key";
    if (lists({}, tag.N)) return "names: no records";
    if (recordFor("alice.example.com", tag.N) != "_onesecret.alice.example.com  TXT  \"v=onesecret1 k=" + h + "\"") return "names: record text";
    {
        const auto bare = listedKeysBare("zz " + h + ",deadbeef\n" + h);
        if (bare.size() != 2 || bare[0] != tag.N) return "names: bare entry";
        if (!listedKeysBare(h.substr(2)).empty()) return "names: bare short token";
        if (commandFor("alice", tag.N) != "names set-text alice onesecret.key " + h) return "names: command text";
    }
    return std::string();
}

} // namespace osc::names
