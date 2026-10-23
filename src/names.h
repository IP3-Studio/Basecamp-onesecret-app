// Qt-free helpers for reader names and profiles. A reader may say which name
// they open a link as, or carry a stable reader key without a name (the
// anonymous profile). The name and key travel sealed inside the claim so that
// only link holders can read them. A sender can verify a domain name through
// its DNS TXT record (see docs/names.md).
#pragma once

#include "crypto.h"

#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace osc::names {

constexpr size_t kMaxNameLength = 253;   // a domain name; plain names are shorter

// The TXT record a domain publishes, one per reader key:
//   _onesecret.<name>  TXT  "v=onesecret1 k=<64 hex of the X25519 public key>"
constexpr const char* kRecordPrefix = "_onesecret.";
constexpr const char* kRecordVersion = "v=onesecret1";

enum class Kind { Domain, Plain };

struct Name {
    Kind kind = Kind::Plain;
    std::string value;   // canonical: lowercase ASCII
};

// Canonical form of what a reader typed. A name with a dot is a domain:
// labels of 1 to 63 of [a-z0-9-] with no hyphen at either end, at least two
// labels, at most 253 characters, trailing dot dropped. Anything else is a
// plain name: 1 to 32 of [a-z0-9-], no hyphen at either end. Input must be
// ASCII; convert an internationalised domain to its ACE form first. nullopt
// when the input is neither.
std::optional<Name> normalise(std::string_view input);

// The tag in a claim: the reader key and the name (empty for an anonymous
// profile), AES-256-GCM under HKDF(K_claim, "onesecret/v1/name") with the
// secret id and the claim's R as associated data. Layout: iv12 || ct || tag16.
struct Tag {
    Bytes N;            // 32-byte X25519 public key
    std::string name;   // canonical name, or empty for an anonymous profile
};
Bytes sealTag(const Bytes& kClaim, const std::string& id, const Bytes& R, const Tag& tag);
std::optional<Tag> openTag(const Bytes& kClaim, const std::string& id, const Bytes& R, const Bytes& sealed);

// Reader keys listed by a name's TXT records: each record that carries
// "v=onesecret1" contributes its "k=<64 hex>" tokens.
std::vector<Bytes> listedKeys(const std::vector<std::string>& records);
bool lists(const std::vector<std::string>& records, const Bytes& key);

// The record text for this reader key, for the Open tab.
std::string recordFor(const std::string& domain, const Bytes& readerPub);

// The Logos names module (pull request 3, jefdiesel/logos-names): a name's
// "onesecret.key" text entry lists bare 64-hex reader keys separated by
// spaces, commas or newlines, set with `names set-text <name> onesecret.key <hex>`.
constexpr const char* kLogosKeyEntry = "onesecret.key";
std::vector<Bytes> listedKeysBare(std::string_view entry);
std::string commandFor(const std::string& name, const Bytes& readerPub);

// Empty on success, otherwise the first failing check.
std::string selfTest();

} // namespace osc::names
