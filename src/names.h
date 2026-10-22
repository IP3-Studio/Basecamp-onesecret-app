// Qt-free helpers for reading receipts by Logos name (LNS). A reader may say
// which name they open a link as; the sender checks that name's
// "onesecret.key" text entry and, when it lists the reader's key, wraps the
// release to that key as well, so only the name's holder can open it.
#pragma once

#include "crypto.h"

#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace osc::names {

// The text entry a name publishes its Onesecret reader keys in: one or more
// 64-hex X25519 public keys separated by spaces, commas or newlines.
constexpr const char* kKeyEntry = "onesecret.key";

// LNS SPEC section 2, the part a client needs: ASCII lowercase, an optional
// "lns:" then "@" prefix and ".lez" suffix dropped, then 1 to 32 of [a-z0-9-]
// with no hyphen at either end. nullopt when the input is not a name.
std::optional<std::string> normalise(std::string_view input);

// The name tag in a claim: the claimant's name (empty for an anonymous
// profile, which shows only the reader key) and reader key, sealed under
// HKDF(K_claim, "onesecret/v1/name") with the secret id and the claim's R as
// associated data. Only link holders can read it, so a store node cannot link
// a reader's secrets together by name. Layout: iv12 || AES-256-GCM(N || name).
struct Tag {
    std::string name;   // empty: an anonymous profile
    Bytes N;   // 32-byte X25519 public key
};
Bytes sealTag(const Bytes& kClaim, const std::string& id, const Bytes& R, const Tag& tag);
std::optional<Tag> openTag(const Bytes& kClaim, const std::string& id, const Bytes& R, const Bytes& sealed);

// The 32-byte keys an entry lists; tokens that are not 64 hex digits are skipped.
std::vector<Bytes> listedKeys(std::string_view entry);
bool lists(std::string_view entry, const Bytes& key);

// Empty on success, otherwise the first failing check. Run with osc::selfTest().
std::string selfTest();

} // namespace osc::names
