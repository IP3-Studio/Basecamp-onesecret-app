// Where the at-rest key lives. On macOS it is a generic-password item in the
// user's login Keychain, created and read by this backend process; the
// Keychain's access control keeps it from other processes unless the user
// allows them. Elsewhere there is no platform store yet and the caller keeps
// the 0600 file (docs/design.md, "At rest").
#pragma once

#include "crypto.h"

#include <string>

namespace osc::keystore {

struct Result {
    bool ok = false;      // the store answered
    bool found = false;   // an item exists (for get)
    Bytes value;
    std::string error;    // when !ok
};

bool available();
Result get(const std::string& service, const std::string& account);
Result set(const std::string& service, const std::string& account, const Bytes& value,
           const std::string& label);
Result remove(const std::string& service, const std::string& account);

} // namespace osc::keystore
