// Host-side check of src/crypto.cpp against any OpenSSL 3.x:
//   clang++ -std=c++17 -Isrc -I$OPENSSL/include src/crypto.cpp src/names.cpp tests/crypto_selftest.cpp -L$OPENSSL/lib -lcrypto
#include "crypto.h"
#include "names.h"
#include <cstdio>
int main() {
    std::string r = osc::selfTest();
    if (r.empty()) r = osc::names::selfTest();
    if (!r.empty()) { std::printf("FAIL: %s\n", r.c_str()); return 1; }
    const auto k = osc::randomBytes(32), c = osc::randomBytes(8);
    const std::string link = osc::encodeLink(k, c);
    const auto d = osc::deriveFromLink(k);
    std::printf("OK\nsample link: %s\nid: %s\ntopic: %s\n", link.c_str(), d.id.c_str(), d.topic.c_str());
    return 0;
}
