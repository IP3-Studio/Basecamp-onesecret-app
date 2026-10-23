#include "keystore.h"

#ifdef __APPLE__
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#endif

namespace osc::keystore {

#ifdef __APPLE__

namespace {

struct CfRef {
    CFTypeRef ref = nullptr;
    explicit CfRef(CFTypeRef r) : ref(r) {}
    ~CfRef() { if (ref) CFRelease(ref); }
    CfRef(const CfRef&) = delete;
    CfRef& operator=(const CfRef&) = delete;
};

CFStringRef cfString(const std::string& s)
{
    return CFStringCreateWithCString(kCFAllocatorDefault, s.c_str(), kCFStringEncodingUTF8);
}

CFDictionaryRef query(CFStringRef service, CFStringRef account, bool returnData)
{
    const void* keys[5] = {kSecClass, kSecAttrService, kSecAttrAccount, kSecReturnData, kSecMatchLimit};
    const void* vals[5] = {kSecClassGenericPassword, service, account, kCFBooleanTrue, kSecMatchLimitOne};
    return CFDictionaryCreate(kCFAllocatorDefault, keys, vals, returnData ? 5 : 3,
                              &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
}

std::string describe(OSStatus st)
{
    CfRef msg(SecCopyErrorMessageString(st, nullptr));
    char buf[256] = {0};
    if (msg.ref && CFStringGetCString(static_cast<CFStringRef>(msg.ref), buf, sizeof buf, kCFStringEncodingUTF8))
        return std::string(buf) + " (" + std::to_string(st) + ")";
    return "Keychain error " + std::to_string(st);
}

} // namespace

bool available() { return true; }

Result get(const std::string& service, const std::string& account)
{
    Result r;
    CfRef svc(cfString(service));
    CfRef acc(cfString(account));
    CfRef q(query(static_cast<CFStringRef>(svc.ref), static_cast<CFStringRef>(acc.ref), true));
    CFTypeRef out = nullptr;
    const OSStatus st = SecItemCopyMatching(static_cast<CFDictionaryRef>(q.ref), &out);
    if (st == errSecItemNotFound) {
        r.ok = true;
        return r;
    }
    if (st != errSecSuccess) {
        r.error = describe(st);
        return r;
    }
    CfRef data(out);
    const CFDataRef d = static_cast<CFDataRef>(data.ref);
    const UInt8* p = CFDataGetBytePtr(d);
    r.value.assign(p, p + CFDataGetLength(d));
    r.ok = true;
    r.found = true;
    return r;
}

Result set(const std::string& service, const std::string& account, const Bytes& value,
           const std::string& label)
{
    Result r;
    remove(service, account);   // replace, if present
    CfRef svc(cfString(service));
    CfRef acc(cfString(account));
    CfRef lab(cfString(label));
    CfRef data(CFDataCreate(kCFAllocatorDefault, value.data(), static_cast<CFIndex>(value.size())));
    const void* keys[5] = {kSecClass, kSecAttrService, kSecAttrAccount, kSecAttrLabel, kSecValueData};
    const void* vals[5] = {kSecClassGenericPassword, svc.ref, acc.ref, lab.ref, data.ref};
    CfRef attrs(CFDictionaryCreate(kCFAllocatorDefault, keys, vals, 5,
                                   &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks));
    const OSStatus st = SecItemAdd(static_cast<CFDictionaryRef>(attrs.ref), nullptr);
    if (st != errSecSuccess) {
        r.error = describe(st);
        return r;
    }
    r.ok = true;
    return r;
}

Result remove(const std::string& service, const std::string& account)
{
    Result r;
    CfRef svc(cfString(service));
    CfRef acc(cfString(account));
    CfRef q(query(static_cast<CFStringRef>(svc.ref), static_cast<CFStringRef>(acc.ref), false));
    const OSStatus st = SecItemDelete(static_cast<CFDictionaryRef>(q.ref));
    r.ok = st == errSecSuccess || st == errSecItemNotFound;
    if (!r.ok)
        r.error = describe(st);
    return r;
}

#else

bool available() { return false; }
Result get(const std::string&, const std::string&) { Result r; r.error = "no platform key store"; return r; }
Result set(const std::string&, const std::string&, const Bytes&, const std::string&) { Result r; r.error = "no platform key store"; return r; }
Result remove(const std::string&, const std::string&) { Result r; r.error = "no platform key store"; return r; }

#endif

} // namespace osc::keystore
