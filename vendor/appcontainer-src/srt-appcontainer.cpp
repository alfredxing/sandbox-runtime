// srt-appcontainer.exe — Windows AppContainer sandbox launcher for sandbox-runtime.
//
// Two modes:
//   srt-appcontainer.exe --config <path.json>
//     Create an AppContainer profile, grant/deny ACLs on paths, enable loopback,
//     spawn a child process with a LowBox token (no internetClient capability),
//     wait for it, revoke ACLs, delete the profile, exit with the child's code.
//
//   srt-appcontainer.exe --sweep <path.aclstate>
//     Read a sidecar left behind by a crashed prior run, revoke the ACLs it
//     recorded, delete the profile, remove the sidecar. Used by the TS layer on
//     startup to recover from prior crashes.
//
// Build (MSVC):
//   cl /O2 /MT /EHsc /W4 /DUNICODE /D_UNICODE srt-appcontainer.cpp ^
//      /link userenv.lib advapi32.lib shell32.lib
//
//   /MT links the static CRT so the binary has no vcruntime140.dll dependency.
//
// Security model:
//   - AppContainer with zero capabilities: child cannot open outbound TCP to
//     non-loopback addresses. Loopback is blocked by default too (network
//     isolation); we explicitly exempt our SID via NetworkIsolationSetAppContainerConfig
//     so the child can reach the srt proxy on 127.0.0.1.
//   - Filesystem write is deny-by-default. allowWrite paths get an explicit
//     GRANT ACE for the AppContainer SID. denyRead paths get a DENY ACE.
//   - The child cannot mutate ACLs (no WRITE_DAC) so it cannot escape.
//   - All ACL changes are recorded in a sidecar file before spawning so that
//     a crash recovery sweep can undo them.

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <userenv.h>
#include <aclapi.h>
#include <sddl.h>
#include <shellapi.h>

#include <cstdio>
#include <cstdlib>
#include <cwchar>
#include <string>
#include <vector>

// ---------------------------------------------------------------------------
// Error handling
// ---------------------------------------------------------------------------

static void die(const wchar_t* msg, DWORD err = GetLastError()) {
    wchar_t* sysMsg = nullptr;
    FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
            FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr, err, 0, (LPWSTR)&sysMsg, 0, nullptr);
    fwprintf(stderr, L"srt-appcontainer: %ls (error %lu: %ls)\n", msg, err,
             sysMsg ? sysMsg : L"<no message>");
    if (sysMsg) LocalFree(sysMsg);
    // Caller is responsible for cleanup before calling die() in the main
    // flow; die() is only used directly for unrecoverable early failures.
    ExitProcess(127);
}

static void warn(const wchar_t* msg, DWORD err = GetLastError()) {
    fwprintf(stderr, L"srt-appcontainer: warning: %ls (error %lu)\n", msg, err);
}

// ---------------------------------------------------------------------------
// Tiny JSON reader
//
// Supports the subset we emit from the TS layer: UTF-8 input, objects at the
// top level, string and string-array values, boolean values. No numbers, no
// nesting beyond one level of arrays. This avoids pulling in a JSON library.
// ---------------------------------------------------------------------------

struct Config {
    std::wstring profileName;
    std::wstring command;
    std::wstring sidecarPath;
    std::vector<std::wstring> allowWrite;
    std::vector<std::wstring> denyRead;
    std::vector<std::wstring> env;  // "KEY=value" pairs to override/add
    bool needsNetworkRestriction = true;
};

struct JsonReader {
    const char* p;
    const char* end;

    void skipWs() {
        while (p < end && (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r'))
            p++;
    }

    bool consume(char c) {
        skipWs();
        if (p < end && *p == c) {
            p++;
            return true;
        }
        return false;
    }

    void expect(char c, const wchar_t* ctx) {
        if (!consume(c)) {
            fwprintf(stderr,
                     L"srt-appcontainer: JSON parse error: expected '%c' %ls\n",
                     c, ctx);
            ExitProcess(127);
        }
    }

    // Reads a JSON string (after the opening quote has been consumed) into a
    // UTF-8 std::string.
    std::string readStringBody() {
        std::string out;
        while (p < end && *p != '"') {
            if (*p == '\\' && p + 1 < end) {
                p++;
                switch (*p) {
                    case '"':  out += '"';  break;
                    case '\\': out += '\\'; break;
                    case '/':  out += '/';  break;
                    case 'n':  out += '\n'; break;
                    case 't':  out += '\t'; break;
                    case 'r':  out += '\r'; break;
                    case 'b':  out += '\b'; break;
                    case 'f':  out += '\f'; break;
                    case 'u': {
                        // Only handle BMP codepoints; surrogate pairs are
                        // unlikely in file paths / env strings.
                        if (p + 4 >= end) break;
                        wchar_t cp = 0;
                        for (int i = 1; i <= 4; i++) {
                            char h = p[i];
                            cp <<= 4;
                            if (h >= '0' && h <= '9') cp |= (h - '0');
                            else if (h >= 'a' && h <= 'f') cp |= (h - 'a' + 10);
                            else if (h >= 'A' && h <= 'F') cp |= (h - 'A' + 10);
                        }
                        p += 4;
                        // Encode cp as UTF-8.
                        if (cp < 0x80) {
                            out += (char)cp;
                        } else if (cp < 0x800) {
                            out += (char)(0xC0 | (cp >> 6));
                            out += (char)(0x80 | (cp & 0x3F));
                        } else {
                            out += (char)(0xE0 | (cp >> 12));
                            out += (char)(0x80 | ((cp >> 6) & 0x3F));
                            out += (char)(0x80 | (cp & 0x3F));
                        }
                        break;
                    }
                    default: out += *p; break;
                }
                p++;
            } else {
                out += *p++;
            }
        }
        if (p < end) p++;  // closing quote
        return out;
    }

    std::wstring readString() {
        expect('"', L"string start");
        std::string utf8 = readStringBody();
        if (utf8.empty()) return L"";
        int wlen = MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(),
                                       (int)utf8.size(), nullptr, 0);
        std::wstring out(wlen, L'\0');
        MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), (int)utf8.size(),
                            &out[0], wlen);
        return out;
    }

    std::vector<std::wstring> readStringArray() {
        std::vector<std::wstring> out;
        expect('[', L"array start");
        skipWs();
        if (p < end && *p == ']') {
            p++;
            return out;
        }
        while (true) {
            out.push_back(readString());
            skipWs();
            if (p < end && *p == ',') {
                p++;
                continue;
            }
            break;
        }
        expect(']', L"array end");
        return out;
    }

    bool readBool() {
        skipWs();
        if (p + 4 <= end && strncmp(p, "true", 4) == 0) {
            p += 4;
            return true;
        }
        if (p + 5 <= end && strncmp(p, "false", 5) == 0) {
            p += 5;
            return false;
        }
        fwprintf(stderr, L"srt-appcontainer: JSON parse error: expected bool\n");
        ExitProcess(127);
        return false;
    }

    // Skip an unknown value (string, array, bool, null) so the reader
    // tolerates extra keys emitted by newer TS versions.
    void skipValue() {
        skipWs();
        if (p >= end) return;
        if (*p == '"') { readString(); return; }
        if (*p == '[') { readStringArray(); return; }
        if (*p == 't' || *p == 'f') { readBool(); return; }
        if (p + 4 <= end && strncmp(p, "null", 4) == 0) { p += 4; return; }
        // Unknown token — advance to next delimiter.
        while (p < end && *p != ',' && *p != '}') p++;
    }
};

static Config parseConfigFile(const wchar_t* path) {
    HANDLE h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, nullptr,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) die(L"cannot open config file");
    DWORD size = GetFileSize(h, nullptr);
    std::string buf(size, '\0');
    DWORD read = 0;
    if (!ReadFile(h, &buf[0], size, &read, nullptr) || read != size) {
        CloseHandle(h);
        die(L"cannot read config file");
    }
    CloseHandle(h);

    Config cfg;
    JsonReader r{buf.c_str(), buf.c_str() + buf.size()};
    r.expect('{', L"config root");
    bool first = true;
    while (true) {
        r.skipWs();
        if (r.p < r.end && *r.p == '}') { r.p++; break; }
        if (!first) r.expect(',', L"between keys");
        first = false;
        std::wstring key = r.readString();
        r.expect(':', L"after key");
        if      (key == L"profileName")            cfg.profileName = r.readString();
        else if (key == L"command")                cfg.command     = r.readString();
        else if (key == L"sidecarPath")            cfg.sidecarPath = r.readString();
        else if (key == L"allowWrite")             cfg.allowWrite  = r.readStringArray();
        else if (key == L"denyRead")               cfg.denyRead    = r.readStringArray();
        else if (key == L"env")                    cfg.env         = r.readStringArray();
        else if (key == L"needsNetworkRestriction") cfg.needsNetworkRestriction = r.readBool();
        else r.skipValue();
    }
    return cfg;
}

// ---------------------------------------------------------------------------
// Sidecar file (.aclstate) — records what we granted so a sweep can undo it.
// Format: plain UTF-16LE text, one field per line:
//   line 1: profileName
//   line 2: SID string
//   remaining lines: <op>|<path>  where op is G (grant) or D (deny)
// ---------------------------------------------------------------------------

struct Sidecar {
    std::wstring profileName;
    std::wstring sidString;
    std::vector<std::pair<wchar_t, std::wstring>> aces;  // ('G'|'D', path)
};

static void writeSidecar(const std::wstring& path, const Sidecar& sc) {
    HANDLE h = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        warn(L"cannot write sidecar (crash recovery will not work)");
        return;
    }
    std::wstring content = sc.profileName + L"\n" + sc.sidString + L"\n";
    for (const auto& ace : sc.aces) {
        content += ace.first;
        content += L"|";
        content += ace.second;
        content += L"\n";
    }
    DWORD written = 0;
    WriteFile(h, content.c_str(), (DWORD)(content.size() * sizeof(wchar_t)),
              &written, nullptr);
    CloseHandle(h);
}

static bool readSidecar(const std::wstring& path, Sidecar& out) {
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ,
                           nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL,
                           nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    DWORD size = GetFileSize(h, nullptr);
    std::wstring buf(size / sizeof(wchar_t), L'\0');
    DWORD read = 0;
    ReadFile(h, &buf[0], size, &read, nullptr);
    CloseHandle(h);

    size_t pos = 0;
    auto nextLine = [&]() -> std::wstring {
        size_t nl = buf.find(L'\n', pos);
        if (nl == std::wstring::npos) nl = buf.size();
        std::wstring line = buf.substr(pos, nl - pos);
        pos = nl + 1;
        return line;
    };
    out.profileName = nextLine();
    out.sidString = nextLine();
    while (pos < buf.size()) {
        std::wstring line = nextLine();
        if (line.size() < 3 || line[1] != L'|') continue;
        out.aces.push_back({line[0], line.substr(2)});
    }
    return true;
}

// ---------------------------------------------------------------------------
// AppContainer profile lifecycle
// ---------------------------------------------------------------------------

static PSID createProfile(const std::wstring& name) {
    PSID sid = nullptr;
    HRESULT hr = CreateAppContainerProfile(
        name.c_str(), name.c_str(), name.c_str(), nullptr, 0, &sid);
    if (SUCCEEDED(hr)) return sid;
    if (HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS) == hr) {
        // Profile left over from a crashed prior run. Derive its SID.
        hr = DeriveAppContainerSidFromAppContainerName(name.c_str(), &sid);
        if (SUCCEEDED(hr)) return sid;
    }
    die(L"CreateAppContainerProfile failed", (DWORD)hr);
    return nullptr;
}

static void deleteProfile(const std::wstring& name) {
    DeleteAppContainerProfile(name.c_str());
}

// ---------------------------------------------------------------------------
// ACL grant/revoke
//
// GetNamedSecurityInfoW → SetEntriesInAclW (builds new DACL with our ACE
// prepended) → SetNamedSecurityInfoW.
//
// Deny ACEs are placed before allow ACEs by SetEntriesInAclW, which is the
// canonical DACL ordering Windows expects, so DENY on denyRead paths
// correctly overrides any inherited ALLOW from ALL APPLICATION PACKAGES.
// ---------------------------------------------------------------------------

static bool addAce(const std::wstring& path, PSID sid, ACCESS_MODE mode,
                   DWORD rights) {
    PACL oldDacl = nullptr;
    PSECURITY_DESCRIPTOR sd = nullptr;
    DWORD err = GetNamedSecurityInfoW(path.c_str(), SE_FILE_OBJECT,
                                      DACL_SECURITY_INFORMATION, nullptr,
                                      nullptr, &oldDacl, nullptr, &sd);
    if (err != ERROR_SUCCESS) {
        fwprintf(stderr,
                 L"srt-appcontainer: cannot read ACL on %ls (error %lu) — skipping\n",
                 path.c_str(), err);
        return false;
    }

    EXPLICIT_ACCESS_W ea = {};
    ea.grfAccessPermissions = rights;
    ea.grfAccessMode = mode;
    ea.grfInheritance = CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE;
    ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
    ea.Trustee.TrusteeType = TRUSTEE_IS_UNKNOWN;
    ea.Trustee.ptstrName = (LPWSTR)sid;

    PACL newDacl = nullptr;
    err = SetEntriesInAclW(1, &ea, oldDacl, &newDacl);
    if (err != ERROR_SUCCESS) {
        LocalFree(sd);
        fwprintf(stderr,
                 L"srt-appcontainer: SetEntriesInAcl failed on %ls (error %lu)\n",
                 path.c_str(), err);
        return false;
    }

    err = SetNamedSecurityInfoW((LPWSTR)path.c_str(), SE_FILE_OBJECT,
                                DACL_SECURITY_INFORMATION, nullptr, nullptr,
                                newDacl, nullptr);
    LocalFree(newDacl);
    LocalFree(sd);
    if (err != ERROR_SUCCESS) {
        fwprintf(stderr,
                 L"srt-appcontainer: SetNamedSecurityInfo failed on %ls (error %lu)\n",
                 path.c_str(), err);
        return false;
    }
    return true;
}

// Remove all ACEs for `sid` from `path`'s DACL.
static void removeAcesForSid(const std::wstring& path, PSID sid) {
    PACL oldDacl = nullptr;
    PSECURITY_DESCRIPTOR sd = nullptr;
    DWORD err = GetNamedSecurityInfoW(path.c_str(), SE_FILE_OBJECT,
                                      DACL_SECURITY_INFORMATION, nullptr,
                                      nullptr, &oldDacl, nullptr, &sd);
    if (err != ERROR_SUCCESS || oldDacl == nullptr) {
        if (sd) LocalFree(sd);
        return;
    }

    // Count ACEs that are NOT ours, allocate a new DACL for them.
    ACL_SIZE_INFORMATION sizeInfo = {};
    GetAclInformation(oldDacl, &sizeInfo, sizeof(sizeInfo), AclSizeInformation);

    // Build a new DACL copying every ACE except ones matching our SID.
    DWORD newSize = sizeof(ACL);
    std::vector<LPVOID> keep;
    for (DWORD i = 0; i < sizeInfo.AceCount; i++) {
        LPVOID ace = nullptr;
        if (!GetAce(oldDacl, i, &ace)) continue;
        PACE_HEADER hdr = (PACE_HEADER)ace;
        // ACCESS_ALLOWED_ACE and ACCESS_DENIED_ACE share the same layout:
        // Header, Mask, SidStart. We rely on that.
        PSID aceSid =
            (PSID) & ((PACCESS_ALLOWED_ACE)ace)->SidStart;  // same offset for DENIED
        if (EqualSid(aceSid, sid)) continue;
        keep.push_back(ace);
        newSize += hdr->AceSize;
    }

    PACL newDacl = (PACL)LocalAlloc(LPTR, newSize);
    if (!newDacl) {
        LocalFree(sd);
        return;
    }
    InitializeAcl(newDacl, newSize, ACL_REVISION);
    for (LPVOID ace : keep) {
        PACE_HEADER hdr = (PACE_HEADER)ace;
        AddAce(newDacl, ACL_REVISION, MAXDWORD, ace, hdr->AceSize);
    }

    SetNamedSecurityInfoW((LPWSTR)path.c_str(), SE_FILE_OBJECT,
                          DACL_SECURITY_INFORMATION, nullptr, nullptr, newDacl,
                          nullptr);
    LocalFree(newDacl);
    LocalFree(sd);
}

// ---------------------------------------------------------------------------
// Loopback exemption
//
// AppContainers are network-isolated by default: they cannot connect to
// 127.0.0.1 because that would let a compromised sandbox attack local
// services. We specifically WANT the child to reach srt's allowlist proxy on
// 127.0.0.1, so we exempt our per-invocation SID.
//
// NetworkIsolationSetAppContainerConfig is in Firewallapi.dll (Win8+) but is
// not always present in the import libs shipped with older SDKs, so we load
// it dynamically.
//
// On some Windows versions this call requires admin. If it fails with
// ERROR_ACCESS_DENIED, we print instructions for a one-time manual exemption
// and fail closed — network restriction was requested, we can't deliver it
// safely without the proxy being reachable.
// ---------------------------------------------------------------------------

typedef struct _INET_FIREWALL_AC_BINARY {
    DWORD size;
    BYTE* data;
} INET_FIREWALL_AC_BINARY;

typedef struct _INET_FIREWALL_APP_CONTAINER {
    SID* appContainerSid;
    SID* userSid;
    LPWSTR appContainerName;
    LPWSTR displayName;
    LPWSTR description;
    INET_FIREWALL_AC_BINARY capabilities;
    INET_FIREWALL_AC_BINARY binaries;
    LPWSTR workingDirectory;
    LPWSTR packageFullName;
} INET_FIREWALL_APP_CONTAINER;

typedef DWORD(WINAPI* PFN_NetIsoSetConfig)(DWORD, PSID_AND_ATTRIBUTES);
typedef DWORD(WINAPI* PFN_NetIsoGetConfig)(DWORD*, PSID_AND_ATTRIBUTES*);
typedef DWORD(WINAPI* PFN_NetIsoFree)(PSID_AND_ATTRIBUTES);

static bool enableLoopback(PSID sid) {
    HMODULE fw = LoadLibraryW(L"Firewallapi.dll");
    if (!fw) {
        warn(L"Firewallapi.dll not found; loopback to proxy may fail");
        return false;
    }
    auto getConfig = (PFN_NetIsoGetConfig)GetProcAddress(
        fw, "NetworkIsolationGetAppContainerConfig");
    auto setConfig = (PFN_NetIsoSetConfig)GetProcAddress(
        fw, "NetworkIsolationSetAppContainerConfig");
    auto freeConfig = (PFN_NetIsoFree)GetProcAddress(
        fw, "NetworkIsolationFreeAppContainers");
    if (!getConfig || !setConfig) {
        warn(L"NetworkIsolation APIs not found; loopback to proxy may fail");
        FreeLibrary(fw);
        return false;
    }

    // Read existing exemptions, append ours, write back. The API replaces the
    // full list, so we must merge.
    DWORD existingCount = 0;
    PSID_AND_ATTRIBUTES existing = nullptr;
    getConfig(&existingCount, &existing);

    std::vector<SID_AND_ATTRIBUTES> merged;
    for (DWORD i = 0; i < existingCount; i++) {
        merged.push_back(existing[i]);
    }
    SID_AND_ATTRIBUTES ours = {};
    ours.Sid = sid;
    ours.Attributes = 0;
    merged.push_back(ours);

    DWORD err = setConfig((DWORD)merged.size(), merged.data());

    if (existing && freeConfig) freeConfig(existing);
    FreeLibrary(fw);

    if (err != ERROR_SUCCESS) {
        wchar_t* sidStr = nullptr;
        ConvertSidToStringSidW(sid, &sidStr);
        fwprintf(stderr,
                 L"srt-appcontainer: loopback exemption failed (error %lu).\n"
                 L"  Network restriction is enabled but the sandboxed process cannot\n"
                 L"  reach the allowlist proxy. Run once as admin:\n"
                 L"    CheckNetIsolation LoopbackExempt -a -p=%ls\n"
                 L"  Or disable network restriction for this run.\n",
                 err, sidStr ? sidStr : L"<SID>");
        if (sidStr) LocalFree(sidStr);
        return false;
    }
    return true;
}

// Remove our SID from the loopback exemption list.
static void disableLoopback(PSID sid) {
    HMODULE fw = LoadLibraryW(L"Firewallapi.dll");
    if (!fw) return;
    auto getConfig = (PFN_NetIsoGetConfig)GetProcAddress(
        fw, "NetworkIsolationGetAppContainerConfig");
    auto setConfig = (PFN_NetIsoSetConfig)GetProcAddress(
        fw, "NetworkIsolationSetAppContainerConfig");
    auto freeConfig = (PFN_NetIsoFree)GetProcAddress(
        fw, "NetworkIsolationFreeAppContainers");
    if (!getConfig || !setConfig) {
        FreeLibrary(fw);
        return;
    }

    DWORD existingCount = 0;
    PSID_AND_ATTRIBUTES existing = nullptr;
    getConfig(&existingCount, &existing);

    std::vector<SID_AND_ATTRIBUTES> kept;
    for (DWORD i = 0; i < existingCount; i++) {
        if (!EqualSid(existing[i].Sid, sid)) kept.push_back(existing[i]);
    }
    setConfig((DWORD)kept.size(), kept.empty() ? nullptr : kept.data());

    if (existing && freeConfig) freeConfig(existing);
    FreeLibrary(fw);
}

// ---------------------------------------------------------------------------
// Environment block
//
// The child inherits our environment with cfg.env entries merged on top.
// We pass CREATE_UNICODE_ENVIRONMENT so the block is wide-char.
// Env block format: KEY=value\0KEY=value\0\0
// ---------------------------------------------------------------------------

static std::wstring buildEnvBlock(const std::vector<std::wstring>& overrides) {
    // Build a map of current env, then apply overrides.
    // GetEnvironmentStringsW returns KEY=val\0KEY=val\0\0.
    std::vector<std::pair<std::wstring, std::wstring>> vars;

    LPWCH envStrings = GetEnvironmentStringsW();
    if (envStrings) {
        const wchar_t* p = envStrings;
        while (*p) {
            size_t len = wcslen(p);
            const wchar_t* eq = wcschr(p, L'=');
            // Skip the per-drive cwd vars Windows uses internally (keys start
            // with '=', e.g. "=C:=C:\Users\x"). They're harmless to pass
            // through, so we keep them.
            if (eq && eq != p) {
                vars.push_back({std::wstring(p, eq - p), std::wstring(eq + 1)});
            } else if (eq == p) {
                // Keep the "=C:" style entries verbatim under a placeholder
                // so they survive the override merge below.
                const wchar_t* eq2 = wcschr(p + 1, L'=');
                if (eq2) {
                    vars.push_back({std::wstring(p, eq2 - p), std::wstring(eq2 + 1)});
                }
            }
            p += len + 1;
        }
        FreeEnvironmentStringsW(envStrings);
    }

    // Apply overrides (case-insensitive key match — Windows env is
    // case-insensitive).
    for (const auto& ov : overrides) {
        size_t eq = ov.find(L'=');
        if (eq == std::wstring::npos) continue;
        std::wstring key = ov.substr(0, eq);
        std::wstring val = ov.substr(eq + 1);
        bool replaced = false;
        for (auto& v : vars) {
            if (_wcsicmp(v.first.c_str(), key.c_str()) == 0) {
                v.second = val;
                replaced = true;
                break;
            }
        }
        if (!replaced) vars.push_back({key, val});
    }

    // Serialize.
    std::wstring block;
    for (const auto& v : vars) {
        block += v.first;
        block += L'=';
        block += v.second;
        block += L'\0';
    }
    block += L'\0';
    return block;
}

// ---------------------------------------------------------------------------
// Spawn inside AppContainer
// ---------------------------------------------------------------------------

static DWORD spawnInContainer(PSID sid, const Config& cfg) {
    // Allocate the proc-thread attribute list (one attribute: security caps).
    SIZE_T attrSize = 0;
    InitializeProcThreadAttributeList(nullptr, 1, 0, &attrSize);
    auto attrList =
        (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, attrSize);
    if (!attrList) die(L"HeapAlloc for attribute list");
    if (!InitializeProcThreadAttributeList(attrList, 1, 0, &attrSize)) {
        HeapFree(GetProcessHeap(), 0, attrList);
        die(L"InitializeProcThreadAttributeList");
    }

    // Build capability list. If network restriction is NOT requested, grant
    // the internetClient capability so the child can connect normally.
    // Otherwise, zero capabilities: outbound TCP is blocked at the kernel.
    SECURITY_CAPABILITIES secCaps = {};
    secCaps.AppContainerSid = sid;

    SID_AND_ATTRIBUTES capAttrs[1] = {};
    BYTE capSidBuf[SECURITY_MAX_SID_SIZE];
    if (!cfg.needsNetworkRestriction) {
        DWORD sidSize = sizeof(capSidBuf);
        if (CreateWellKnownSid(WinCapabilityInternetClientSid, nullptr,
                               capSidBuf, &sidSize)) {
            capAttrs[0].Sid = (PSID)capSidBuf;
            capAttrs[0].Attributes = SE_GROUP_ENABLED;
            secCaps.Capabilities = capAttrs;
            secCaps.CapabilityCount = 1;
        }
    }

    if (!UpdateProcThreadAttribute(
            attrList, 0, PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, &secCaps,
            sizeof(secCaps), nullptr, nullptr)) {
        DeleteProcThreadAttributeList(attrList);
        HeapFree(GetProcessHeap(), 0, attrList);
        die(L"UpdateProcThreadAttribute(SECURITY_CAPABILITIES)");
    }

    std::wstring envBlock = buildEnvBlock(cfg.env);

    STARTUPINFOEXW siex = {};
    siex.StartupInfo.cb = sizeof(siex);
    siex.lpAttributeList = attrList;

    PROCESS_INFORMATION pi = {};

    // CreateProcessW mutates lpCommandLine, so copy to a writable buffer.
    std::wstring cmdline = cfg.command;

    BOOL ok = CreateProcessW(
        nullptr,                  // lpApplicationName — use cmdline's first token
        &cmdline[0],              // lpCommandLine
        nullptr,                  // lpProcessAttributes
        nullptr,                  // lpThreadAttributes
        TRUE,                     // bInheritHandles — so stdio goes to parent
        EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT,
        (LPVOID)envBlock.c_str(), // lpEnvironment
        nullptr,                  // lpCurrentDirectory — inherit
        &siex.StartupInfo,
        &pi);

    DWORD createErr = GetLastError();
    DeleteProcThreadAttributeList(attrList);
    HeapFree(GetProcessHeap(), 0, attrList);

    if (!ok) {
        fwprintf(stderr,
                 L"srt-appcontainer: CreateProcessW failed (error %lu)\n"
                 L"  command: %ls\n",
                 createErr, cfg.command.c_str());
        return 127;
    }

    // Forward Ctrl+C to the child: by not calling SetConsoleCtrlHandler we
    // share the console and both get the signal; the child exits, we fall
    // through the wait, and run cleanup.
    WaitForSingleObject(pi.hProcess, INFINITE);

    DWORD exitCode = 1;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return exitCode;
}

// ---------------------------------------------------------------------------
// State for Ctrl+C handler — we want best-effort ACL cleanup even if the
// user interrupts mid-wait. The child gets the signal too (shared console).
// ---------------------------------------------------------------------------

static volatile PSID g_sid = nullptr;
static const Config* g_cfg = nullptr;
static volatile bool g_loopbackSet = false;

static void cleanup() {
    if (!g_sid || !g_cfg) return;
    PSID sid = (PSID)g_sid;
    for (const auto& p : g_cfg->allowWrite) removeAcesForSid(p, sid);
    for (const auto& p : g_cfg->denyRead)   removeAcesForSid(p, sid);
    if (g_loopbackSet) disableLoopback(sid);
    deleteProfile(g_cfg->profileName);
    if (!g_cfg->sidecarPath.empty()) DeleteFileW(g_cfg->sidecarPath.c_str());
    g_sid = nullptr;
}

static BOOL WINAPI ctrlHandler(DWORD type) {
    if (type == CTRL_C_EVENT || type == CTRL_BREAK_EVENT ||
        type == CTRL_CLOSE_EVENT) {
        // Child receives the signal too (shared console) and will exit.
        // WaitForSingleObject returns, normal cleanup runs. We just need to
        // NOT die before that happens. Return TRUE to say "handled, don't
        // kill us."
        return TRUE;
    }
    return FALSE;
}

// ---------------------------------------------------------------------------
// Sweep mode: undo a crashed run's ACL changes.
// ---------------------------------------------------------------------------

static int sweep(const wchar_t* sidecarPath) {
    Sidecar sc;
    if (!readSidecar(sidecarPath, sc)) {
        fwprintf(stderr, L"srt-appcontainer: cannot read sidecar %ls\n",
                 sidecarPath);
        return 1;
    }

    PSID sid = nullptr;
    if (!ConvertStringSidToSidW(sc.sidString.c_str(), &sid)) {
        // SID unparseable — best we can do is delete the profile and sidecar.
        deleteProfile(sc.profileName);
        DeleteFileW(sidecarPath);
        return 0;
    }

    for (const auto& ace : sc.aces) {
        removeAcesForSid(ace.second, sid);
    }
    disableLoopback(sid);
    deleteProfile(sc.profileName);
    LocalFree(sid);
    DeleteFileW(sidecarPath);
    return 0;
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

int wmain(int argc, wchar_t** argv) {
    if (argc >= 3 && wcscmp(argv[1], L"--sweep") == 0) {
        return sweep(argv[2]);
    }
    if (argc < 3 || wcscmp(argv[1], L"--config") != 0) {
        fwprintf(stderr,
                 L"usage: srt-appcontainer.exe --config <path.json>\n"
                 L"       srt-appcontainer.exe --sweep <path.aclstate>\n");
        return 2;
    }

    Config cfg = parseConfigFile(argv[2]);
    if (cfg.profileName.empty() || cfg.command.empty()) {
        fwprintf(stderr,
                 L"srt-appcontainer: config missing profileName or command\n");
        return 2;
    }

    SetConsoleCtrlHandler(ctrlHandler, TRUE);

    // 1. Create AppContainer profile → SID.
    PSID sid = createProfile(cfg.profileName);
    g_sid = sid;
    g_cfg = &cfg;

    wchar_t* sidStr = nullptr;
    ConvertSidToStringSidW(sid, &sidStr);

    Sidecar sc;
    sc.profileName = cfg.profileName;
    sc.sidString = sidStr ? sidStr : L"";

    // 2. Grant ACLs on allowWrite paths. We grant FILE_ALL_ACCESS minus
    // WRITE_DAC/WRITE_OWNER so the child can't reACL its way out. In
    // practice GENERIC_READ|GENERIC_WRITE|GENERIC_EXECUTE is enough.
    bool anyGrantFailed = false;
    for (const auto& p : cfg.allowWrite) {
        if (addAce(p, sid, GRANT_ACCESS,
                   GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE | DELETE)) {
            sc.aces.push_back({L'G', p});
        } else {
            anyGrantFailed = true;
        }
    }

    // 3. Deny ACLs on denyRead paths. DENY ACEs precede ALLOW ACEs in
    // canonical DACL order, so this overrides any inherited read grant.
    for (const auto& p : cfg.denyRead) {
        if (addAce(p, sid, DENY_ACCESS, GENERIC_READ | GENERIC_WRITE)) {
            sc.aces.push_back({L'D', p});
        }
        // A deny that fails to apply is not fatal — it means the path
        // doesn't exist or we lack WRITE_DAC. The child still can't write
        // (deny-by-default), it just might be able to read. We recorded
        // nothing in the sidecar so sweep won't try to undo.
    }

    // 4. Loopback exemption (only if network restriction active — otherwise
    // we granted internetClient and the child has full network anyway).
    if (cfg.needsNetworkRestriction) {
        if (enableLoopback(sid)) {
            g_loopbackSet = true;
        } else {
            // Fail closed: network restriction was requested but the child
            // won't be able to reach the proxy. enableLoopback already
            // printed instructions.
            cleanup();
            if (sidStr) LocalFree(sidStr);
            FreeSid(sid);
            return 126;
        }
    }

    // 5. Write sidecar so a future sweep can undo steps 2-4 if we crash now.
    if (!cfg.sidecarPath.empty()) {
        writeSidecar(cfg.sidecarPath, sc);
    }

    if (sidStr) LocalFree(sidStr);

    // 6-7. Spawn and wait.
    DWORD exitCode = spawnInContainer(sid, cfg);

    // 8. Revoke everything.
    cleanup();
    FreeSid(sid);

    // Best-effort: also remove the config JSON the TS layer wrote.
    // (The TS layer also cleans this up, but belt-and-suspenders.)
    DeleteFileW(argv[2]);

    // If a grant failed earlier, the child ran with partial write access —
    // not a security problem (too few permissions, not too many), but worth
    // surfacing if the child also failed.
    if (anyGrantFailed && exitCode != 0) {
        fwprintf(stderr,
                 L"srt-appcontainer: note: one or more allowWrite ACL grants failed; "
                 L"this may have caused the command to fail with access denied.\n");
    }

    return (int)exitCode;
}
