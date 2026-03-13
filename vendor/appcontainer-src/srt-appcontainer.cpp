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
//      /link userenv.lib advapi32.lib shell32.lib ws2_32.lib
//
//   /MT links the static CRT so the binary has no vcruntime140.dll dependency.
//
// Security model:
//   - AppContainer with zero capabilities: child cannot open outbound TCP to
//     non-loopback addresses. Loopback to other processes is also blocked by
//     AppContainer network isolation — but intra-container loopback works
//     (two processes with the same AppContainer SID can talk to each other).
//   - Network bridge: a named pipe crosses the AppContainer boundary. The
//     helper listens on \\.\pipe\srt-<id>-{http,socks} (pipe DACL grants the
//     AppContainer SID) and forwards to the srt proxy on 127.0.0.1. An
//     in-container forwarder listens on 127.0.0.1:{3128,1080} and forwards
//     to the pipe. The user command sees HTTP_PROXY=http://127.0.0.1:3128.
//   - Filesystem write is deny-by-default. allowWrite paths get an explicit
//     GRANT ACE for the AppContainer SID. denyRead paths have the SID's
//     inherited ALLOW stripped and DACL protected from re-inheritance.
//   - The child cannot mutate ACLs (no WRITE_DAC) so it cannot escape.
//   - All ACL changes are recorded in a sidecar file before spawning so that
//     a crash recovery sweep can undo them.

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <userenv.h>
#include <aclapi.h>
#include <sddl.h>
#include <shellapi.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <process.h>

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
    // Pipe bridge: host-side proxy ports to forward pipe traffic to, and
    // path to the in-container forwarder binary. Zero port = not used.
    int httpProxyPort = 0;
    int socksProxyPort = 0;
    std::wstring forwarderPath;
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

    int readInt() {
        skipWs();
        int sign = 1;
        if (p < end && *p == '-') { sign = -1; p++; }
        int v = 0;
        while (p < end && *p >= '0' && *p <= '9') {
            v = v * 10 + (*p - '0');
            p++;
        }
        return v * sign;
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
        if ((*p >= '0' && *p <= '9') || *p == '-') { readInt(); return; }
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
        else if (key == L"httpProxyPort")          cfg.httpProxyPort  = r.readInt();
        else if (key == L"socksProxyPort")         cfg.socksProxyPort = r.readInt();
        else if (key == L"forwarderPath")          cfg.forwarderPath  = r.readString();
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

    // UNPROTECTED restores inheritance on paths where addAce used PROTECTED.
    SetNamedSecurityInfoW((LPWSTR)path.c_str(), SE_FILE_OBJECT,
                          DACL_SECURITY_INFORMATION | UNPROTECTED_DACL_SECURITY_INFORMATION,
                          nullptr, nullptr, newDacl,
                          nullptr);
    LocalFree(newDacl);
    LocalFree(sd);
}

// ---------------------------------------------------------------------------
// Named-pipe bridge
//
// AppContainer network isolation blocks loopback to processes outside the
// container, and the admin-only NetworkIsolationSetAppContainerConfig
// exemption is not usable here. Instead we bridge over a named pipe: pipe
// DACLs are filesystem-object security, not subject to network isolation.
//
// The helper (full integrity) creates \\.\pipe\srt-<id>-{http,socks} with a
// DACL granting the AppContainer SID, and runs threads that accept pipe
// connections and forward each to 127.0.0.1:<proxyPort>. The in-container
// forwarder connects to these pipes and exposes TCP listeners on
// 127.0.0.1:{3128,1080} that the user command uses via HTTP_PROXY/ALL_PROXY.
// ---------------------------------------------------------------------------

// Build a security descriptor granting the AppContainer SID full access to
// the pipe. System/current-user get access implicitly (as pipe creator).
static bool buildPipeSA(PSID containerSid, SECURITY_ATTRIBUTES* sa,
                        PSECURITY_DESCRIPTOR* outSd, PACL* outDacl) {
    // Also grant the current user so the helper's own CreateNamedPipe works
    // (creator owns the pipe, but an explicit ACE avoids edge cases).
    HANDLE token = nullptr;
    OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token);
    DWORD userLen = 0;
    GetTokenInformation(token, TokenUser, nullptr, 0, &userLen);
    auto userBuf = (PTOKEN_USER)LocalAlloc(LPTR, userLen);
    GetTokenInformation(token, TokenUser, userBuf, userLen, &userLen);
    CloseHandle(token);

    EXPLICIT_ACCESS_W ea[2] = {};
    ea[0].grfAccessPermissions = GENERIC_READ | GENERIC_WRITE;
    ea[0].grfAccessMode = GRANT_ACCESS;
    ea[0].grfInheritance = NO_INHERITANCE;
    ea[0].Trustee.TrusteeForm = TRUSTEE_IS_SID;
    ea[0].Trustee.ptstrName = (LPWSTR)containerSid;

    ea[1] = ea[0];
    ea[1].grfAccessPermissions = GENERIC_ALL;
    ea[1].Trustee.ptstrName = (LPWSTR)userBuf->User.Sid;

    PACL dacl = nullptr;
    if (SetEntriesInAclW(2, ea, nullptr, &dacl) != ERROR_SUCCESS) {
        LocalFree(userBuf);
        return false;
    }
    LocalFree(userBuf);

    PSECURITY_DESCRIPTOR sd = LocalAlloc(LPTR, SECURITY_DESCRIPTOR_MIN_LENGTH);
    InitializeSecurityDescriptor(sd, SECURITY_DESCRIPTOR_REVISION);
    SetSecurityDescriptorDacl(sd, TRUE, dacl, FALSE);

    sa->nLength = sizeof(*sa);
    sa->lpSecurityDescriptor = sd;
    sa->bInheritHandle = FALSE;
    *outSd = sd;
    *outDacl = dacl;
    return true;
}

struct BridgeShuttle {
    SOCKET sock;
    HANDLE pipe;
    bool pipeToSock;
};

static unsigned __stdcall bridgeShuttle(void* argp) {
    BridgeShuttle* s = (BridgeShuttle*)argp;
    char buf[16 * 1024];
    if (s->pipeToSock) {
        for (;;) {
            DWORD n = 0;
            if (!ReadFile(s->pipe, buf, sizeof(buf), &n, nullptr) || n == 0) break;
            int off = 0;
            while (off < (int)n) {
                int w = send(s->sock, buf + off, (int)n - off, 0);
                if (w <= 0) goto done1;
                off += w;
            }
        }
    done1:
        CloseHandle(s->pipe);
        shutdown(s->sock, SD_SEND);
    } else {
        for (;;) {
            int n = recv(s->sock, buf, sizeof(buf), 0);
            if (n <= 0) break;
            DWORD off = 0;
            while (off < (DWORD)n) {
                DWORD w = 0;
                if (!WriteFile(s->pipe, buf + off, n - off, &w, nullptr)) goto done2;
                off += w;
            }
        }
    done2:
        CloseHandle(s->pipe);
        shutdown(s->sock, SD_RECEIVE);
    }
    delete s;
    return 0;
}

struct PipeConnArgs {
    HANDLE pipe;         // connected pipe instance (helper side)
    u_short proxyPort;   // 127.0.0.1:<proxyPort> to forward to
};

// Forward one pipe connection to one TCP connection to the proxy.
static unsigned __stdcall bridgePipeConn(void* argp) {
    PipeConnArgs* c = (PipeConnArgs*)argp;
    HANDLE pipe = c->pipe;
    u_short port = c->proxyPort;
    delete c;

    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        CloseHandle(pipe);
        return 1;
    }
    sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    if (connect(sock, (sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        closesocket(sock);
        CloseHandle(pipe);
        return 1;
    }

    HANDLE pipe2 = INVALID_HANDLE_VALUE;
    DuplicateHandle(GetCurrentProcess(), pipe, GetCurrentProcess(), &pipe2,
                    0, FALSE, DUPLICATE_SAME_ACCESS);

    auto* s1 = new BridgeShuttle{sock, pipe,  true};   // pipe → sock
    auto* s2 = new BridgeShuttle{sock, pipe2, false};  // sock → pipe
    HANDLE t1 = (HANDLE)_beginthreadex(nullptr, 0, bridgeShuttle, s1, 0, nullptr);
    HANDLE t2 = (HANDLE)_beginthreadex(nullptr, 0, bridgeShuttle, s2, 0, nullptr);
    HANDLE ts[2] = {t1, t2};
    WaitForMultipleObjects(2, ts, TRUE, INFINITE);
    CloseHandle(t1);
    CloseHandle(t2);
    closesocket(sock);
    return 0;
}

struct BridgeListenerArgs {
    std::wstring pipeName;
    u_short proxyPort;
    SECURITY_ATTRIBUTES* sa;
    volatile bool* stop;
};

// Accept-loop: create a pipe instance, wait for a client (the in-AC
// forwarder), hand it off to bridgePipeConn, repeat. Each iteration creates
// a fresh instance so multiple concurrent connections work.
static unsigned __stdcall bridgeListener(void* argp) {
    BridgeListenerArgs* la = (BridgeListenerArgs*)argp;

    while (!*la->stop) {
        HANDLE pipe = CreateNamedPipeW(
            la->pipeName.c_str(),
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT |
                PIPE_REJECT_REMOTE_CLIENTS,
            PIPE_UNLIMITED_INSTANCES,
            64 * 1024, 64 * 1024,
            0,      // default timeout for WaitNamedPipe
            la->sa);
        if (pipe == INVALID_HANDLE_VALUE) {
            // Most likely: we lost a race with stop during teardown, or the
            // SA is bad. Either way, nothing useful to do on retry.
            return 1;
        }

        // ConnectNamedPipe blocks until a client connects. On stop, the
        // main thread sets *stop and this thread is abandoned — it will
        // either be waiting here (and die with the process) or mid-forward
        // (and finish that connection). Both are fine.
        BOOL ok = ConnectNamedPipe(pipe, nullptr);
        if (!ok && GetLastError() != ERROR_PIPE_CONNECTED) {
            CloseHandle(pipe);
            continue;
        }
        if (*la->stop) {
            CloseHandle(pipe);
            return 0;
        }

        auto* c = new PipeConnArgs{pipe, la->proxyPort};
        HANDLE t = (HANDLE)_beginthreadex(nullptr, 0, bridgePipeConn, c, 0, nullptr);
        if (t) CloseHandle(t);
        else { CloseHandle(pipe); delete c; }
    }
    return 0;
}

struct PipeBridge {
    std::wstring httpPipeName;
    std::wstring socksPipeName;
    SECURITY_ATTRIBUTES sa = {};
    PSECURITY_DESCRIPTOR sd = nullptr;
    PACL dacl = nullptr;
    BridgeListenerArgs httpArgs = {};
    BridgeListenerArgs socksArgs = {};
    volatile bool stop = false;
};

// Starts pipe-listener threads. Returns false on setup failure. Does NOT
// wait for a client — listeners run in the background until stop is set.
static bool startPipeBridge(PipeBridge* br, PSID containerSid,
                            const std::wstring& profileName,
                            int httpProxyPort, int socksProxyPort) {
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return false;

    if (!buildPipeSA(containerSid, &br->sa, &br->sd, &br->dacl)) return false;

    br->httpPipeName  = L"\\\\.\\pipe\\" + profileName + L"-http";
    br->socksPipeName = L"\\\\.\\pipe\\" + profileName + L"-socks";

    if (httpProxyPort > 0) {
        br->httpArgs.pipeName  = br->httpPipeName;
        br->httpArgs.proxyPort = (u_short)httpProxyPort;
        br->httpArgs.sa        = &br->sa;
        br->httpArgs.stop      = &br->stop;
        HANDLE t = (HANDLE)_beginthreadex(nullptr, 0, bridgeListener,
                                          &br->httpArgs, 0, nullptr);
        if (t) CloseHandle(t);
    }
    if (socksProxyPort > 0) {
        br->socksArgs.pipeName  = br->socksPipeName;
        br->socksArgs.proxyPort = (u_short)socksProxyPort;
        br->socksArgs.sa        = &br->sa;
        br->socksArgs.stop      = &br->stop;
        HANDLE t = (HANDLE)_beginthreadex(nullptr, 0, bridgeListener,
                                          &br->socksArgs, 0, nullptr);
        if (t) CloseHandle(t);
    }
    return true;
}

static void stopPipeBridge(PipeBridge* br) {
    br->stop = true;
    // Listener threads are either blocked in ConnectNamedPipe (will die
    // with the process) or mid-forward (will finish). We don't join; the
    // process is about to exit anyway. Free the SD/DACL we allocated.
    if (br->sd)   LocalFree(br->sd);
    if (br->dacl) LocalFree(br->dacl);
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

// Spawn a process inside the AppContainer. Returns the process handle (or
// NULL on failure); caller waits/closes. If grantInternet is true the
// internetClient capability is attached (used when needsNetworkRestriction
// is false). envOverrides are merged on top of the inherited environment.
static HANDLE spawnInContainerRaw(PSID sid, const std::wstring& cmdline,
                                  const std::vector<std::wstring>& envOverrides,
                                  bool grantInternet) {
    SIZE_T attrSize = 0;
    InitializeProcThreadAttributeList(nullptr, 1, 0, &attrSize);
    auto attrList =
        (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, attrSize);
    if (!attrList) return nullptr;
    if (!InitializeProcThreadAttributeList(attrList, 1, 0, &attrSize)) {
        HeapFree(GetProcessHeap(), 0, attrList);
        return nullptr;
    }

    SECURITY_CAPABILITIES secCaps = {};
    secCaps.AppContainerSid = sid;

    SID_AND_ATTRIBUTES capAttrs[1] = {};
    BYTE capSidBuf[SECURITY_MAX_SID_SIZE];
    if (grantInternet) {
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
        return nullptr;
    }

    std::wstring envBlock = buildEnvBlock(envOverrides);

    STARTUPINFOEXW siex = {};
    siex.StartupInfo.cb = sizeof(siex);
    siex.lpAttributeList = attrList;

    PROCESS_INFORMATION pi = {};
    std::wstring mutableCmd = cmdline;

    BOOL ok = CreateProcessW(
        nullptr, &mutableCmd[0], nullptr, nullptr,
        TRUE,  // inherit handles for stdio
        EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT,
        (LPVOID)envBlock.c_str(), nullptr, &siex.StartupInfo, &pi);

    DWORD err = GetLastError();
    DeleteProcThreadAttributeList(attrList);
    HeapFree(GetProcessHeap(), 0, attrList);

    if (!ok) {
        fwprintf(stderr,
                 L"srt-appcontainer: CreateProcessW failed (error %lu)\n"
                 L"  command: %ls\n",
                 err, cmdline.c_str());
        return nullptr;
    }
    CloseHandle(pi.hThread);
    return pi.hProcess;
}

// Spawn the in-AC forwarder. Returns its process handle (to be killed when
// the user command exits) or NULL if no bridge is needed/available.
static HANDLE spawnForwarder(PSID sid, const Config& cfg, const PipeBridge& br) {
    if (cfg.forwarderPath.empty()) return nullptr;
    if (cfg.httpProxyPort <= 0 && cfg.socksProxyPort <= 0) return nullptr;

    // In-container ports: fixed, mirror Linux's socat bridge.
    const int inHttpPort  = cfg.httpProxyPort  > 0 ? 3128 : 0;
    const int inSocksPort = cfg.socksProxyPort > 0 ? 1080 : 0;

    wchar_t httpPortStr[8], socksPortStr[8];
    _itow_s(inHttpPort,  httpPortStr,  10);
    _itow_s(inSocksPort, socksPortStr, 10);

    std::wstring cmd = L"\"" + cfg.forwarderPath + L"\" " +
                       httpPortStr  + L" " + br.httpPipeName  + L" " +
                       socksPortStr + L" " + br.socksPipeName;

    // Forwarder gets no env overrides (it doesn't care about HTTP_PROXY) and
    // no internetClient (same network restriction as the user command).
    return spawnInContainerRaw(sid, cmd, {}, false);
}

static DWORD spawnUserCommand(PSID sid, const Config& cfg) {
    HANDLE proc = spawnInContainerRaw(sid, cfg.command, cfg.env,
                                      !cfg.needsNetworkRestriction);
    if (!proc) return 127;

    WaitForSingleObject(proc, INFINITE);
    DWORD exitCode = 1;
    GetExitCodeProcess(proc, &exitCode);
    CloseHandle(proc);
    return exitCode;
}

// ---------------------------------------------------------------------------
// State for Ctrl+C handler — we want best-effort ACL cleanup even if the
// user interrupts mid-wait. The child gets the signal too (shared console).
// ---------------------------------------------------------------------------

static volatile PSID g_sid = nullptr;
static const Config* g_cfg = nullptr;
static PipeBridge* g_bridge = nullptr;
static volatile HANDLE g_forwarderProc = nullptr;

static void cleanup() {
    if (!g_sid || !g_cfg) return;
    PSID sid = (PSID)g_sid;
    for (const auto& p : g_cfg->allowWrite) removeAcesForSid(p, sid);
    for (const auto& p : g_cfg->denyRead)   removeAcesForSid(p, sid);
    if (!g_cfg->forwarderPath.empty()) removeAcesForSid(g_cfg->forwarderPath, sid);
    if (g_forwarderProc) {
        TerminateProcess((HANDLE)g_forwarderProc, 0);
        CloseHandle((HANDLE)g_forwarderProc);
        g_forwarderProc = nullptr;
    }
    if (g_bridge) stopPipeBridge(g_bridge);
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

    // 3. Deny access on denyRead paths.
    //
    // AppContainer access checks do not honour DENY ACEs in the normal way.
    // Instead we remove the AppContainer SID's inherited ALLOW from the
    // file's DACL and protect it from re-inheriting.  Without an ALLOW for
    // the AppContainer SID (or ALL APPLICATION PACKAGES), the AppContainer
    // access check fails and access is denied.
    //
    // Cleanup (removeAcesForSid) sets UNPROTECTED, which re-enables
    // inheritance and restores the original DACL.
    for (const auto& p : cfg.denyRead) {
        // Read current DACL, rebuild without our SID, set with PROTECTED.
        PACL oldDacl = nullptr;
        PSECURITY_DESCRIPTOR dsd = nullptr;
        DWORD derr = GetNamedSecurityInfoW(p.c_str(), SE_FILE_OBJECT,
                                           DACL_SECURITY_INFORMATION, nullptr,
                                           nullptr, &oldDacl, nullptr, &dsd);
        if (derr != ERROR_SUCCESS || oldDacl == nullptr) {
            if (dsd) LocalFree(dsd);
            continue;
        }

        ACL_SIZE_INFORMATION dsi = {};
        GetAclInformation(oldDacl, &dsi, sizeof(dsi), AclSizeInformation);

        DWORD newSz = sizeof(ACL);
        std::vector<LPVOID> keep;
        for (DWORD i = 0; i < dsi.AceCount; i++) {
            LPVOID ace = nullptr;
            if (!GetAce(oldDacl, i, &ace)) continue;
            PACE_HEADER hdr = (PACE_HEADER)ace;
            PSID aceSid = (PSID)&((PACCESS_ALLOWED_ACE)ace)->SidStart;
            if (EqualSid(aceSid, sid)) continue;  // skip our SID
            keep.push_back(ace);
            newSz += hdr->AceSize;
        }

        PACL newDacl = (PACL)LocalAlloc(LPTR, newSz);
        if (newDacl) {
            InitializeAcl(newDacl, newSz, ACL_REVISION);
            for (LPVOID ace : keep) {
                PACE_HEADER hdr = (PACE_HEADER)ace;
                AddAce(newDacl, ACL_REVISION, MAXDWORD, ace, hdr->AceSize);
            }

            derr = SetNamedSecurityInfoW(
                (LPWSTR)p.c_str(), SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                nullptr, nullptr, newDacl, nullptr);

            LocalFree(newDacl);

            if (derr == ERROR_SUCCESS) {
                sc.aces.push_back({L'D', p});
            }
        }
        LocalFree(dsd);
    }

    // 4. Start the pipe bridge (only if network restriction active —
    // otherwise we granted internetClient and the child has full network).
    // The bridge is ephemeral: named pipes are kernel objects that vanish
    // when the process exits, so nothing persists for the sweep to undo.
    static PipeBridge bridge;
    if (cfg.needsNetworkRestriction &&
        (cfg.httpProxyPort > 0 || cfg.socksProxyPort > 0)) {
        if (!startPipeBridge(&bridge, sid, cfg.profileName,
                             cfg.httpProxyPort, cfg.socksProxyPort)) {
            fwprintf(stderr,
                     L"srt-appcontainer: failed to start pipe bridge\n");
            cleanup();
            if (sidStr) LocalFree(sidStr);
            FreeSid(sid);
            return 126;
        }
        g_bridge = &bridge;

        // The forwarder binary may live in a user-profile install dir
        // (scoop, npx) that lacks the ALL APPLICATION PACKAGES SID — the
        // AppContainer wouldn't be able to read/execute it. Grant
        // read+execute to our SID. Recorded in the sidecar so sweep undoes it.
        if (!cfg.forwarderPath.empty()) {
            if (addAce(cfg.forwarderPath, sid, GRANT_ACCESS,
                       GENERIC_READ | GENERIC_EXECUTE)) {
                sc.aces.push_back({L'G', cfg.forwarderPath});
            }
        }
    }

    // 5. Write sidecar so a future sweep can undo steps 2-3 if we crash now.
    if (!cfg.sidecarPath.empty()) {
        writeSidecar(cfg.sidecarPath, sc);
    }

    if (sidStr) LocalFree(sidStr);

    // 6. Spawn the in-container forwarder (if bridge is active). It runs
    // alongside the user command and is killed when the command exits.
    if (g_bridge) {
        g_forwarderProc = spawnForwarder(sid, cfg, bridge);
        if (!g_forwarderProc) {
            fwprintf(stderr,
                     L"srt-appcontainer: failed to spawn forwarder; "
                     L"network access via proxy will not work\n");
            // Not fatal — fs sandboxing still works. The user command's
            // HTTP_PROXY connect will just fail.
        }
    }

    // 7. Spawn user command and wait.
    DWORD exitCode = spawnUserCommand(sid, cfg);

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
