// spike-intraloop.cpp — Can two processes inside the SAME AppContainer talk
// over 127.0.0.1?
//
//   cl /MT /EHsc spike-intraloop.cpp /link userenv.lib advapi32.lib ws2_32.lib
//
// Run with no args as a non-admin user. The binary is its own test subject:
// the orchestrator (full integrity) creates an AppContainer, spawns itself
// twice inside it (--server then --client), and reports what happened.
//
// Exit codes:
//   0 = intra-container loopback works → named-pipe bridge is viable
//   1 = server's bind() failed → AppContainer blocks binding itself
//   2 = server bound but client's connect() failed → isolation blocks intra-AC loopback too
//   3 = setup failure
//
// If this exits 0, the Linux socat-bridge architecture ports directly:
//   helper thread: named pipe ↔ proxy TCP
//   in-AC forwarder: 127.0.0.1:3128 ↔ named pipe
//   child: HTTP_PROXY=http://127.0.0.1:3128

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <userenv.h>
#include <sddl.h>
#include <cstdio>
#include <string>

// ---------------------------------------------------------------------------
// Worker modes: --server / --client
// These run INSIDE the AppContainer.
// ---------------------------------------------------------------------------

static int runServer(u_short port) {
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        fprintf(stderr, "[server] WSAStartup: %d\n", WSAGetLastError());
        return 3;
    }

    SOCKET ls = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (ls == INVALID_SOCKET) {
        fprintf(stderr, "[server] socket: %d\n", WSAGetLastError());
        return 1;
    }

    sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);

    if (bind(ls, (sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        int e = WSAGetLastError();
        fprintf(stderr, "[server] bind(127.0.0.1:%u) failed: %d %s\n", port, e,
                e == WSAEACCES ? "(WSAEACCES — AppContainer blocks bind)" : "");
        closesocket(ls);
        return 1;
    }
    fprintf(stderr, "[server] bound 127.0.0.1:%u\n", port);

    if (listen(ls, 1) == SOCKET_ERROR) {
        fprintf(stderr, "[server] listen: %d\n", WSAGetLastError());
        closesocket(ls);
        return 1;
    }
    fprintf(stderr, "[server] listening\n");

    // Accept with timeout so a failed client doesn't hang us forever.
    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(ls, &rfds);
    timeval tv = {5, 0};
    if (select(0, &rfds, nullptr, nullptr, &tv) <= 0) {
        fprintf(stderr, "[server] accept timeout — no client connected\n");
        closesocket(ls);
        return 2;
    }

    SOCKET cs = accept(ls, nullptr, nullptr);
    if (cs == INVALID_SOCKET) {
        fprintf(stderr, "[server] accept: %d\n", WSAGetLastError());
        closesocket(ls);
        return 2;
    }
    fprintf(stderr, "[server] client connected\n");
    send(cs, "pong", 4, 0);
    closesocket(cs);
    closesocket(ls);
    return 0;
}

static int runClient(u_short port) {
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return 3;

    // Small retry loop in case we race the server's listen().
    for (int attempt = 0; attempt < 10; attempt++) {
        SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (s == INVALID_SOCKET) {
            fprintf(stderr, "[client] socket: %d\n", WSAGetLastError());
            return 2;
        }

        sockaddr_in addr = {};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);

        if (connect(s, (sockaddr*)&addr, sizeof(addr)) == 0) {
            char buf[8] = {};
            int n = recv(s, buf, 4, 0);
            closesocket(s);
            fprintf(stderr, "[client] received: %.*s\n", n, buf);
            return (n == 4 && memcmp(buf, "pong", 4) == 0) ? 0 : 2;
        }

        int e = WSAGetLastError();
        closesocket(s);
        if (e == WSAECONNREFUSED) {
            // Server not up yet — retry.
            Sleep(100);
            continue;
        }
        fprintf(stderr, "[client] connect: %d %s\n", e,
                e == WSAEACCES ? "(WSAEACCES — AppContainer blocks connect)" : "");
        return 2;
    }
    fprintf(stderr, "[client] gave up after retries\n");
    return 2;
}

// ---------------------------------------------------------------------------
// Orchestrator: create AppContainer, spawn self twice inside it.
// ---------------------------------------------------------------------------

static HANDLE spawnInContainer(PSID sid, const wchar_t* args) {
    SIZE_T sz = 0;
    InitializeProcThreadAttributeList(nullptr, 1, 0, &sz);
    auto attrs = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, sz);
    InitializeProcThreadAttributeList(attrs, 1, 0, &sz);

    SECURITY_CAPABILITIES caps = {};
    caps.AppContainerSid = sid;
    // Zero capabilities — same as the real helper uses for network restriction.
    UpdateProcThreadAttribute(attrs, 0,
                              PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
                              &caps, sizeof(caps), nullptr, nullptr);

    wchar_t exe[MAX_PATH];
    GetModuleFileNameW(nullptr, exe, MAX_PATH);

    std::wstring cmdline = L"\"";
    cmdline += exe;
    cmdline += L"\" ";
    cmdline += args;

    STARTUPINFOEXW si = {};
    si.StartupInfo.cb = sizeof(si);
    si.lpAttributeList = attrs;
    PROCESS_INFORMATION pi = {};

    BOOL ok = CreateProcessW(nullptr, &cmdline[0], nullptr, nullptr, TRUE,
                             EXTENDED_STARTUPINFO_PRESENT, nullptr, nullptr,
                             &si.StartupInfo, &pi);
    DWORD err = GetLastError();
    DeleteProcThreadAttributeList(attrs);
    HeapFree(GetProcessHeap(), 0, attrs);

    if (!ok) {
        fprintf(stderr, "[orch] CreateProcessW(%ls): %lu\n", args, err);
        return nullptr;
    }
    CloseHandle(pi.hThread);
    return pi.hProcess;
}

int wmain(int argc, wchar_t** argv) {
    // Worker dispatch.
    if (argc == 3 && wcscmp(argv[1], L"--server") == 0)
        return runServer((u_short)_wtoi(argv[2]));
    if (argc == 3 && wcscmp(argv[1], L"--client") == 0)
        return runClient((u_short)_wtoi(argv[2]));

    // Orchestrator.
    printf("=== AppContainer intra-container loopback spike ===\n\n");

    PSID sid = nullptr;
    const wchar_t* profile = L"srt-spike-intraloop";
    HRESULT hr = CreateAppContainerProfile(profile, profile, L"spike",
                                           nullptr, 0, &sid);
    if (hr == HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS))
        DeriveAppContainerSidFromAppContainerName(profile, &sid);
    else if (FAILED(hr)) {
        fprintf(stderr, "CreateAppContainerProfile: 0x%08lx\n", hr);
        return 3;
    }

    wchar_t* sidStr = nullptr;
    ConvertSidToStringSidW(sid, &sidStr);
    wprintf(L"AppContainer SID: %ls\n\n", sidStr);
    LocalFree(sidStr);

    // Arbitrary port unlikely to be in use.
    const wchar_t* port = L"58231";

    printf("Spawning server inside AppContainer...\n");
    std::wstring serverArgs = L"--server "; serverArgs += port;
    HANDLE hServer = spawnInContainer(sid, serverArgs.c_str());
    if (!hServer) { DeleteAppContainerProfile(profile); return 3; }

    Sleep(300);  // let server reach listen()

    printf("Spawning client inside AppContainer...\n");
    std::wstring clientArgs = L"--client "; clientArgs += port;
    HANDLE hClient = spawnInContainer(sid, clientArgs.c_str());
    if (!hClient) {
        TerminateProcess(hServer, 3);
        CloseHandle(hServer);
        DeleteAppContainerProfile(profile);
        return 3;
    }

    WaitForSingleObject(hClient, 10000);
    WaitForSingleObject(hServer, 10000);

    DWORD serverExit = 99, clientExit = 99;
    GetExitCodeProcess(hServer, &serverExit);
    GetExitCodeProcess(hClient, &clientExit);
    CloseHandle(hServer);
    CloseHandle(hClient);
    DeleteAppContainerProfile(profile);

    printf("\nserver exit: %lu   client exit: %lu\n\n", serverExit, clientExit);

    if (serverExit == 1) {
        printf("=> bind() REFUSED inside AppContainer.\n");
        printf("   The in-container forwarder can't listen. Named-pipe bridge is dead.\n");
        printf("   Remaining option: fixed profile + one-time admin CheckNetIsolation setup.\n");
        return 1;
    }
    if (serverExit == 0 && clientExit == 0) {
        printf("=> Intra-container loopback WORKS.\n");
        printf("   Named-pipe bridge is viable. Architecture:\n");
        printf("     helper thread:  \\\\.\\pipe\\srt-<id> <-> 127.0.0.1:<proxyPort>\n");
        printf("     in-AC forwarder: 127.0.0.1:3128 <-> \\\\.\\pipe\\srt-<id>\n");
        printf("     child:           HTTP_PROXY=http://127.0.0.1:3128\n");
        return 0;
    }
    printf("=> Server bound but client connect failed.\n");
    printf("   AppContainer isolation blocks loopback even within the same container.\n");
    printf("   Remaining option: fixed profile + one-time admin CheckNetIsolation setup.\n");
    return 2;
}
