// srt-pipe-forwarder.exe — in-container TCP→named-pipe forwarder.
//
// Runs INSIDE the AppContainer. Listens on 127.0.0.1 and forwards each
// accepted connection to a named pipe. The helper (srt-appcontainer.exe,
// running outside the AppContainer at full integrity) listens on the other
// end of that pipe and forwards to the srt allowlist proxy.
//
// This is the in-container half of a bridge that crosses the AppContainer
// network isolation boundary using filesystem-object security (pipe DACLs)
// instead of the admin-only NetworkIsolationSetAppContainerConfig.
//
//   child: HTTP_PROXY=http://127.0.0.1:<httpPort>
//     → this process (same AppContainer, intra-AC loopback works)
//       → \\.\pipe\srt-<id>-http (DACL grants the AppContainer SID)
//         → helper thread (full integrity) → 127.0.0.1:<srt proxy port>
//
// Usage: srt-pipe-forwarder.exe <httpPort> <httpPipeName> <socksPort> <socksPipeName>
//   Port of 0 disables that half.
//
// Build: cl /O2 /MT /EHsc /W4 /DUNICODE /D_UNICODE srt-pipe-forwarder.cpp /link ws2_32.lib

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <cstdio>
#include <cstdlib>
#include <process.h>
#include <string>

struct Shuttle {
    SOCKET sock;
    HANDLE pipe;       // duplicate handle; each shuttle owns its copy
    bool sockToPipe;
    HANDLE ovlEvent;   // per-shuttle event for OVERLAPPED pipe I/O
};

// Synchronous-style wrappers over OVERLAPPED pipe I/O. The pipe is
// FILE_FLAG_OVERLAPPED so concurrent ReadFile + WriteFile can be in
// flight on the same instance (one per shuttle event).
static bool ovlReadPipe(HANDLE pipe, HANDLE ev, char* buf, DWORD cap, DWORD* n) {
    OVERLAPPED ovl = {}; ovl.hEvent = ev;
    BOOL ok = ReadFile(pipe, buf, cap, nullptr, &ovl);
    if (!ok && GetLastError() != ERROR_IO_PENDING) return false;
    return GetOverlappedResult(pipe, &ovl, n, TRUE) && *n > 0;
}
static bool ovlWritePipe(HANDLE pipe, HANDLE ev, const char* buf, DWORD len, DWORD* w) {
    OVERLAPPED ovl = {}; ovl.hEvent = ev;
    BOOL ok = WriteFile(pipe, buf, len, nullptr, &ovl);
    if (!ok && GetLastError() != ERROR_IO_PENDING) return false;
    return GetOverlappedResult(pipe, &ovl, w, TRUE);
}

// One-way copy. On EOF/error, closes its own pipe handle (dup) and shuts
// down the socket in its direction so the sibling's blocking call returns.
static unsigned __stdcall shuttle(void* argp) {
    Shuttle* s = (Shuttle*)argp;
    char buf[16 * 1024];

    if (s->sockToPipe) {
        for (;;) {
            int n = recv(s->sock, buf, sizeof(buf), 0);
            if (n <= 0) break;
            DWORD off = 0;
            while (off < (DWORD)n) {
                DWORD w = 0;
                if (!ovlWritePipe(s->pipe, s->ovlEvent, buf + off, n - off, &w))
                    goto done_s2p;
                off += w;
            }
        }
    done_s2p:
        // Tell helper: no more data coming from client. CloseHandle on our
        // dup signals EOF on the pipe once the sibling also closes its dup.
        CloseHandle(s->pipe);
        // Tell client: no more data coming from us (sibling's send() will
        // still work until it hits its own EOF).
        shutdown(s->sock, SD_RECEIVE);
    } else {
        for (;;) {
            DWORD n = 0;
            if (!ovlReadPipe(s->pipe, s->ovlEvent, buf, sizeof(buf), &n))
                break;
            int off = 0;
            while (off < (int)n) {
                int w = send(s->sock, buf + off, (int)n - off, 0);
                if (w <= 0) goto done_p2s;
                off += w;
            }
        }
    done_p2s:
        CloseHandle(s->pipe);
        shutdown(s->sock, SD_SEND);
    }

    CloseHandle(s->ovlEvent);
    delete s;
    return 0;
}

struct ConnArgs {
    SOCKET client;
    const wchar_t* pipeName;
};

static unsigned __stdcall handleConn(void* argp) {
    ConnArgs* c = (ConnArgs*)argp;
    SOCKET sock = c->client;
    const wchar_t* pipeName = c->pipeName;
    delete c;

    HANDLE pipe = INVALID_HANDLE_VALUE;
    for (int attempt = 0; attempt < 50; attempt++) {
        pipe = CreateFileW(pipeName, GENERIC_READ | GENERIC_WRITE, 0,
                           nullptr, OPEN_EXISTING, FILE_FLAG_OVERLAPPED,
                           nullptr);
        if (pipe != INVALID_HANDLE_VALUE) break;
        if (GetLastError() != ERROR_PIPE_BUSY) break;
        WaitNamedPipeW(pipeName, 2000);
    }
    if (pipe == INVALID_HANDLE_VALUE) {
        closesocket(sock);
        return 1;
    }

    // Duplicate the pipe handle so each shuttle can close its own copy
    // without racing a use-after-close on a shared HANDLE value.
    HANDLE pipe2 = INVALID_HANDLE_VALUE;
    if (!DuplicateHandle(GetCurrentProcess(), pipe, GetCurrentProcess(),
                         &pipe2, 0, FALSE, DUPLICATE_SAME_ACCESS)) {
        CloseHandle(pipe);
        closesocket(sock);
        return 1;
    }

    HANDLE ev1 = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    HANDLE ev2 = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    auto* s1 = new Shuttle{sock, pipe,  true,  ev1};  // sock → pipe
    auto* s2 = new Shuttle{sock, pipe2, false, ev2};  // pipe → sock

    HANDLE t1 = (HANDLE)_beginthreadex(nullptr, 0, shuttle, s1, 0, nullptr);
    HANDLE t2 = (HANDLE)_beginthreadex(nullptr, 0, shuttle, s2, 0, nullptr);

    HANDLE ts[2] = {t1, t2};
    WaitForMultipleObjects(2, ts, TRUE, INFINITE);
    CloseHandle(t1);
    CloseHandle(t2);

    // Both shuttles closed their pipe dups and shut down their socket
    // direction. Final close of the socket.
    closesocket(sock);
    return 0;
}

struct ListenerArgs {
    u_short port;
    std::wstring pipeName;
};

static unsigned __stdcall listenerThread(void* argp) {
    ListenerArgs* la = (ListenerArgs*)argp;

    SOCKET ls = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (ls == INVALID_SOCKET) {
        fprintf(stderr, "srt-pipe-forwarder: socket: %d\n", WSAGetLastError());
        return 1;
    }

    sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(la->port);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);

    if (bind(ls, (sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR ||
        listen(ls, SOMAXCONN) == SOCKET_ERROR) {
        fprintf(stderr, "srt-pipe-forwarder: bind/listen %u: %d\n",
                la->port, WSAGetLastError());
        closesocket(ls);
        return 1;
    }

    for (;;) {
        SOCKET client = accept(ls, nullptr, nullptr);
        if (client == INVALID_SOCKET) {
            if (WSAGetLastError() == WSAEINTR) break;
            continue;
        }
        auto* ca = new ConnArgs{client, la->pipeName.c_str()};
        HANDLE t = (HANDLE)_beginthreadex(nullptr, 0, handleConn, ca, 0, nullptr);
        if (t) CloseHandle(t);
        else { closesocket(client); delete ca; }
    }

    closesocket(ls);
    return 0;
}

int wmain(int argc, wchar_t** argv) {
    if (argc != 5) {
        fwprintf(stderr,
                 L"usage: srt-pipe-forwarder.exe <httpPort> <httpPipe> <socksPort> <socksPipe>\n");
        return 2;
    }

    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return 1;

    static ListenerArgs httpArgs, socksArgs;
    httpArgs.port     = (u_short)_wtoi(argv[1]);
    httpArgs.pipeName = argv[2];
    socksArgs.port     = (u_short)_wtoi(argv[3]);
    socksArgs.pipeName = argv[4];

    HANDLE threads[2] = {};
    int n = 0;
    if (httpArgs.port > 0)
        threads[n++] = (HANDLE)_beginthreadex(nullptr, 0, listenerThread, &httpArgs, 0, nullptr);
    if (socksArgs.port > 0)
        threads[n++] = (HANDLE)_beginthreadex(nullptr, 0, listenerThread, &socksArgs, 0, nullptr);

    if (n == 0) Sleep(INFINITE);

    // Listeners only exit on bind/listen error. Normal termination is the
    // helper killing us when the user command exits.
    WaitForMultipleObjects(n, threads, FALSE, INFINITE);
    WSACleanup();
    return 1;
}
