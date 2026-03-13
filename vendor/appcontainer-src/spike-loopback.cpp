// spike-loopback.cpp — Does NetworkIsolationSetAppContainerConfig need admin?
//
//   cl /MT /EHsc spike-loopback.cpp /link userenv.lib advapi32.lib
//
// Run as a NON-admin user. Exit codes:
//   0  = loopback set + verified via round-trip read (works without admin)
//   5  = ERROR_ACCESS_DENIED (needs admin — fall back to named-pipe bridge)
//   N  = any other error
//
// This is a throwaway diagnostic, not shipped code.

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <userenv.h>
#include <sddl.h>
#include <cstdio>
#include <vector>

typedef DWORD(WINAPI* PFN_Get)(DWORD*, PSID_AND_ATTRIBUTES*);
typedef DWORD(WINAPI* PFN_Set)(DWORD, PSID_AND_ATTRIBUTES);

int wmain() {
    // 1. Create a throwaway AppContainer profile so we have a real SID.
    PSID sid = nullptr;
    HRESULT hr = CreateAppContainerProfile(
        L"srt-spike-loopback", L"srt-spike-loopback", L"spike", nullptr, 0, &sid);
    if (hr == HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS))
        DeriveAppContainerSidFromAppContainerName(L"srt-spike-loopback", &sid);
    else if (FAILED(hr)) {
        fprintf(stderr, "CreateAppContainerProfile: hr=0x%08lx\n", hr);
        return (int)hr;
    }

    wchar_t* sidStr = nullptr;
    ConvertSidToStringSidW(sid, &sidStr);
    wprintf(L"Profile SID: %ls\n", sidStr);

    // 2. Load the NetworkIsolation API.
    HMODULE fw = LoadLibraryW(L"Firewallapi.dll");
    auto get = (PFN_Get)GetProcAddress(fw, "NetworkIsolationGetAppContainerConfig");
    auto set = (PFN_Set)GetProcAddress(fw, "NetworkIsolationSetAppContainerConfig");
    if (!get || !set) {
        fprintf(stderr, "NetworkIsolation APIs not exported\n");
        DeleteAppContainerProfile(L"srt-spike-loopback");
        return 1;
    }

    // 3. Read current exemption list, append our SID, write back.
    DWORD count = 0;
    PSID_AND_ATTRIBUTES existing = nullptr;
    DWORD gerr = get(&count, &existing);
    printf("Get before set: err=%lu count=%lu\n", gerr, count);

    std::vector<SID_AND_ATTRIBUTES> merged;
    for (DWORD i = 0; i < count; i++) merged.push_back(existing[i]);
    merged.push_back({sid, 0});

    DWORD serr = set((DWORD)merged.size(), merged.data());
    printf("Set: err=%lu\n", serr);

    if (serr == ERROR_ACCESS_DENIED) {
        fprintf(stderr,
                "\n==> ERROR_ACCESS_DENIED: needs admin.\n"
                "    Fallback options:\n"
                "      a) one-time admin setup: CheckNetIsolation LoopbackExempt -a -p=%ls\n"
                "      b) named-pipe bridge instead of TCP loopback (like Linux's socat bridge)\n",
                sidStr);
        DeleteAppContainerProfile(L"srt-spike-loopback");
        return 5;
    }
    if (serr != ERROR_SUCCESS) {
        DeleteAppContainerProfile(L"srt-spike-loopback");
        return (int)serr;
    }

    // 4. Round-trip: re-read and confirm our SID is actually in the list.
    //    A silent-success API that doesn't persist would be worse than a
    //    clean ACCESS_DENIED.
    DWORD count2 = 0;
    PSID_AND_ATTRIBUTES check = nullptr;
    get(&count2, &check);
    bool found = false;
    for (DWORD i = 0; i < count2; i++) {
        if (EqualSid(check[i].Sid, sid)) { found = true; break; }
    }
    printf("Get after set: count=%lu, our SID present=%s\n", count2, found ? "yes" : "no");

    // 5. Restore original list and clean up.
    set(count, existing);
    DeleteAppContainerProfile(L"srt-spike-loopback");
    LocalFree(sidStr);

    if (!found) {
        fprintf(stderr, "\n==> Set returned success but SID not in list — API is lying.\n");
        return 2;
    }
    printf("\n==> Works without admin.\n");
    return 0;
}
