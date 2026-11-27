/* Kernel COM investigation (topic#51 msg#2114). A DLL that, when loaded,
 * records which process loaded it and with what token, then refuses to
 * load (DllMain returns FALSE), so nothing else of it ever runs and the
 * loading call just fails. Disposable Windows CI runners only. */
#include <windows.h>
#include <stdio.h>

static void token_facts(DWORD *integrity, DWORD *elevated)
{
    HANDLE token;
    BYTE label[256];
    TOKEN_ELEVATION elevation;
    DWORD size;
    *integrity = 0;
    *elevated = 0;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token))
        return;
    if (GetTokenInformation(token, TokenIntegrityLevel, label, sizeof label, &size)) {
        PSID sid = ((TOKEN_MANDATORY_LABEL *)label)->Label.Sid;
        *integrity = *GetSidSubAuthority(sid, *GetSidSubAuthorityCount(sid) - 1);
    }
    if (GetTokenInformation(token, TokenElevation, &elevation, sizeof elevation, &size))
        *elevated = elevation.TokenIsElevated;
    CloseHandle(token);
}

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved)
{
    (void)instance;
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        wchar_t image[MAX_PATH] = L"?";
        wchar_t path[MAX_PATH];
        DWORD integrity, elevated;
        FILE *out;
        GetModuleFileNameW(NULL, image, MAX_PATH);
        token_facts(&integrity, &elevated);
        swprintf(path, MAX_PATH, L"C:\\etd-kcom\\hit-%lu.txt", GetCurrentProcessId());
        if (_wfopen_s(&out, path, L"w") == 0 && out) {
            fwprintf(out, L"image=%ls\nintegrity=0x%lx\nelevated=%lu\n", image, integrity, elevated);
            fclose(out);
        }
        return FALSE;
    }
    return TRUE;
}
