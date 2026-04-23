#include <windows.h>
#include <psapi.h>   
#include <vector>
#include <iostream>
#include <cstdint>  

// sig scanner
uintptr_t FindSignature(const char* moduleName, const char* pattern) {
    HMODULE hModule = GetModuleHandleA(moduleName);
    if (!hModule) return 0;

    MODULEINFO modInfo;
    if (!GetModuleInformation(GetCurrentProcess(), hModule, &modInfo, sizeof(MODULEINFO)))
        return 0;

    uintptr_t start = (uintptr_t)modInfo.lpBaseOfDll;
    uintptr_t end = start + modInfo.SizeOfImage;

    const char* pat = pattern;
    uintptr_t firstMatch = 0;

    for (uintptr_t pCur = start; pCur < end; pCur++) {
        if (!*pat) return firstMatch;
        if (*(BYTE*)pat == '\?' || *(BYTE*)pCur == strtoul(pat, NULL, 16)) {
            if (!firstMatch) firstMatch = pCur;
            if (!pat[2]) return firstMatch;
            if (*(WORD*)pat == 0x3F3F || *(BYTE*)pat != '\?') pat += 3; 
            else pat += 2;
        } else {
            pat = pattern;
            firstMatch = 0;
        }
    }
    return 0;
}

// thank you so much amalgam linux for this part
void RunBypass() {
    while (!GetModuleHandleA("engine.dll")) {
        Sleep(500);
    }

    uintptr_t addr = FindSignature("engine.dll", "40 88 35 ? ? ? ? 40 84 FF");

    if (addr) {
        int32_t relativeOffset = *(int32_t*)(addr + 3);
        uintptr_t finalAddr = addr + 7 + relativeOffset;

        DWORD oldProtect;
        VirtualProtect((LPVOID)finalAddr, sizeof(bool), PAGE_EXECUTE_READWRITE, &oldProtect);
        *(bool*)finalAddr = true;
        VirtualProtect((LPVOID)finalAddr, sizeof(bool), oldProtect, &oldProtect);
    }
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID reserved) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        CreateThread(0, 0, (LPTHREAD_START_ROUTINE)RunBypass, 0, 0, 0);
    }
    return TRUE;
}
