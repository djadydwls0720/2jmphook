// dllmain.cpp : DLL 애플리케이션의 진입점을 정의합니다.
#include "pch.h"
#include "windows.h"
#include "stdio.h"
#include <stdint.h>

#pragma pack(push,1)
BOOL WINAPI Hook(LPVOID lptr);
BOOL WINAPI UnHook(LPVOID lptr);

DWORD protect;
LPVOID lptr;
DWORD64 orgcode;

typedef BOOL(WINAPI* PFWRITEFILE)(
    HANDLE       hFile,
    LPCVOID      lpBuffer,
    DWORD        nNumberOfBytesToWrite,
    LPDWORD      lpNumberOfBytesWritten,
    LPOVERLAPPED lpOverlapped
    );

struct shell_code
{
    BYTE code;
    DWORD64 point;
};

#pragma pack(pop)



BOOL WINAPI fakeWriteFile(_In_ HANDLE hFile,
    _In_reads_bytes_opt_(nNumberOfBytesToWrite) LPCVOID lpBuffer,
    _In_ DWORD nNumberOfBytesToWrite,
    _Out_opt_ LPDWORD lpNumberOfBytesWritten,
    _Inout_opt_ LPOVERLAPPED lpOverlapped) {
    FARPROC func = GetProcAddress(GetModuleHandleA("kernel32.dll"), "WriteFile");
    func = (FARPROC)((DWORD64)func + 5);

    MessageBoxA(NULL, "ok", "ok", NULL);
    ((PFWRITEFILE)(func))(hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped);

    return TRUE;
}

BOOL WINAPI Hook(LPVOID lptr) {
    shell_code code;
    char m[1000];

    code.code = 0xE9;
    code.point = (DWORD64)((char*)fakeWriteFile - (char*)lptr - sizeof(shell_code) + 4);


    VirtualProtect(lptr, sizeof(shell_code) + sizeof(DWORD64), PAGE_EXECUTE_READWRITE, &protect);

    memcpy_s(&orgcode, sizeof(DWORD64), lptr, sizeof(DWORD64));
    memcpy_s(lptr, sizeof(shell_code), &code, sizeof(shell_code));
    orgcode -= 0x50000;

    memcpy_s((LPVOID)((DWORD64)lptr + sizeof(shell_code) - 4), sizeof(DWORD64), &orgcode, sizeof(DWORD64));


    VirtualProtect(lptr, sizeof(shell_code) + sizeof(DWORD64), protect, NULL);
    return TRUE;

}

BOOL WINAPI UnHook(LPVOID lptr) {
    //shell_code code;
    char m[1000];

    DWORD64 code = 0xCCCCCCCCCCCCCC;


    VirtualProtect(lptr, sizeof(orgcode) + sizeof(DWORD64), PAGE_EXECUTE_READWRITE, &protect);
    orgcode += 0x50000;

    memcpy_s(lptr, sizeof(orgcode), &orgcode, sizeof(orgcode));
    //0x7FFE8E5321E8
    //0x00007FFE74E41100

    memcpy_s((LPVOID)((DWORD64)lptr + sizeof(orgcode)), sizeof(DWORD64), &code, sizeof(DWORD64));


    VirtualProtect(lptr, sizeof(orgcode) + sizeof(DWORD64), protect, NULL);
    return TRUE;

}

BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        lptr = GetProcAddress(GetModuleHandleA("kernel32.dll"), "WriteFile");
        Hook(lptr);

        break;

    case DLL_PROCESS_DETACH:
        UnHook(lptr);
        break;
    }
    return TRUE;
}