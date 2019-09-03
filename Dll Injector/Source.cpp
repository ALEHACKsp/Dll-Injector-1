#include <Windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <iostream>
#include <string>
#include "XorCompileTime.h"

DWORD findPidByName(const char* pname)
{
    HANDLE h;
    PROCESSENTRY32 procSnapshot;
    h = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    procSnapshot.dwSize = sizeof(PROCESSENTRY32);

    do
    {
        if (!_stricmp(procSnapshot.szExeFile, pname))
        {
            DWORD pid = procSnapshot.th32ProcessID;
            CloseHandle(h);
#ifdef _DEBUG
            printf(XorStr("[+] found: %ld\n"), pid);
#endif
            return pid;
        }
    } while (Process32Next(h, &procSnapshot));

    CloseHandle(h);
    return 0;
}

typedef DWORD(WINAPI* pRtlCreateUserThread)(
    IN HANDLE 					ProcessHandle,
    IN PSECURITY_DESCRIPTOR 	SecurityDescriptor,
    IN BOOL 					CreateSuspended,
    IN ULONG					StackZeroBits,
    IN OUT PULONG				StackReserved,
    IN OUT PULONG				StackCommit,
    IN LPVOID					StartAddress,
    IN LPVOID					StartParameter,
    OUT HANDLE 					ThreadHandle,
    OUT LPVOID					ClientID
    );

DWORD RtlCreateUserThread(LPCSTR pszLibFile, DWORD dwProcessId)
{
    pRtlCreateUserThread RtlCreateUserThread = NULL;
    HANDLE  hRemoteThread = NULL;

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessId);
    if (hProcess == NULL)
    {
        printf(XorStr("[-] Error: Could not open process for PID (%d).\n"), dwProcessId);
        exit(1);
    }

    LPVOID LoadLibraryAddress = (LPVOID)GetProcAddress(GetModuleHandle(XorStr("kernel32.dll")), XorStr("LoadLibraryA"));
    if (LoadLibraryAddress == NULL)
    {
        printf(XorStr("[-] Error: Could not find LoadLibraryA function inside kernel32.dll library.\n"));
        exit(1);
    }

    RtlCreateUserThread = (pRtlCreateUserThread)GetProcAddress(GetModuleHandle(XorStr("ntdll.dll")), XorStr("RtlCreateUserThread"));
    if (RtlCreateUserThread == NULL)
    {
        //wprintf(L"[-] Error: Could not find RtlCreateUserThread function inside ntdll.dll library.\n");
        exit(1);
    }

#ifdef _DEBUG
    printf(XorStr("[+] Found at 0x%08x\n"), (UINT)RtlCreateUserThread);
    printf(XorStr("[+] Found at 0x%08x\n"), (UINT)LoadLibraryAddress);
#endif

    DWORD dwSize = (strlen(pszLibFile) + 1) * sizeof(char);

    LPVOID lpBaseAddress = VirtualAllocEx(hProcess, NULL, dwSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (lpBaseAddress == NULL)
    {
        printf(XorStr("[-] Error: Could not allocate memory inside PID (%d).\n"), dwProcessId);
        exit(1);
    }

    BOOL bStatus = WriteProcessMemory(hProcess, lpBaseAddress, pszLibFile, dwSize, NULL);
    if (bStatus == 0)
    {
        printf(XorStr("[-] Error: Could not write any bytes into the PID (%d) address space.\n"), dwProcessId);
        return(1);
    }

    bStatus = (BOOL)RtlCreateUserThread(
        hProcess,
        NULL,
        0,
        0,
        0,
        0,
        LoadLibraryAddress,
        lpBaseAddress,
        &hRemoteThread,
        NULL);
    if (bStatus < 0)
    {
        printf(XorStr("[-] Error: RtlCreateUserThread failed\n"));
        return(1);
    }
    else
    {
        printf(XorStr("[+] Remote thread has been created successfully ...\n"));
        WaitForSingleObject(hRemoteThread, INFINITE);

        CloseHandle(hProcess);
        VirtualFreeEx(hProcess, lpBaseAddress, dwSize, MEM_RELEASE);
        return(0);
    }

    return(0);
}

std::string ExePath()
{
    char buffer[MAX_PATH];
    GetModuleFileName(NULL, buffer, MAX_PATH);
    std::string::size_type pos = std::string(buffer).find_last_of("\\/");
    return std::string(buffer).substr(0, pos);
}

int main()
{
    const char* name = XorStr("Process.exe");

    DWORD pId = findPidByName(name);
    LPCSTR location = XorStr("C:\\library.dll");

    RtlCreateUserThread(location, pId);
}