#include <Windows.h>
#include <TlHelp32.h>
#include <iostream>

DWORD GetTargetProcessIdFromProcname(const std::string& procName)
{
    PROCESSENTRY32 pe;
    HANDLE thSnapshot;
    BOOL retval, ProcFound = false;

    thSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (thSnapshot == INVALID_HANDLE_VALUE)
    {
        MessageBox(NULL, "Error: unable to create toolhelp snapshot", "Loader", NULL);
        return false;
    }

    pe.dwSize = sizeof(PROCESSENTRY32);

    retval = Process32First(thSnapshot, &pe);

    while (retval)
    {
        if (procName == pe.szExeFile)
        {
            ProcFound = true;
            break;
        }

        retval = Process32Next(thSnapshot, &pe);
        pe.dwSize = sizeof(PROCESSENTRY32);
    }

    return pe.th32ProcessID;
}

BOOL InjectDLL(const DWORD& processId, const std::string& dllName);

/**
 * If it is a 64-bit process, compile and run in 64bit:
 * https://stackoverflow.com/questions/9456228/createremotethread-returning-error-access-denied-windows-7-dll-injection
 ***/
int main()
{
    const std::string dllName{ "D:\\repos\\Dll Injector\\x64\\Debug\\DummyDll.dll" };
    const DWORD processId{ GetTargetProcessIdFromProcname("notepad.exe") };

    InjectDLL(processId, dllName);

    return 0;
}

BOOL InjectDLL(const DWORD& processId, const std::string& dllName)
{
    if (!processId)
        return false;

    const HANDLE hProc = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, processId);

    if (!hProc)
    {
        std::cout << "OpenProcess() failed: " << GetLastError() << std::endl;
        return false;
    }

    const LPVOID loadLibrary = static_cast<LPVOID>(GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA"));
    if (!loadLibrary)
    {
        std::cout << "GetProcAddress() failed: " << GetLastError() << std::endl;
        return false;
    }

    const LPVOID remoteStringAllocatedMem = static_cast<LPVOID>(VirtualAllocEx(hProc, NULL, dllName.length(), MEM_RESERVE | MEM_COMMIT,
        PAGE_READWRITE));
    if (!remoteStringAllocatedMem)
    {
        std::cout << "VirtualAllocEx() failed: " << GetLastError() << std::endl;
        return false;
    }

    if (!WriteProcessMemory(hProc, static_cast<LPVOID>(remoteStringAllocatedMem), dllName.c_str(), dllName.length(), NULL))
    {
        std::cout << "WriteProcessMemory() failed: " << GetLastError() << std::endl;
        return false;
    }

    HANDLE hRemoteThread = CreateRemoteThread(hProc, NULL, NULL, static_cast<LPTHREAD_START_ROUTINE>(loadLibrary), static_cast<LPVOID>(remoteStringAllocatedMem), NULL, NULL);
    if (!hRemoteThread)
    {
        std::cout << "CreateRemoteThread() failed: " << GetLastError() << std::endl;
        return false;
    }

    CloseHandle(hProc);
    CloseHandle(hRemoteThread);

    return true;
}