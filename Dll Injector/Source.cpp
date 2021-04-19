#include <Windows.h>
#include <TlHelp32.h>
#include <iostream>

DWORD GetTargetProcessIdFromProcessName(const std::string& procName);
BOOL InjectDllLoadLibrary(const DWORD& processId, const std::string& dllName);

using std::cout;
using std::endl;

/**
 * If it is a 64-bit process, compile and run in 64bit:
 * https://stackoverflow.com/questions/9456228/createremotethread-returning-error-access-denied-windows-7-dll-injection
 ***/
int main()
{
    const std::string dllFullPath{ "D:\\repos\\Dll Injector\\x64\\Debug\\DummyDll.dll" };
    const DWORD processId{ GetTargetProcessIdFromProcessName("notepad.exe") };

    (void)InjectDllLoadLibrary(processId, dllFullPath);

    return 0;
}

BOOL InjectDllLoadLibrary(const DWORD& processId, const std::string& dllName)
{
    if (!processId)
        return false;

    const HANDLE hProc = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, processId);

    if (!hProc)
    {
        cout << "OpenProcess() failed: " << GetLastError() << endl;
        return false;
    }

    const LPVOID loadLibrary{ static_cast<LPVOID>(GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA")) };
    if (!loadLibrary)
    {
        cout << "GetProcAddress() failed: " << GetLastError() << endl;
        return false;
    }

    const LPVOID remoteStringAllocatedMem{ static_cast<LPVOID>(VirtualAllocEx(hProc, NULL, dllName.length(), MEM_RESERVE | MEM_COMMIT,
        PAGE_READWRITE)) };
    if (!remoteStringAllocatedMem)
    {
        cout << "VirtualAllocEx() failed: " << GetLastError() << endl;
        return false;
    }

    if (!WriteProcessMemory(hProc, static_cast<LPVOID>(remoteStringAllocatedMem), dllName.c_str(), dllName.length(), NULL))
    {
        cout << "WriteProcessMemory() failed: " << GetLastError() << endl;
        return false;
    }

    const HANDLE hRemoteThread{ CreateRemoteThread(hProc, NULL, NULL, static_cast<LPTHREAD_START_ROUTINE>(loadLibrary), static_cast<LPVOID>(remoteStringAllocatedMem), NULL, NULL) };
    if (!hRemoteThread)
    {
        cout << "CreateRemoteThread() failed: " << GetLastError() << endl;
        return false;
    }

    CloseHandle(hProc);
    CloseHandle(hRemoteThread);

    return true;
}

DWORD GetTargetProcessIdFromProcessName(const std::string& procName)
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