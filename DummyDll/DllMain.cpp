#include <Windows.h>
#include <iostream>
#include <sstream>

void HandleError(const std::string& msg);
DWORD WINAPI StartRoutine(LPVOID lpParam);

BOOL WINAPI DllMain(
    HINSTANCE hinstDLL,  // handle to DLL module
    DWORD fdwReason,     // reason for calling function
    LPVOID lpReserved)  // reserved
{
    switch (fdwReason)
    {
    case DLL_PROCESS_ATTACH:
        (void)MessageBox(NULL, "Injected", "Success", MB_OK);
        CreateThread(NULL, NULL, StartRoutine, hinstDLL, NULL, NULL);
        break;

    case DLL_THREAD_ATTACH:
        //(void)MessageBox(NULL, "DLL_THREAD_ATTACH", "Success", MB_OK);
        break;

    case DLL_THREAD_DETACH:
        //(void)MessageBox(NULL, "DLL_THREAD_DETACH", "Success", MB_OK);
        break;

    case DLL_PROCESS_DETACH:
        //(void)MessageBox(NULL, "DLL_PROCESS_DETACH", "Success", MB_OK);
        break;
    }
    return TRUE;
}

void HandleError(const std::string& msg)
{
    std::ostringstream s;
    s << msg << "\nError code: " << GetLastError();

    if (GetConsoleWindow())
    {
        std::cout << s.str();
    }
    else
    {
        MessageBox(NULL, s.str().c_str(), "Error", MB_OK);
    }
}

DWORD WINAPI StartRoutine(LPVOID lpParam)
{
    //MessageBox(NULL, "Routine", "Work", MB_OK);

    if (!AllocConsole())
    {
        HandleError("Failed to attach console");
        FreeLibraryAndExitThread(static_cast<HMODULE>(lpParam), 0);
    }
    freopen_s(reinterpret_cast<FILE**>(stdout), "CONOUT$", "w", stdout);
    std::cout << "Console initialized!" << std::endl;

    while (!(GetAsyncKeyState(VK_INSERT) & 0x1))
    {
        //std::cout << "Loop" << std::endl;
        Sleep(100);
    }

    FreeConsole();
    FreeLibraryAndExitThread(static_cast<HMODULE>(lpParam), 0);
}