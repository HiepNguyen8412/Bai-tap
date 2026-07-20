#include <windows.h>
#include <iostream>

using namespace std;

int wmain()
{
    //--------------------------------------------------
    // Tạo file output.txt để redirect stdout
    //--------------------------------------------------

    SECURITY_ATTRIBUTES sa;

    sa.nLength = sizeof(sa);
    sa.lpSecurityDescriptor = NULL;
    sa.bInheritHandle = TRUE;

    HANDLE hFile = CreateFileW(
        L"output.txt",
        GENERIC_WRITE,
        FILE_SHARE_READ,
        &sa,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hFile == INVALID_HANDLE_VALUE)
    {
        wcout << L"Cannot create output file!\n";
        wcout << L"Error Code = " << GetLastError() << endl;
        return 1;
    }

    //--------------------------------------------------
    // STARTUPINFO
    //--------------------------------------------------

    STARTUPINFOW si;
    ZeroMemory(&si, sizeof(si));

    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = hFile;
    si.hStdError = hFile;

    PROCESS_INFORMATION pi;
    ZeroMemory(&pi, sizeof(pi));

    //--------------------------------------------------
    // Command Line
    //--------------------------------------------------

    wchar_t cmdLine[] =
        L"Child.exe Hello Windows API";

    DWORD startTime = GetTickCount();

    //--------------------------------------------------
    // Create Process
    //--------------------------------------------------

    BOOL success = CreateProcessW(
        NULL,
        cmdLine,
        NULL,
        NULL,
        TRUE,
        0,
        NULL,
        NULL,
        &si,
        &pi
    );

    if (!success)
    {
        wcout << L"CreateProcess Failed!\n";
        wcout << L"Error Code = " << GetLastError() << endl;

        CloseHandle(hFile);
        return 1;
    }

    //--------------------------------------------------
    // Hiển thị PID
    //--------------------------------------------------

    wcout << L"Parent PID : "
        << GetCurrentProcessId()
        << endl;

    wcout << L"Child PID  : "
        << pi.dwProcessId
        << endl;

    //--------------------------------------------------
    // Chờ Child kết thúc
    //--------------------------------------------------

    WaitForSingleObject(
        pi.hProcess,
        INFINITE);

    DWORD endTime = GetTickCount();

    //--------------------------------------------------
    // Lấy Exit Code
    //--------------------------------------------------

    DWORD exitCode = 0;

    GetExitCodeProcess(
        pi.hProcess,
        &exitCode);

    //--------------------------------------------------
    // Kết quả
    //--------------------------------------------------

    wcout << endl;

    wcout << L"Run Time : "
        << (endTime - startTime)
        << L" ms"
        << endl;

    wcout << L"Exit Code : "
        << exitCode
        << endl;

    //--------------------------------------------------
    // Giải phóng Handle
    //--------------------------------------------------

    CloseHandle(hFile);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    wcout << L"\nOutput redirected to output.txt\n";

    return 0;
}
