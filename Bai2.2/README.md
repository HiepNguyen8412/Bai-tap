#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <iomanip>

using namespace std;

// Chuyển FILETIME sang số 64-bit
ULONGLONG FileTimeToUInt64(const FILETIME& ft)
{
    ULARGE_INTEGER uli;
    uli.LowPart = ft.dwLowDateTime;
    uli.HighPart = ft.dwHighDateTime;
    return uli.QuadPart;
}

void ListThreads(DWORD pid)
{
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);

    if (hSnapshot == INVALID_HANDLE_VALUE)
    {
        cout << "Cannot create snapshot!" << endl;
        return;
    }

    THREADENTRY32 te;
    te.dwSize = sizeof(THREADENTRY32);

    if (!Thread32First(hSnapshot, &te))
    {
        cout << "Cannot enumerate threads!" << endl;
        CloseHandle(hSnapshot);
        return;
    }

    cout << left
        << setw(10) << "TID"
        << setw(12) << "Priority"
        << setw(18) << "CPU Time(ms)"
        << setw(20) << "Status"
        << endl;

    cout << "--------------------------------------------------------------"
        << endl;

    do
    {
        if (te.th32OwnerProcessID == pid)
        {
            HANDLE hThread = OpenThread(
                THREAD_QUERY_INFORMATION,
                FALSE,
                te.th32ThreadID);

            string status = "Access Denied";
            double cpuTimeMs = 0;

            if (hThread != NULL)
            {
                status = "Accessible";

                FILETIME creation, exit, kernel, user;

                if (GetThreadTimes(
                    hThread,
                    &creation,
                    &exit,
                    &kernel,
                    &user))
                {
                    ULONGLONG kernelTime = FileTimeToUInt64(kernel);
                    ULONGLONG userTime = FileTimeToUInt64(user);

                    // FILETIME = 100ns
                    cpuTimeMs = (kernelTime + userTime) / 10000.0;
                }

                CloseHandle(hThread);
            }

            cout << left
                << setw(10) << te.th32ThreadID
                << setw(12) << te.tpBasePri
                << setw(18) << fixed << setprecision(2) << cpuTimeMs
                << setw(20) << status
                << endl;
        }

    } while (Thread32Next(hSnapshot, &te));

    CloseHandle(hSnapshot);
}

int main()
{
    DWORD pid;

    cout << "Enter PID: ";
    cin >> pid;

    ListThreads(pid);

    return 0;
}
