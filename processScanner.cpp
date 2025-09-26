#include "processScanner.h"
int i = 0;
processScanner::processScanner() {
    hProcessSnap = INVALID_HANDLE_VALUE;
    ZeroMemory(&pe32, sizeof(PROCESSENTRY32));
}

processScanner::~processScanner() {
    if (hProcessSnap != INVALID_HANDLE_VALUE) {
        CloseHandle(hProcessSnap);
    }
}

void processScanner::dumpRunningProcesses() {
    HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE) {
        std::wcerr << L"System Snapshot failed. Error: " << GetLastError() << std::endl;
        return;
    }

    PROCESSENTRY32 pe32{};
    pe32.dwSize = sizeof(PROCESSENTRY32);
    std::wstring filename = L"SysLog" + std::to_wstring(i) + L".txt";
    std::wofstream logFile(filename, std::ios::app);

    do {
        logFile << L"PID=" << pe32.th32ProcessID
            << L", Parent=" << pe32.th32ParentProcessID
            << L", Name=" << pe32.szExeFile
            << std::endl;
    } while (Process32Next(hProcessSnap, &pe32));

    logFile.close();
    std::wcout << L"System processes log file has been created.\n";
    CloseHandle(hProcessSnap);
    i++;
}



