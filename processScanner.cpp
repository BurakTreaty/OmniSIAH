#include "processScanner.h"

processScanner::processScanner() {
    hProcessSnap = INVALID_HANDLE_VALUE;
    ZeroMemory(&pe32, sizeof(PROCESSENTRY32));
}

processScanner::~processScanner() {
    if (hProcessSnap != INVALID_HANDLE_VALUE) {
        CloseHandle(hProcessSnap);
    }
}

std::vector<Process> processScanner::getRunningProcesses() {
    std::vector<Process> processes;

    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE) {
        std::cerr << "CreateToolhelp32Snapshot failed. Error: " << GetLastError() << std::endl;
        return processes;
    }

    pe32.dwSize = sizeof(PROCESSENTRY32);
    if (!Process32First(hProcessSnap, &pe32)) {
        std::cerr << "Process32First failed. Error: " << GetLastError() << std::endl;
        CloseHandle(hProcessSnap);
        hProcessSnap = INVALID_HANDLE_VALUE;
        return processes;
    }

    do {
        Process info;
        info.pid = pe32.th32ProcessID;
        info.parentPid = pe32.th32ParentProcessID;
        info.name = pe32.szExeFile; // INFO : pe32.szExeFile is stored in wstring
        info.path = "";
        info.commandLine = "";
        processes.push_back(info);
    } while (Process32Next(hProcessSnap, &pe32));

    CloseHandle(hProcessSnap);
    hProcessSnap = INVALID_HANDLE_VALUE;
    return processes;
}

Process processScanner::getProcessInfo(DWORD pid) {
    Process info;

    // Get all running processes
    std::vector<Process> processes = getRunningProcesses();

    // Iterate through the vector of processes to find the one with matching PID
    for (Process process : processes) {
        if (process.pid == pid) {
            // Found the matching process, return its information
            return process;
        }
    }

    // If no process found with the given PID, return empty ProcessInfo
    // TODO: Handle no process found with given pid
    std::cerr << "Process with PID " << pid << " not found." << std::endl;
    return Process(); // Return default-constructed ProcessInfo
}



//// Test&Ust Functions

void processScanner::printProcesses()
{
    std::vector<Process> processes = getRunningProcesses();
    for (Process process : processes) {
        std::cout << "Process ID: " << process.pid << "\n Process Parent ID: " << process.parentPid << std::endl;
        std::wcout << "Process Name: " << process.name << std::endl;
    }
}

