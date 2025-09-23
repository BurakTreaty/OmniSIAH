#pragma once
#include "libs.h"
struct Process {
    DWORD pid;
    DWORD parentPid;
    std::wstring name;
    std::string path;
    std::string commandLine;
    bool isAlert = false;
};

class processScanner {
private:
    HANDLE hProcessSnap;
    PROCESSENTRY32 pe32;

public:
    processScanner();
    ~processScanner();
    std::vector<Process> getRunningProcesses();
    Process getProcessInfo(DWORD pid);
    void printProcesses();    
};