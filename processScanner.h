#pragma once
#include "EventTypes.h"

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