#pragma once
#include <windows.h>
#include <tlhelp32.h>
#include <vector>
#include <string>
#include <iostream>

struct ProcessInfo {
    DWORD pid;
    DWORD parentPid;
    std::wstring name;
    std::string path;
    std::string commandLine;
};

class processScanner {
private:
    HANDLE hProcessSnap;
    PROCESSENTRY32 pe32;

public:
    processScanner();
    ~processScanner();
    std::vector<ProcessInfo> getRunningProcesses();
    ProcessInfo getProcessInfo(DWORD pid);
    void printProcesses();    
};