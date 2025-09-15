#pragma once
#include <windows.h>
#include <tlhelp32.h>
#include <vector>
#include <iostream>
#include <evntrace.h> 
#include <evntcons.h>  
#include <initguid.h> 
#include <guiddef.h>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <ctime>
struct Process {
    DWORD pid;
    DWORD parentPid;
    std::wstring name;
    std::string path;
    std::string commandLine;
    bool isAlert = false;
};