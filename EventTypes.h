#pragma once
#include <windows.h>
#include <tlhelp32.h>
#include <vector>
#include <string>
#include <iostream>
#include <evntrace.h>
#include <evntcons.h>
#include <functional>
#include <atomic>
#include <memory>
#include <tdh.h>
#include <thread>

struct Process {
    DWORD pid;
    DWORD parentPid;
    std::wstring name;
    std::string path;
    std::string commandLine;
    bool isAlert = false;
};