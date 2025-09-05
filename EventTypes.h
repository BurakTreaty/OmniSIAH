#pragma once
#include <windows.h>
#include <tlhelp32.h>
#include <vector>
#include <string>
#include <iostream>
#include <evntrace.h>   // StartTrace, ControlTrace, EnableTraceEx2
#include <evntcons.h>   // OpenTrace, ProcessTrace, EVENT_RECORD callback
#include <tdh.h>        // (optional) advanced parsing with TDH
#include <functional>
#include <atomic>
#include <memory>
#include <thread>
#include <initguid.h> 
#include <guiddef.h>
struct Process {
    DWORD pid;
    DWORD parentPid;
    std::wstring name;
    std::string path;
    std::string commandLine;
    bool isAlert = false;
};