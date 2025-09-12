#include "EtwKernelLogger.h"
#include <iostream>

// Link with advapi32.lib and tdh.lib
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "tdh.lib")

EtwKernelLogger::EtwKernelLogger() {
    sessionHandle = 0;
    consumerHandle = 0;
    props = nullptr;
}

EtwKernelLogger::~EtwKernelLogger() {
    StopAndClean();
}

std::wstring EtwKernelLogger::GetErrorMessage(DWORD code) {
    LPWSTR buffer = nullptr;
    FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL, code, 0, (LPWSTR)&buffer, 0, NULL);

    std::wstring msg = buffer ? buffer : L"Unknown error";
    if (buffer) LocalFree(buffer);
    return msg;
}

bool EtwKernelLogger::EnablePrivilege(LPCWSTR privName) {
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!OpenProcessToken(GetCurrentProcess(),
        TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
        &hToken)) {
        return false;
    }

    if (!LookupPrivilegeValueW(NULL, privName, &luid)) {
        CloseHandle(hToken);
        return false;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tp,
        sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
        CloseHandle(hToken);
        return false;
    }

    CloseHandle(hToken);
    return GetLastError() == ERROR_SUCCESS;
}

VOID WINAPI EtwKernelLogger::OnEventRecord(PEVENT_RECORD record) {
    auto& h = record->EventHeader;

    if (h.EventDescriptor.Opcode == 1) {
        std::wcout << L"[+] Process Start: PID=" << h.ProcessId << std::endl;
    }
    else if (h.EventDescriptor.Opcode == 2) {
        std::wcout << L"[-] Process Exit: PID=" << h.ProcessId << std::endl;
    }
    else {
        std::wcout << L"[ETW] EventId=" << h.EventDescriptor.Id
            << L" Opcode=" << (int)h.EventDescriptor.Opcode
            << L" PID=" << h.ProcessId << std::endl;
    }
}

bool EtwKernelLogger::EnablePrivileges() {
    bool ok1 = EnablePrivilege(SE_SYSTEM_PROFILE_NAME);
    bool ok2 = EnablePrivilege(SE_DEBUG_NAME);
    if (!ok1) std::wcerr << L"Failed to enable SeSystemProfilePrivilege\n";
    if (!ok2) std::wcerr << L"Failed to enable SeDebugPrivilege\n";
    return ok1 && ok2;
}

bool EtwKernelLogger::SetupProvider() {
    const wchar_t* sessionName = KERNEL_LOGGER_NAME;
    size_t propsSize = sizeof(EVENT_TRACE_PROPERTIES) + sizeof(KERNEL_LOGGER_NAME);

    props = (EVENT_TRACE_PROPERTIES*)malloc(propsSize);
    ZeroMemory(props, propsSize);

    props->Wnode.BufferSize = (ULONG)propsSize;
    props->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    props->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    props->LogFileMode = EVENT_TRACE_REAL_TIME_MODE | EVENT_TRACE_SYSTEM_LOGGER_MODE;
    props->EnableFlags = EVENT_TRACE_FLAG_PROCESS;

    ULONG status = StartTrace(&sessionHandle, sessionName, props);
    if (status != ERROR_SUCCESS && status != ERROR_ALREADY_EXISTS) {
        std::wcerr << L"StartTrace failed (" << status << L"): "
            << GetErrorMessage(status) << std::endl;
        free(props);
        props = nullptr;
        return false;
    }
    return true;
}

bool EtwKernelLogger::SetupConsumer() {
    const wchar_t* sessionName = KERNEL_LOGGER_NAME;

    EVENT_TRACE_LOGFILEW logfile{};
    logfile.LoggerName = (LPWSTR)sessionName;
    logfile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    logfile.EventRecordCallback = (PEVENT_RECORD_CALLBACK)(OnEventRecord);

    consumerHandle = OpenTraceW(&logfile);
    if (consumerHandle == INVALID_PROCESSTRACE_HANDLE) {
        DWORD err = GetLastError();
        std::wcerr << L"OpenTrace failed: " << err << L" ("
            << GetErrorMessage(err) << L")\n";
        return false;
    }
    return true;
}

void EtwKernelLogger::Run() {
    std::wcout << L"Listening for process start/exit events...\n"
        << L"Open or close Notepad/Calc/etc. to trigger events.\n"
        << L"Press Ctrl+C to stop.\n";

    ULONG status = ProcessTrace(&consumerHandle, 1, nullptr, nullptr);
    if (status != ERROR_SUCCESS) {
        std::wcerr << L"ProcessTrace failed (" << status << L"): "
            << GetErrorMessage(status) << std::endl;
    }
}

void EtwKernelLogger::StopAndClean() {
    if (consumerHandle) {
        CloseTrace(consumerHandle);
        consumerHandle = 0;
    }
    if (sessionHandle) {
        ControlTrace(sessionHandle, KERNEL_LOGGER_NAME, props, EVENT_TRACE_CONTROL_STOP);
        sessionHandle = 0;
    }
    if (props) {
        free(props);
        props = nullptr;
    }
}
