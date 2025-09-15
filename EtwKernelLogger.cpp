#include "EtwKernelLogger.h"

// Link with advapi32.lib and tdh.lib
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "tdh.lib")

EtwKernelLogger::EtwKernelLogger() { //construcator
    sessionHandle = 0;
    consumerHandle = 0;
    props = nullptr;
}

EtwKernelLogger::~EtwKernelLogger() { //destructor
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
// --------- Privilege enabler ----------
bool EtwKernelLogger::EnablePrivilege(LPCWSTR privName) {
    HANDLE hToken; // access token handle
    TOKEN_PRIVILEGES tp; // name of privilege to enable/disable
    LUID luid; // to enable or disable privilege

    OpenProcessToken(GetCurrentProcess(),//access token for the current process.
        TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken);

    LookupPrivilegeValueW(NULL, privName, &luid); //translate the privilege nam to LUID 

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;//luID
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED; // "enable" said privs

    AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL); // apply arranged properities

    CloseHandle(hToken); //close handle
    return GetLastError() == ERROR_SUCCESS; //if fail return error
}

// Event logging operation
VOID WINAPI EtwKernelLogger::OnEventRecord(PEVENT_RECORD record) {
    auto& h = record->EventHeader;

    // Timestamp
    std::time_t now = std::time(nullptr);
    std::tm localTime;
    localtime_s(&localTime, &now);

    // Format as readable text
    std::wostringstream entry;
    entry << L"[" << std::put_time(&localTime, L"%Y-%m-%d %H:%M:%S") << L"] "
        << L"PID=" << h.ProcessId
        << L", TID=" << h.ThreadId
        << L", EventID=" << h.EventDescriptor.Id
        << L", Opcode=" << (int)h.EventDescriptor.Opcode
        << std::endl;

    //All evenets recorded in EventLog for further investiagion
    std::wofstream log("EventLog.txt", std::ios::app);
    if (log.is_open()) {
        log << entry.str();
    }
}

//priv enable checker
bool EtwKernelLogger::EnablePrivileges() {
    bool ok1 = EnablePrivilege(SE_SYSTEM_PROFILE_NAME);
    bool ok2 = EnablePrivilege(SE_DEBUG_NAME);
    if (!ok1) std::wcerr << L"Failed to enable SeSystemProfilePrivilege\n";
    if (!ok2) std::wcerr << L"Failed to enable SeDebugPrivilege\n";
    return ok1 && ok2;
}

//1) Setup provider session
bool EtwKernelLogger::SetupProvider() {
    const wchar_t* sessionName = KERNEL_LOGGER_NAME;//predefined constant name for kernel session KERNEL_LOGGER_NAME -> NT Kernel Logger
    
    //propeties arrangement and allocation
    size_t propsSize = sizeof(EVENT_TRACE_PROPERTIES) + sizeof(KERNEL_LOGGER_NAME);
    props = (EVENT_TRACE_PROPERTIES*)malloc(propsSize);
    ZeroMemory(props, propsSize);

    //1.1) prop loads
    props->Wnode.BufferSize = (ULONG)propsSize;//buffer size
    props->Wnode.Flags = WNODE_FLAG_TRACED_GUID; //trace guid session
    props->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES); // buffer offset of logger name (i.e offset of NT Kernel Logger)
    props->LogFileMode = EVENT_TRACE_REAL_TIME_MODE | EVENT_TRACE_SYSTEM_LOGGER_MODE; //don’t log to a file, deliver events live to consumers -for now-
    props->EnableFlags = EVENT_TRACE_FLAG_PROCESS; // track process events //TODO: EVENT_TRACE_FLAG_IMAGE_LOAD for DLL/exe loads

    //1.2) Start session (provider)
    ULONG status = StartTrace(&sessionHandle, sessionName, props); // start session with given props
    if (status != ERROR_SUCCESS && status != ERROR_ALREADY_EXISTS) { //error handling -if sesssion is already created or failed without error
        std::wcerr << L"StartTrace failed (" << status << L"): "
            << GetErrorMessage(status) << std::endl;
        free(props);
        props = nullptr;
        return false;
    }
    return true;
}

//2) setup consumer session
bool EtwKernelLogger::SetupConsumer() { 
    const wchar_t* sessionName = KERNEL_LOGGER_NAME;
    //2.1) consumer properities
    EVENT_TRACE_LOGFILEW logfile{};  // consume properities init from the logfile
    logfile.LoggerName = (LPWSTR)sessionName; //name is same as session name
    logfile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD; //real time trace in Event_record format 
    logfile.EventRecordCallback = (PEVENT_RECORD_CALLBACK)(OnEventRecord); //callback register

    //2.2) start consumer session
    consumerHandle = OpenTraceW(&logfile);
    if (consumerHandle == INVALID_PROCESSTRACE_HANDLE) {
        DWORD err = GetLastError();
        std::wcerr << L"OpenTrace failed: " << err << L" ("
            << GetErrorMessage(err) << L")\n";
        return false;
    }
    return true;
}

void EtwKernelLogger::Run() { //Run 
    std::wcout << L"Listening for process start/exit events...";
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

    ULONG status = ControlTraceW(
        0,                                // 0 = "ignore handle, use session name"
        KERNEL_LOGGER_NAME,               // NT Kernel Logger
        props,
        EVENT_TRACE_CONTROL_STOP
    );

    sessionHandle = 0;

    if (props) {
        free(props);
        props = nullptr;
    }
}
