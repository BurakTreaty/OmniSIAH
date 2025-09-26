#include "EtwSession.h"

// Link with advapi32.lib and tdh.lib
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "tdh.lib")

//TDH functions
std::wstring processName(PEVENT_RECORD rec) {
    std::wstring name = L"<unknown>";
    ULONG bufferSize = 0;

    TdhGetEventInformation(rec, 0, nullptr, nullptr, &bufferSize);
    PTRACE_EVENT_INFO info = (PTRACE_EVENT_INFO)malloc(bufferSize);
    if (!info) return name;


    if (TdhGetEventInformation(rec, 0, nullptr, info, &bufferSize) != ERROR_SUCCESS) {
        free(info);
        return name;
    }

    for (ULONG i = 0; i < info->TopLevelPropertyCount; i++) {
        EVENT_PROPERTY_INFO prop = info->EventPropertyInfoArray[i];
        std::wstring propName = (LPWSTR)((PBYTE)info + prop.NameOffset);

        if (propName == L"ImageFileName" || propName == L"ProcessName") {
            PROPERTY_DATA_DESCRIPTOR desc{};
            desc.PropertyName = (ULONGLONG)((PBYTE)info + prop.NameOffset);

            WCHAR value[1024] = { 0 };
            ULONG size = sizeof(value);
            if (TdhGetProperty(rec, 0, nullptr, 1, &desc, size, (PBYTE)value) == ERROR_SUCCESS) {
                name = value;
            }
            break;
        }
    }

    free(info);
    return name;
}  
//TDH NAME RETRİVE DOES NOT WORK

std::wstring ResolveProcessName(DWORD pid) {

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (hProcess) {
        WCHAR buffer[MAX_PATH];
        DWORD size = MAX_PATH;
        if (QueryFullProcessImageNameW(hProcess, 0, buffer, &size)) {
            CloseHandle(hProcess);
            return std::wstring(buffer);
        }
        CloseHandle(hProcess);
    }
    return L"<unknown>";
}

DWORD parentPID(PEVENT_RECORD rec) {
    DWORD parentPid = 0;
    ULONG bufferSize = 0;
    TdhGetEventInformation(rec, 0, nullptr, nullptr, &bufferSize);
    PTRACE_EVENT_INFO info = (PTRACE_EVENT_INFO)malloc(bufferSize);
    TdhGetEventInformation(rec, 0, nullptr, info, &bufferSize);


    for (ULONG i = 0; i < info->TopLevelPropertyCount; i++) {
        EVENT_PROPERTY_INFO prop = info->EventPropertyInfoArray[i];
        std::wstring propName = (LPWSTR)((PBYTE)info + prop.NameOffset);

        if (propName == L"ParentProcessID") {
            PROPERTY_DATA_DESCRIPTOR desc{};
            desc.PropertyName = (ULONGLONG)((PBYTE)info + prop.NameOffset);

            ULONG size = sizeof(parentPid);
            TdhGetProperty(rec, 0, nullptr, 1, &desc, size, (PBYTE)&parentPid);
            break;
        }
    }
    free(info);
    return parentPid; // 0 if not found
}

std::wstring dllPath(PEVENT_RECORD rec) {
    std::wstring path = L"<unknown>";
    ULONG bufferSize = 0;

    if (TdhGetEventInformation(rec, 0, nullptr, nullptr, &bufferSize) != ERROR_INSUFFICIENT_BUFFER)
        return path;

    PTRACE_EVENT_INFO info = (PTRACE_EVENT_INFO)malloc(bufferSize);
    if (!info) return path;

    if (TdhGetEventInformation(rec, 0, nullptr, info, &bufferSize) != ERROR_SUCCESS) {
        free(info);
        return path;
    }
    for (ULONG i = 0; i < info->TopLevelPropertyCount; i++) {
        EVENT_PROPERTY_INFO& prop = info->EventPropertyInfoArray[i];
        std::wstring propName = (LPWSTR)((PBYTE)info + prop.NameOffset);
        if (propName == L"FileName" || propName == L"ImageFileName") {
            PROPERTY_DATA_DESCRIPTOR desc{};
            desc.PropertyName = (ULONGLONG)((PBYTE)info + prop.NameOffset);

            WCHAR value[1024] = { 0 };
            ULONG size = sizeof(value);

            if (TdhGetProperty(rec, 0, nullptr, 1, &desc, size, (PBYTE)value) == ERROR_SUCCESS) {
                path = value;
            }
            break; // Stop once we found a matching property
        }
    }

    free(info);
    return path;
}

//ETW class functions
EtwSession::EtwSession() { //construcator
    sessionHandle = 0;
    consumerHandle = 0;
    props = nullptr;
}

EtwSession::~EtwSession() { //destructor
    stopAndClean();
}

std::wstring EtwSession::getErrorMessage(DWORD code) {
    LPWSTR buffer = nullptr;
    FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL, code, 0, (LPWSTR)&buffer, 0, NULL);

    std::wstring msg = buffer ? buffer : L"Unknown error";
    if (buffer) LocalFree(buffer);
    return msg;
}
// --------- Privilege enabler ----------
bool EtwSession::enablePrivilege(LPCWSTR privName) {
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

VOID WINAPI EtwSession::onEventRecord(PEVENT_RECORD record) {
    int opCode = (int)record->EventHeader.EventDescriptor.Opcode;
    std::wstring path;
    path = dllPath(record);
    
    // Timestamp
    std::time_t now = std::time(nullptr);
    std::tm localTime;
    localtime_s(&localTime, &now);
    std::wostringstream entry;
    entry << L"[" << std::put_time(&localTime, L"%Y-%m-%d %H:%M:%S") << L"] "
        << L", Opcode=" << opCode
        << L", Parent ID=" << parentPID(record)
        << L", PID=" << record->EventHeader.ProcessId
        << L", Process=" << ResolveProcessName(record->EventHeader.ProcessId)
        << L", TID=" << record->EventHeader.ThreadId;

    if (opCode == 10) {
        entry << L", Path=" << dllPath(record);
    }

    entry << std::endl;


    // Append to log
        std::wofstream log("EventLog.txt", std::ios::app);
        if (log.is_open()) {
            log << entry.str();
        }    
}




//priv enable checker
bool EtwSession::enablePrivileges() {
    bool ok1 = enablePrivilege(SE_SYSTEM_PROFILE_NAME);
    bool ok2 = enablePrivilege(SE_DEBUG_NAME);
    if (!ok1) std::wcerr << L"Failed to enable SeSystemProfilePrivilege\n";
    if (!ok2) std::wcerr << L"Failed to enable SeDebugPrivilege\n";
    return ok1 && ok2;
}

//1) Setup provider session
bool EtwSession::setupProvider() {
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
    props->EnableFlags = EVENT_TRACE_FLAG_PROCESS | EVENT_TRACE_FLAG_THREAD | EVENT_TRACE_FLAG_IMAGE_LOAD; // track process events , dll/exe loads

    //1.2) Start session (provider)
    ULONG status = StartTrace(&sessionHandle, sessionName, props); // start session with given props
    if (status != ERROR_SUCCESS && status != ERROR_ALREADY_EXISTS) { //error handling -if sesssion is already created or failed without error
        std::wcerr << L"StartTrace failed (" << status << L"): "
            << getErrorMessage(status) << std::endl;
        free(props);
        props = nullptr;
        return false;
    }
    return true;
}

//2) setup consumer session
bool EtwSession::setupConsumer() { 
    const wchar_t* sessionName = KERNEL_LOGGER_NAME;
    //2.1) consumer properities
    EVENT_TRACE_LOGFILEW logfile{};  // consume properities init from the logfile
    logfile.LoggerName = (LPWSTR)sessionName; //name is same as session name
    logfile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD; //real time trace in Event_record format 
    logfile.EventRecordCallback = (PEVENT_RECORD_CALLBACK)(onEventRecord); //callback register

    //2.2) start consumer session
    consumerHandle = OpenTraceW(&logfile);
    if (consumerHandle == INVALID_PROCESSTRACE_HANDLE) {
        DWORD err = GetLastError();
        std::wcerr << L"OpenTrace failed: " << err << L" ("
            << getErrorMessage(err) << L")\n";
        return false;
    }
    return true;
}

void EtwSession::run() { //Run 
    std::wcout << L"Listening for process start/exit events...";
    ULONG status = ProcessTrace(&consumerHandle, 1, nullptr, nullptr);
    if (status != ERROR_SUCCESS) {
        std::wcerr << L"ProcessTrace failed (" << status << L"): "
            << getErrorMessage(status) << std::endl;
    }
}

void EtwSession::stopAndClean() {
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
