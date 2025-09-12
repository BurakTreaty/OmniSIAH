#include "EventTypes.h"
// Link with: advapi32.lib, tdh.lib
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "tdh.lib")

//Kernel Process provider  GUID 
DEFINE_GUID(Microsoft_Windows_Kernel_Process,
    0x22fb2cd6, 0x0e7b, 0x422b, 0xa0, 0xc7, 0x2f, 0x53, 0x1e, 0x18, 0x65, 0xb7); //default constant guid for kernel sub

std::wstring GetErrorMessage(DWORD code) {
    LPWSTR buffer = nullptr;
    FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL, code, 0, (LPWSTR)&buffer, 0, NULL);

    std::wstring msg = buffer ? buffer : L"Unknown error";
    if (buffer) LocalFree(buffer);
    return msg;
}

// --------- Privilege enabler ----------
bool EnablePrivilege(LPCWSTR privName) { // get the privilige name and enable it
    HANDLE hToken; // access token handle
    TOKEN_PRIVILEGES tp; // name of privilege to enable/disable
    LUID luid; // to enable or disable privilege

    OpenProcessToken(GetCurrentProcess(),//access token for the current process.
        TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken); //TODO: error handling

    LookupPrivilegeValueW(NULL, privName, &luid); //translate the privilege nam to LUID , TODO: error handling

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid; //luID
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED; // want to enable

    AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL); // apply arranged properities

    CloseHandle(hToken); //close handle
    return GetLastError() == ERROR_SUCCESS; //if fail return error
}

// --------- Event callback ----------
VOID WINAPI OnEventRecord(PEVENT_RECORD record) {
    auto& h = record->EventHeader;
   /* h structure:
   ProviderId:GUID of the event provider.
   ProcessId:PID that generated the event.
   ThreadId:TID that generated it.
   EventDescriptor.Id:the event ID.
   EventDescriptor.Opcode:which action happened 0->Info 1->Start 2->stop .*/

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

// --------- Main program ----------
int wmain() {
    std::wcout << L"--- ETW Kernel Logger Safe Tester ---\n";

    // 0)Enable privileges
    if (!EnablePrivilege(SE_SYSTEM_PROFILE_NAME)) {
        std::wcerr << L"Failed to enable SeSystemProfilePrivilege\n";
    }
    else 
    {
        if (!EnablePrivilege(SE_DEBUG_NAME)) {
            std::wcerr << L"Failed to enable SeDebugPrivilege\n";
        }
        else
        {
            std::cout << L"All system privileges enbaled...\n" << std::endl;
        }
    }


    // 1)Setup session
    const wchar_t* sessionName = KERNEL_LOGGER_NAME; //constant name for kernel session KERNEL_LOGGER_NAME -> NT Kernel Logger

    size_t propsSize = sizeof(EVENT_TRACE_PROPERTIES) + sizeof(KERNEL_LOGGER_NAME); //propeties arrangement and allocation
    EVENT_TRACE_PROPERTIES* props = (EVENT_TRACE_PROPERTIES*)malloc(propsSize);
    ZeroMemory(props, propsSize);

    //      1.1)prop loads
    props->Wnode.BufferSize = (ULONG)propsSize; //buffer size
    props->Wnode.Flags = WNODE_FLAG_TRACED_GUID; //trace GUID session
    props->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES); //mark end of propeties in buffer
    props->LogFileMode = EVENT_TRACE_REAL_TIME_MODE | EVENT_TRACE_SYSTEM_LOGGER_MODE; //don’t log to a file, deliver events live to consumers
    props->EnableFlags = EVENT_TRACE_FLAG_PROCESS; // track process events //TODO: EVENT_TRACE_FLAG_IMAGE_LOAD for DLL/exe loads

    //      1.2)Start session (provider)
    TRACEHANDLE sessionHandle = 0; //init
    ULONG status = StartTrace(&sessionHandle, sessionName, props); // create the session
    if (status != ERROR_SUCCESS && status != ERROR_ALREADY_EXISTS) { //error handling for session creation
        std::wcerr << L"StartTrace failed (" << status << L"): "
            << GetErrorMessage(status) << std::endl;
        free(props);
        return 1;
    }

    // 2)Setup consumer
    //      2.1)consumer properities
    EVENT_TRACE_LOGFILEW logfile{}; // consume properities init
    logfile.LoggerName = (LPWSTR)sessionName; //session name to connect
    logfile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD; //real time trace in Event_record format 
    logfile.EventRecordCallback = (PEVENT_RECORD_CALLBACK)(OnEventRecord); //callback register

    //      2.2) Connect consumer
    TRACEHANDLE consumerHandle = OpenTraceW(&logfile); //coonect the session in logfile
    if (consumerHandle == INVALID_PROCESSTRACE_HANDLE) { //error management for consumer connection
        DWORD err = GetLastError();
        std::wcerr << L"OpenTrace failed: " << err << L" (" << GetErrorMessage(err) << L")\n";
        ControlTrace(sessionHandle, sessionName, props, EVENT_TRACE_CONTROL_STOP);
        free(props);
        return 1;
    }

    std::wcout << L"Listening for process start/exit events...\n" //UI for armed consumer
        << L"Open or close Notepad/Calc/etc. to trigger events.\n"
        << L"Press Ctrl+C to stop.\n";

    status = ProcessTrace(&consumerHandle, 1, nullptr, nullptr);
    //                  (trace handles(just 1) , #trace handles (1) , optional time range (null is forever))

    if (status != ERROR_SUCCESS) { //error handling
        std::wcerr << L"ProcessTrace failed (" << status << L"): "
            << GetErrorMessage(status) << std::endl;
    }

    // 3)Clean
    CloseTrace(consumerHandle); //close consumer
    ControlTrace(sessionHandle, sessionName, props, EVENT_TRACE_CONTROL_STOP); //stop ETW session

    free(props);
    return 0;
}