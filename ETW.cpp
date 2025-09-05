#include <windows.h>
#include <evntrace.h>
#include <evntcons.h>
#include <iostream>
#include <string>

#include <initguid.h>
#include <guiddef.h>

// Link with: advapi32.lib, tdh.lib
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "tdh.lib")

//Kernel Process provider  GUID 
DEFINE_GUID(Microsoft_Windows_Kernel_Process,
    0x22fb2cd6, 0x0e7b, 0x422b, 0xa0, 0xc7, 0x2f, 0x53, 0x1e, 0x18, 0x65, 0xb7);

// Event callback (called by ProcessTrace for each event)
VOID WINAPI OnEventRecord(PEVENT_RECORD record) {
    EVENT_HEADER& h = record->EventHeader;

    std::wcout << L"[ETW Event] "
        << L"Provider=" << h.ProviderId.Data1
        << L" EventId=" << h.EventDescriptor.Id
        << L" Opcode=" << (int)h.EventDescriptor.Opcode
        << L" PID=" << h.ProcessId
        << L" TID=" << h.ThreadId
        << std::endl;
}

int wmain() {
    // --- 1. Define session name ---
    const wchar_t* sessionName = L"MiniEDR-Session";

    // --- 2. Allocate properties ---
    EVENT_TRACE_PROPERTIES* props = nullptr;
    size_t propsSize = sizeof(EVENT_TRACE_PROPERTIES) + (wcslen(sessionName) + 1) * sizeof(wchar_t);
    props = (EVENT_TRACE_PROPERTIES*)malloc(propsSize);
    ZeroMemory(props, propsSize);

    props->Wnode.BufferSize = (ULONG)propsSize;
    props->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    props->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    props->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;

    // --- 3. Start the session ---
    ControlTrace(0, sessionName, props, EVENT_TRACE_CONTROL_STOP); //Control and close already existing trace
    TRACEHANDLE sessionHandle = 0;
    ULONG status = StartTrace(&sessionHandle, sessionName, props);
    if (status != ERROR_SUCCESS) {
        std::wcerr << L"StartTrace failed: " << status << std::endl;
        return 1;
    }

    // --- 4. Enable provider ---
    status = EnableTraceEx2(
        sessionHandle,
        &Microsoft_Windows_Kernel_Process,
        EVENT_CONTROL_CODE_ENABLE_PROVIDER,
        TRACE_LEVEL_INFORMATION,
        0, 0, 0,
        nullptr
    );
    if (status != ERROR_SUCCESS) {
        std::wcerr << L"EnableTraceEx2 failed: " << status << std::endl;
        ControlTrace(sessionHandle, sessionName, props, EVENT_TRACE_CONTROL_STOP);
        return 1;
    }

    // --- 5. Open the trace for consumption ---
    EVENT_TRACE_LOGFILEW logfile{};
    logfile.LoggerName = (LPWSTR)sessionName;
    logfile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    logfile.EventRecordCallback = (PEVENT_RECORD_CALLBACK)(OnEventRecord);

    TRACEHANDLE consumerHandle = OpenTraceW(&logfile);
    if (consumerHandle == INVALID_PROCESSTRACE_HANDLE) {
        std::wcerr << L"OpenTrace failed: " << GetLastError() << std::endl;
        ControlTrace(sessionHandle, sessionName, props, EVENT_TRACE_CONTROL_STOP);
        return 1;
    }

    // --- 6. Process events ---
    std::wcout << L"Listening for process events... press Ctrl+C to stop.\n";
    status = ProcessTrace(&consumerHandle, 1, nullptr, nullptr);

    // --- 7. Cleanup ---
    CloseTrace(consumerHandle);
    ControlTrace(sessionHandle, sessionName, props, EVENT_TRACE_CONTROL_STOP);

    free(props);
    return 0;
}
