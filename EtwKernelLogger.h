#pragma once
#include "EventTypes.h"

class EtwKernelLogger {
private:
    TRACEHANDLE sessionHandle;
    TRACEHANDLE consumerHandle;
    EVENT_TRACE_PROPERTIES* props;

    static std::wstring GetErrorMessage(DWORD code);
    static bool EnablePrivilege(LPCWSTR privName);

    // Callback must be static so ETW can call it without an instance pointer
    static VOID WINAPI OnEventRecord(PEVENT_RECORD record);

public:
    EtwKernelLogger();
    ~EtwKernelLogger();

    bool EnablePrivileges();
    bool SetupProvider();
    bool SetupConsumer();
    void Run();
    void StopAndClean();
};
