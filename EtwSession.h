#include "Libs.h"
class EtwSession {
private:
    TRACEHANDLE sessionHandle;
    TRACEHANDLE consumerHandle;
    EVENT_TRACE_PROPERTIES* props;

    static std::wstring getErrorMessage(DWORD code);
    static bool enablePrivilege(LPCWSTR privName);

    // Callback must be static so ETW can call it without an instance pointer
    static VOID WINAPI onEventRecord(PEVENT_RECORD record);

public:
    EtwSession();
    ~EtwSession();
    bool enablePrivileges();
    bool setupProvider();
    bool setupConsumer();
    void run();
    void stopAndClean();
};
