#pragma once
#include "EventTypes.h"

using eventCallBack = std::function<void(PEVENT_RECORD)>;

class ETWMonitor
{
private:
    std::wstring sessionName_;
    eventCallBack userCallback_;

    TRACEHANDLE controllerHandle_;   // session handle returned by StartTrace
    TRACEHANDLE consumerTraceHandle_; // handle returned by OpenTrace

    std::atomic_bool running_;
    std::thread consumerThread_;

    EVENT_TRACE_PROPERTIES* AllocateTraceProperties(const std::wstring& sessionName, size_t extraBytes = 0);

    void WINAPI EventRecordCallbackStatic(PEVENT_RECORD pEvent);
    void OnEvent(PEVENT_RECORD pEvent);

public:
	ETWMonitor();
	~ETWMonitor();
    bool StartKernelSession(const std::wstring& sessionName, ULONG enableFlags);

    bool StartSession(const std::wstring& sessionName);

    bool EnableProvider(const GUID& providerGuid,
        UCHAR level = TRACE_LEVEL_INFORMATION,
        ULONGLONG matchAnyKeyword = 0,
        ULONGLONG matchAllKeyword = 0);

    bool StartConsumer(const std::wstring& sessionName, eventCallBack cb);

    void Stop();

};

