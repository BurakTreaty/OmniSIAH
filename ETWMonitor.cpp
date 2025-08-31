#include "ETWMonitor.h"

ETWMonitor* ETWMonitor::instance = nullptr;

ETWMonitor::ETWMonitor() {
    instance = this;
}

ETWMonitor::~ETWMonitor() {
    Stop();
}