#include "libs.h"


class processScanner {
private:
    HANDLE hProcessSnap;
    PROCESSENTRY32 pe32;

public:
    processScanner();
    ~processScanner();
    void dumpRunningProcesses();
};