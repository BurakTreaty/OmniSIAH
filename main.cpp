#include "EtwKernelLogger.h"

int wmain() {
    std::wcout << L"EDR Agent Manager----------"<<std::endl;
    int opt = 0;
    while (opt != 4) {
        std::wcout  << L"Choose an option:" << std::endl;
        std::cin >> opt;
        if (opt == 1) { void; }
        if (opt == 2) { void; }
        if (opt == 3) { void; }
        if (opt == 4) { void; }
    }
    

    EtwKernelLogger etw;
    if (!etw.EnablePrivileges()) return 1;
    if (!etw.SetupProvider()) return 1;
    if (!etw.SetupConsumer()) {
        etw.StopAndClean();
        return 1;
    }

    etw.Run();
    return 0;
}
