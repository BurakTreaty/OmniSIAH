#include "EtwSession.h"
#include "processScanner.h"

//Mutex
#include <thread>
#include <atomic>

std::atomic<bool> etwRunning(false);
std::thread etwThread;

void runEtw(EtwSession* etw) {
    etwRunning = true;
    etw->run();   // blocking call
    etwRunning = false;
}

int wmain() {
    std::wcout << L"EDR Agent Manager ----------" << std::endl;

    EtwSession etw;
    if (!etw.enablePrivileges()) return 1;
    if (!etw.setupProvider()) return 1;
    if (!etw.setupConsumer()) {
        etw.stopAndClean();
        return 1;
    }

    int opt = 0;
    while (opt != 5) {
        std::wcout << L"\nChoose an option:\n"
            << L"1. Start ETW process monitor\n"
            << L"2. Take system snapshot\n"
            << L"3. Stop ETW\n"
            << L"4. NULL\n> "
            << L"5. Exit\n> ";
        std::wcin >> opt;

        if (opt== 1) {
            if (!etwRunning) {
                etwThread = std::thread(runEtw, &etw);
                std::wcout << L"[+] ETW process monitoring started in background thread.\n";
            }
            else {
                std::wcout << L"[!] ETW is already running.\n";
            }
        }

        if (opt ==2) {
            processScanner scanner;
            scanner.printProcesses();
        }

        if (opt == 3) {
            if (etwRunning) {
                etw.stopAndClean();
                if (etwThread.joinable()) etwThread.join();
                std::wcout << L"[+] ETW monitoring stopped.\n";
            }
            else {
                std::wcout << L"[!] ETW is not running.\n";
            }
        }

        if (opt == 4) {
            void;
        }
    }

    if (etwRunning) {
        etw.stopAndClean();
        if (etwThread.joinable()) etwThread.join();
    }

    std::wcout << L"Exiting program...\n";
    return 0;
}
