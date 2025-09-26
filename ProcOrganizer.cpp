#include "ProcOrganizer.h"
int a = 0;
void ProcOrganizer::printNode(ProcessNode* node, int indent) {
    std::wcout << std::wstring(indent * 4, L' ')
        << node->data.pid << L" - " << node->data.name
        << (node->data.isAlert ? L" [ALERT]" : L"") << std::endl;

    for (ProcessNode* child : node->children) {
        printNode(child, indent + 1);
    }
}

void ProcOrganizer::addProcess(const procData& p) {
    ProcessNode* node = new ProcessNode(p);
    allNodes.push_back(node);
    ProcessNode* parent = nullptr;
    for (ProcessNode* n : allNodes) {
        if (n->data.pid == p.parentPid) {
            parent = n;
            break;
        }
    }

    if (parent) {
        parent->children.push_back(node);
    }
    else {
        roots.push_back(node); //parent process ~system
    }
}

void ProcOrganizer::printTree() {
    for (ProcessNode* root : roots) {
        printNode(root, 0);
    }
}

void ProcOrganizer::readSyslog() {
    std::wstring filename = L"SysLog" + std::to_wstring(a) + L".txt";
    std::wifstream file(filename);
    if (!file.is_open()) {
        std::wcerr << L"SysLog.txt couldn't be found " << filename << std::endl;
        return;
    }a++;

    std::wstring line;
    while (std::getline(file, line)) {
        if (line.empty()) continue;

        procData p;

        // Example line: PID=872, Parent=724, Name=services.exe
        size_t pidPos = line.find(L"PID=");
        size_t parentPos = line.find(L"Parent=");
        size_t namePos = line.find(L"Name=");

        if (pidPos == std::wstring::npos ||
            parentPos == std::wstring::npos ||
            namePos == std::wstring::npos) {
            continue;
        }

        // Extract substrings
        std::wstring pidStr = line.substr(pidPos + 4, parentPos - (pidPos + 5));
        std::wstring parentStr = line.substr(parentPos + 7, namePos - (parentPos + 8));
        std::wstring nameStr = line.substr(namePos + 5);

        // Convert numbers
        p.pid = std::stoul(pidStr);
        p.parentPid = std::stoul(parentStr);
        p.name = nameStr;

        addProcess(p); // insert into tree
    }

    file.close();
}

