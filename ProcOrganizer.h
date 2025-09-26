#include "libs.h"

struct procData {
    DWORD pid;
    DWORD parentPid;
    std::wstring name;
    std::wstring path;
    std::wstring commandLine;
    bool isAlert = false;
};

struct ProcessNode {
    procData data; 
    std::vector<ProcessNode*> children;
    ProcessNode(const procData& p) : data(p) {}
};

class ProcOrganizer {
private:
    std::vector<ProcessNode*> roots; 
    std::vector<ProcessNode*> allNodes;

    void printNode(ProcessNode*, int);

public:
    ProcOrganizer() = default;
    ~ProcOrganizer() {
        for (ProcessNode* node : allNodes) {
            delete node;
        }
    }

    void addProcess(const procData&);
    void printTree();
    void readSyslog();
};
