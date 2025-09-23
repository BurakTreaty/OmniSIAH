#include "libs.h"

struct ProcessNode {
    Process data;
    std::vector<ProcessNode*> children;

    ProcessNode(const Process& p) : data(p) {}

};

class ProcOrganizer {
private:
    std::vector<ProcessNode*> roots;       // root node
    std::vector<ProcessNode*> allNodes;    //free memory
    void printNode(ProcessNode* node, int indent) {
        std::wcout << std::wstring(indent * 4, L' ')
            << node->data.pid << L" - " << node->data.name
            << (node->data.isAlert ? L" [ALERT]" : L"") << std::endl;

        for (ProcessNode* child : node->children) {
            printNode(child, indent + 1);
        }
    }

public:
    ProcOrganizer() = default;
    ~ProcOrganizer() {
        for (ProcessNode* node : allNodes) delete node;
    }

    void addProcess(const Process& p) {
        ProcessNode* node = new ProcessNode(p);
        allNodes.push_back(node);

        // Find parent
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
            roots.push_back(node); // parent not found -> top-level
        }
    }

    void printTree() {
        for (ProcessNode* root : roots) {
            printNode(root, 0);
        }
    }

};
