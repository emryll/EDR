#include <unordered_set>
#include <windows.h>
#include "etw.h"

static std::unordered_set<DWORD> processes;

extern "C" {
    void TrackProcess(DWORD pid) {
        processes.insert(pid);
    }

    BOOL IsTracked(DWORD pid) {
        return processes.find(pid) != processes.end();
    }

    void UntrackProcess(DWORD pid) {
        processes.erase(pid);
    }
}