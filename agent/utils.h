#ifndef UTILS_H
#define UTILS_H

#define DLL_NAME "hook.dll"

// thread scan returns threads in this structure
typedef struct {
    DWORD tid;
    DWORD pid;
    LPVOID startAddress;
} THREAD_ENTRY;

int InjectDll(DWORD);
void FreePaths(char***, size_t);
uint8_t* ReadFile2(char*, size_t*);

#endif
