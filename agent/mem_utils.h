#ifndef MEMUTILS_H
#define MEMUTILS_H

#include <windows.h>
#include <stdint.h>

typedef struct {
    void* address;
    size_t size;
} MEMORY_REGION;

typedef struct {
    char name[MAX_PATH];
    size_t         numSections;
    MEMORY_REGION* sections;
} REMOTE_MODULE;

//FILE* OpenLog(char*);
//void Log(const char*, ...);

uint8_t* GetModuleText(HANDLE, size_t*);
uint8_t* ReadProcessMemoryEx(HANDLE, LPVOID, size_t, size_t*);
MEMORY_REGION* GetRWXMemory(HANDLE, size_t*);
MEMORY_REGION* GetAllMemoryRegions(HANDLE, size_t*);
MEMORY_REGION* GetAllSectionsOfModule(HANDLE, char*, size_t*);
REMOTE_MODULE* GetAllSectionsOfProcess(HANDLE, size_t*);
void FreeRemoteModuleArray(REMOTE_MODULE*, size_t);

#endif
