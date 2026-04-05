#include <windows.h>
#include <ntstatus.h>
#include <stdarg.h>
#include <stdio.h>
#include "utils.h"

//?==========================================================================+
//?   This file has helper functions in C used for handle based detection.   |
//?   This part is written in C instead of Go, because these APIs and        |
//?     NT structures are much more of a pain to write in Go...              |
//?==========================================================================+

// Get the global handle table via NtQuerySystemInformation. It also gets object information,
// which calls NtQueryObject. Note that this call is quite heavy, currently typically taking 1000ms.
// Caller must free returned handle table with FreeHandleTable. NULL is returned upon failure.
HANDLE_ENTRY* GetGlobalHandleTable(size_t* handleCount) {
    HANDLE_ENTRY* handleTable = NULL;
    (*handleCount) = 0;
    ULONG hiLenght = 0;
    ULONG infoSize = HANDLE_INFO_MEM_BLOCK;

    NQSI NtQuerySystemInformation = (NQSI)GetProcAddress(GetModuleHandle("ntdll"), "NtQuerySystemInformation");
    PSYSTEM_HANDLE_INFORMATION handleTableInformation = (PSYSTEM_HANDLE_INFORMATION)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, infoSize);
    NTSTATUS status = NtQuerySystemInformation(SystemHandleInformation, handleTableInformation, infoSize, &hiLenght);
    if (status == STATUS_INFO_LENGTH_MISMATCH) {
        while (status == STATUS_INFO_LENGTH_MISMATCH) {
            HeapFree(GetProcessHeap(), 0, handleTableInformation);
            infoSize += HANDLE_INFO_MEM_BLOCK;
            if (infoSize > 10000000) return NULL; // avoid infinite loop with 10MB limit
            handleTableInformation = (PSYSTEM_HANDLE_INFORMATION)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, infoSize);
            status = NtQuerySystemInformation(SystemHandleInformation, handleTableInformation, infoSize, &hiLenght);
        }
    } else if (status != STATUS_SUCCESS) {
        printf("failed to query system information, status: %X\n", status);
        HeapFree(GetProcessHeap(), 0, handleTableInformation);
        return NULL;
    }

    for (int i = 0; i < handleTableInformation->NumberOfHandles; i++) {
        SYSTEM_HANDLE_TABLE_ENTRY_INFO handleInfo = handleTableInformation->Handles[i];

        HANDLE hProcess = OpenProcess(PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
            FALSE, handleInfo.UniqueProcessId);
        if (hProcess == NULL) {
            continue;
        }

        HANDLE hObject = NULL;
        // Handles are just indexes to per-process handle table. Thats why you need to duplicate, so you can pass to NtQueryObject.
        //TODO: what are the minimum required access rights?
        if (!DuplicateHandle(hProcess, (HANDLE)(DWORD_PTR)handleInfo.HandleValue, GetCurrentProcess(),
                &hObject, STANDARD_RIGHTS_REQUIRED | GENERIC_READ, FALSE, 0)) {
            DWORD err = GetLastError();
            if (err != ERROR_ACCESS_DENIED && err != ERROR_NOT_SUPPORTED && err != ERROR_INVALID_HANDLE) {
                printf("Failed to duplicate handle, error: %d\n", err);
            }
            CloseHandle(hProcess);
            continue;
        }
        CloseHandle(hProcess);

        //* create HANDLE_ENTRY
        handleTable = (HANDLE_ENTRY*)realloc(handleTable, ((*handleCount) + 1) * sizeof(HANDLE_ENTRY));
        if (handleTable == NULL) {
            printf("[CRITICAL] Failed to realloc (%dB)\n", ((*handleCount) + 1) * sizeof(HANDLE_ENTRY));
        }

        handleTable[*handleCount].Type   = GetHandleObjectType(hObject);
        handleTable[*handleCount].Pid    = handleInfo.UniqueProcessId;
        handleTable[*handleCount].Access = handleInfo.GrantedAccess;
        handleTable[*handleCount].Handle = (DWORD)handleInfo.HandleValue;
        handleTable[*handleCount].Params = GetHandleParameters(hObject, handleTable[*handleCount].Type, &handleTable[*handleCount].paramsSize);
        CloseHandle(hObject);
        (*handleCount)++;
    }
    HeapFree(GetProcessHeap(), 0, handleTableInformation);
    return handleTable;
}

// Get packet parameters for a handle event. Remember to free buffer after use.
BYTE* GetHandleParameters(HANDLE hObject, DWORD objectType, size_t* paramsSize) {
    BYTE* parameters = NULL;
    switch (objectType) {
        case TYPE_PROCESS: {
        // owning process pid
            DWORD pid = GetProcessId(hObject);
            size_t pidParamSize;
            BYTE* pidParam = BuildParameter(&pidParamSize, PARAMETER_UINT32, "Pid", pid);
        // owning process path
            char path[1026];
            DWORD pathLen = 1026;
            size_t pathParamSize;
            BYTE* pathParam = NULL;
            BOOL ok = QueryFullProcessImageNameA(hObject, 0, path, &pathLen);
            if (!ok) {
                printf("[dbg] failed to get process %d path (%d)\n", pid, GetLastError());
                pathParamSize = 0;
            } else {
                pathParam = BuildParameter(&pathParamSize, PARAMETER_ANSISTRING, "ImagePath", path);
            }

            // construct parameter buffer
            parameters = (BYTE*)malloc(pidParamSize + pathParamSize);
            memcpy(parameters, pidParam, pidParamSize);
            if (pathParamSize > 0) {
                memcpy(parameters + pidParamSize, pathParam, pathParamSize);
                free(pathParam);
            }
            free(pidParam);
            *paramsSize = pidParamSize + pathParamSize;
            break;
        }
        case TYPE_THREAD: {
        // thread id
            DWORD tid = GetThreadId(hObject);
            size_t tidParamSize;
            BYTE* tidParam = BuildParameter(&tidParamSize, PARAMETER_UINT32, "Tid", tid);
        // owning process pid
            DWORD pid = GetProcessIdOfThread(hObject);
            size_t pidParamSize;
            BYTE* pidParam = BuildParameter(&pidParamSize, PARAMETER_UINT32, "Pid", pid);
        
            parameters = (BYTE*)malloc(tidParamSize + pidParamSize);
            memcpy(parameters, tidParam, tidParamSize);
            memcpy(parameters + pidParamSize, pidParam, pidParamSize);
            free(tidParam);
            free(pidParam);
            *paramsSize = pidParamSize + tidParamSize;
            break;
        }
        /*// owning process path
            char path[MAX_PATH];
            DWORD pathLen;
            BOOL ok = QueryFullProcessImageNameA(hObject, 0, path, &pathLen);
            //TODO: create parameter
            break;
        case TYPE_TOKEN:
        // owning process
        // access rights or something like that
            break;*/
    }
    return parameters;
}


void FreeHandleTable(HANDLE_ENTRY* handleTable, size_t handleCount) {
    /*for (size_t i = 0; i < handleCount; i++) {
        CloseHandle(handleTable.handle);
    }*/
    free(handleTable);
}

DWORD GetHandleObjectType(HANDLE hObject) {
    if (NtQueryObject == NULL) {
        NtQueryObject = (NQO)GetProcAddress(GetModuleHandle("ntdll"), "NtQueryObject");
    }
    DWORD bufSize = sizeof(PUBLIC_OBJECT_TYPE_INFORMATION);
    PUBLIC_OBJECT_TYPE_INFORMATION* typeInfo = (PUBLIC_OBJECT_TYPE_INFORMATION*)malloc(bufSize);
    NTSTATUS status = NtQueryObject(hObject, ObjectTypeInformation, (PVOID)typeInfo, bufSize, &bufSize);
    if ((status == STATUS_BUFFER_OVERFLOW) || (status == STATUS_INFO_LENGTH_MISMATCH)) {
        typeInfo = (PUBLIC_OBJECT_TYPE_INFORMATION*)realloc(typeInfo, bufSize);
        if (typeInfo == NULL) {
            printf("Failed to realloc (%dB)\n", bufSize);
            free(typeInfo);
            return TYPE_UNKNOWN;
        }
        status = NtQueryObject(hObject, ObjectTypeInformation, (PVOID)typeInfo, bufSize, &bufSize);
    }
    if ((status != STATUS_SUCCESS) || (typeInfo->TypeName.Buffer == NULL) || (typeInfo->TypeName.Length == 0)) {
        printf("Failed to get object type (status %X)\n", status);
        free(typeInfo);
        return TYPE_UNKNOWN;
    }

    DWORD type = TYPE_UNKNOWN;
    if (wcscmp(typeInfo->TypeName.Buffer, L"Process") == 0) {
        type = TYPE_PROCESS;
    }
    if (wcscmp(typeInfo->TypeName.Buffer, L"Thread") == 0) {
        type = TYPE_THREAD;
    }
    if (wcscmp(typeInfo->TypeName.Buffer, L"Token") == 0) {
        type = TYPE_TOKEN;
    }
    if (wcscmp(typeInfo->TypeName.Buffer, L"Device") == 0) {
        type = TYPE_DEVICE;
    }
    if (wcscmp(typeInfo->TypeName.Buffer, L"Desktop") == 0) {
        type = TYPE_DESKTOP;
    }
    if (wcscmp(typeInfo->TypeName.Buffer, L"Driver") == 0) {
        type = TYPE_DRIVER;
    }
    if (wcscmp(typeInfo->TypeName.Buffer, L"TpWorkerFactory") == 0) {
        type = TYPE_DESKTOP;
    }

    //TODO: Section
    //TODO: DebugObject
    //TODO: Event
    //TODO: Directory
    //TODO: File
    //TODO: Semaphore
    //TODO: Key
    //TODO: SymbolicLink

    free(typeInfo);
    return type;
}

// Create string header for parameter
BYTE* CreateParameter(char* name, DWORD size, DWORD type, size_t* dataSize) {
    if (size > 50000) return NULL;
    // data size will also work as a counter for how much memory to allocate
    (*dataSize) = strlen(name) + 2; // +2 is for the symbol and the null-terminator at the end.

    size_t sizeStrLen;
    if (size > 0) {    
        // get the amount of characters it takes to represent size
        sizeStrLen = snprintf(NULL, 0, "%d", size);
        (*dataSize) += 1; // for the "/"
    } else {
        sizeStrLen = 0;
    }
    (*dataSize) += sizeStrLen;

    char symbol;
    switch (type) {
        case PARAMETER_ANSISTRING:
            symbol = 's'; break;
        case PARAMETER_UINT32:
            symbol = 'd'; break;
        case PARAMETER_UINT64:
            symbol = 'q'; break;
        case PARAMETER_POINTER:
            symbol = 'p'; break;
        case PARAMETER_BOOLEAN:
            symbol = 'b'; break;
        case PARAMETER_BYTES: 
            symbol = 'x'; break;
        default: return NULL;
    }
    
    BYTE* packet = (BYTE*)malloc((*dataSize));
    if (packet == NULL) return NULL;

    if (sizeStrLen == 0) {
        snprintf((char*)packet, (*dataSize), "%c%s", symbol, name);
    } else {
        snprintf((char*)packet, (*dataSize), "%c%s/%d", symbol, name, size);
    }
    //printf("\n[debug] parameter packet: %s\n", (char*)packet);
    return packet;
}


BYTE* BuildParameter(size_t* totalSize, DWORD type, const char* name, ...) {
    va_list args;
    va_start(args, name);

    // Determine value pointer and size based on type
    const void* value = NULL;
    DWORD valueSize = 0;

    switch (type) {
        case PARAMETER_UINT32: {
            // va_arg promotes to int, so we capture then take address
            static DWORD tmp; // static so pointer remains valid briefly
            tmp = (DWORD)va_arg(args, unsigned int);
            value = &tmp;
            valueSize = sizeof(DWORD);
            break;
        }
        case PARAMETER_UINT64: {
            static UINT64 tmp;
            tmp = va_arg(args, UINT64);
            value = &tmp;
            valueSize = sizeof(UINT64);
            break;
        }
        case PARAMETER_POINTER: {
            static void* tmp;
            tmp = va_arg(args, void*);
            value = &tmp;
            valueSize = sizeof(void*);
            break;
        }
        case PARAMETER_BOOLEAN: {
            static BYTE tmp;
            tmp = (BYTE)va_arg(args, int);
            value = &tmp;
            valueSize = sizeof(BYTE);
            break;
        }
        case PARAMETER_ANSISTRING: {
            value = va_arg(args, const char*);
            valueSize = (DWORD)(strlen((const char*)value) + 1); // include null
            break;
        }
        case PARAMETER_BYTES: {
            value = va_arg(args, const void*);
            valueSize = va_arg(args, DWORD); // bytes type needs explicit size
            break;
        }
        default:
            va_end(args);
            return NULL;
    }
    va_end(args);

    // For fixed-size types, size is inferrable so pass 0; for bytes pass valueSize
    DWORD headerSize = (type == PARAMETER_BYTES) ? valueSize : 0;

    size_t headerLen = 0;
    BYTE* header = CreateParameter((char*)name, headerSize, type, &headerLen);
    if (!header) return NULL;

    // Layout: [header bytes (includes null terminator)] [raw value]
    *totalSize = headerLen + valueSize;
    BYTE* buf = (BYTE*)malloc(*totalSize);
    if (!buf) { free(header); return NULL; }

    memcpy(buf, header, headerLen);               // copy header (null terminator included)
    memcpy(buf + headerLen, value, valueSize);     // append raw value

    free(header);
    return buf;
}
