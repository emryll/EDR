#include <windows.h>
#include <stdio.h>
#include "utils.h"

// Caller must free returned handle table with FreeHandleTable. NULL is returned upon failure.
HANDLE_ENTRY* GetGlobalHandleTable(int* handleCount) {
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

        handleTable[*handleCount].type   = GetHandleObjectType(hObject);
        handleTable[*handleCount].pid    = handleInfo.UniqueProcessId;
        handleTable[*handleCount].access = handleInfo.GrantedAccess;
        handleTable[*handleCount].handle = hObject;
        (*handleCount)++;
    }
    HeapFree(GetProcessHeap(), 0, handleTableInformation);
    return handleTable;
}

void FreeHandleTable(HANDLE_ENTRY* handleTable, int handleCount) {
    for (int i = 0; i < handleCount; i++) {
        CloseHandle(handleTable.handle);
    }
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