#include <windows.h>
#include <stdio.h>
#include "etw.h"

HANDLE hCmd = INVALID_HANDLE_VALUE;
HANDLE hEtw = INVALID_HANDLE_VALUE;

void ShutdownWaiter() {
    while(1) {
        ETW_CMD packet;
        BOOL ok = ReadFull(hCmd, &packet, sizeof(packet));
        if (!ok) {
            printf("[debug] failed to read from pipe, error: %d\n", GetLastError());
            break;
        }
        switch (packet.type) {
        case ETW_CMD_SHUTDOWN:
            //* shut down etw session
            if (SessionHandle) {
                EVENT_TRACE_PROPERTIES props = {0};
                props.Wnode.BufferSize = sizeof(props);
                ControlTrace(SessionHandle, SESSION_NAME, &props, EVENT_TRACE_CONTROL_STOP);
            }
            
            if (traceHandle != 0 && traceHandle != INVALID_PROCESSTRACE_HANDLE) {
                CloseTrace(traceHandle);
            }
            
            free(SessionProperties);
            CloseHandle(hEtw);
            CloseHandle(hCmd);
            return;
        // c cases arent a new scope but just a "go-to", so you have to add these braces
        // to make it its own scope, alternative is to declare processList above.
        case ETW_CMD_PLIST_ADD: {
            DWORD* processList = (DWORD*)malloc(packet.dataSize);    
            ok = ReadFull(hCmd, processList, packet.dataSize);
            if (!ok) {
                printf("[debug] Failed to read tracked process list from pipe, error: %d\n", GetLastError());
                break;
            }
            //* add them to a global map
            for (size_t i = 0; i < (packet.dataSize / sizeof(DWORD)); i++) {
                TrackProcess(processList[i]);
            }
            free(processList);
            break;
        }
        case ETW_CMD_PLIST_REMOVE: {
            DWORD* processList = (DWORD*)malloc(packet.dataSize);    
            ok = ReadFull(hCmd, processList, packet.dataSize);
            if (!ok) {
                printf("[debug] Failed to read tracked process list from pipe, error: %d\n", GetLastError());
                break;
            }
            //* add them to a global map
            for (size_t i = 0; i < (packet.dataSize / sizeof(DWORD)); i++) {
                UntrackProcess(processList[i]);
            }
            free(processList);
            break;
        }
        }
    }
}

// 
BOOL InitializeComms() {
    //TODO: add ACL to pipe comms. elevated processes only.

    hEtw = CreateFile(
        ETW_PIPE_NAME, GENERIC_WRITE,
        0, NULL, OPEN_EXISTING, 0, NULL);

    hCmd = CreateFile(
        COMMANDS_PIPE_NAME, GENERIC_READ,
        0, NULL, OPEN_EXISTING, 0, NULL);

    // it will keep trying until it works.    
    while (hCmd == INVALID_HANDLE_VALUE || hEtw == INVALID_HANDLE_VALUE) {
        Sleep(500);
        if (hEtw == INVALID_HANDLE_VALUE) {
            printf("Failed to connect to cmd pipe, error: %d\n", GetLastError());
            hEtw = CreateFile(
                ETW_PIPE_NAME, GENERIC_WRITE,
                0, NULL, OPEN_EXISTING, 0, NULL);
        }
        if (hCmd == INVALID_HANDLE_VALUE) {
            printf("Failed to connect to ETW pipe, error: %d\n", GetLastError());
            hCmd = CreateFile(
                COMMANDS_PIPE_NAME, GENERIC_READ,
                0, NULL, OPEN_EXISTING, 0, NULL);
        }
    }

    printf("[debug] Both pipes connected\n");

    // create thread to receive shutdown signal
    HANDLE WaiterThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)ShutdownWaiter, NULL, 0, NULL);
    if (WaiterThread == NULL) {
        CloseHandle(hCmd);
        CloseHandle(hEtw);
        hEtw = NULL; hCmd = NULL;
        return FALSE;
    }
    return TRUE;
}

BOOL ReadFull(HANDLE pipe, void* buffer, DWORD size) {
    DWORD totalRead = 0;
    while (totalRead < size) {
        DWORD bytesRead = 0;
        if (!ReadFile(pipe, (LPVOID)((ULONG_PTR)buffer + (ULONG_PTR)totalRead), size - totalRead, &bytesRead, NULL)) {
            if (GetLastError() == ERROR_MORE_DATA) {
                totalRead += bytesRead;
                continue;
            }
            return FALSE;
        }
        
        // pipe closed (?)
        if (bytesRead == 0) {
            return FALSE;
        }
        totalRead += bytesRead;
    }
    return TRUE;
}