#include <windows.h>
#include <winnt.h>
#include <evntcons.h>
#include <evntrace.h>
#include <stdio.h>
#include "etw.h"

//?==================================================================================+
//?  This is the ETW consumer for the agent. This runs in a seperate process,        |
//?  and forwards the received events as telemetry packets to the agent via IPC.     |
//?  This should be ran as a service, so it will automatically respawn if shutdown.  |
//?==================================================================================+


BOOL DEBUG_BUILD = TRUE;
char SESSION_NAME[] = "gs_";

BOOL singlePid = TRUE;
DWORD pid = 0;

TRACEHANDLE SessionHandle = 0;
TRACEHANDLE traceHandle = 0;
EVENT_TRACE_PROPERTIES* SessionProperties = {0};

BOOL Running = TRUE;
BOOL trackAny = FALSE;

// Stop the session on keyboard interrupt (only for debug versions)
BOOL WINAPI CtrlHandler(DWORD fdwCtrlType) {
    if (fdwCtrlType == CTRL_C_EVENT || fdwCtrlType == CTRL_CLOSE_EVENT) {
        printf("\nStopping trace session...\n");

        Running = FALSE;

        // Stop logger
        if (SessionHandle) {
            EVENT_TRACE_PROPERTIES props = {0};
            props.Wnode.BufferSize = sizeof(props);
            ControlTrace(SessionHandle, SESSION_NAME, &props, EVENT_TRACE_CONTROL_STOP);
        }
        
        if (traceHandle != 0 && traceHandle != INVALID_PROCESSTRACE_HANDLE) {
            CloseTrace(traceHandle);
        }
        return TRUE;
    }
    return FALSE;
}

void EnableProviders() {
    //*================[ File System Events ]=========================
 
    ULONG64 fileKeywords = 
        //KERNEL_FILE_KEYWORD_FILEIO |  // required base for most events
        KERNEL_FILE_KEYWORD_FILENAME |  // path resolution
        KERNEL_FILE_KEYWORD_CREATE |    // file create
        KERNEL_FILE_KEYWORD_WRITE |     // file write
        KERNEL_FILE_KEYWORD_DELETE_PATH |         // delete
        KERNEL_FILE_KEYWORD_RENAME_SETLINK_PATH | // rename
        KERNEL_FILE_KEYWORD_CREATE_NEW_FILE;      // new file creation

    /*if (!g_LightweightMode)  {
        fileKeywords |= KERNEL_FILE_KEYWORD_READ;
    }*/

    status = EnableTraceEx2(SessionHandle, &FileProviderGuid,
        EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_INFORMATION, fileKeywords, 0, 0, NULL);
    if (status != ERROR_SUCCESS) {
        printf("WARNING: Failed to enable File provider (error %lu)\n", status);
    }
    
    //*========================[ Registry Events ]========================
 
    ULONG regKeywords = 
        KERNEL_REGISTRY_KEYWORD_CREATE_KEY |
        KERNEL_REGISTRY_KEYWORD_DELETE_KEY |
        KERNEL_REGISTRY_KEYWORD_SET_VALUE |
        KERNEL_REGISTRY_KEYWORD_DELETE_VALUE |
        KERNEL_REGISTRY_KEYWORD_SET_INFORMATION |
        KERNEL_REGISTRY_KEYWORD_SET_SECURITY;

    status = EnableTraceEx2(SessionHandle, &RegistryProviderGuid,
        EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_INFORMATION, regKeywords, 0, 0, NULL);
    if (status != ERROR_SUCCESS) {
        printf("WARNING: Failed to enable Registry provider (error %lu)\n", status);
    }

    //*=========================[ Process Events ]=========================

    ULONG procKeywords =
        WINEVENT_KEYWORD_PROCESS |
        WINEVENT_KEYWORD_THREAD;

    status = EnableTraceEx2(SessionHandle, &ProcessProviderGuid,
        EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_INFORMATION, procKeywords, 0, 0, NULL);
    if (status != ERROR_SUCCESS) {
        printf("WARNING: Failed to enable Microsoft-Windows-Kernel-Process provider (error %lu)\n", status);
    } 

/*
? This one can't be used because Microsoft are greedy little pricks
    status = EnableTraceEx2(SessionHandle, &ThreatIntelGuid,
        EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_INFORMATION, 0, 0, 0, NULL);
    if (status != ERROR_SUCCESS) {
        printf("WARNING: Failed to enable Threat Intelligence provider (error %lu)\n", status);
    } 
*/
}

// The ETW consumer is started here
int main(int argc, char** argv) {
    if (!IsAdmin()) {
        printf("You must have elevated privileges to use ETW.\n");
        return 1;
    }

    if (argc >= 2) {
        for (int i = 1; i < argc; i++) {
          pid = atoi(argv[i]);
          TrackProcess(pid);
          printf("Started tracking process %d\n", pid);
        }
    } else {
        trackAny = TRUE;
    }

    BOOL ok = InitializeComms();
    if (!ok) {
        printf("[!] failed to initialize comms\n");
        return 1;
    }

    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        printf("failed to open process token, error code: %d\n", GetLastError());
        return 1;
    }
    LUID luid;
    if (!LookupPrivilegeValueA(NULL, "SeSystemProfilePrivilege", &luid)) {
        printf("failed to lookup privilege value, error code: %d\n", GetLastError());
        return 1;
    }
    TOKEN_PRIVILEGES tp;
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL)) {
        printf("failed to enable SeSystemProfilePrivilege, error code: %d\n", GetLastError());
        return 1;
    } else {
        printf("enabled SeSystemProfilePrivilege\n");
    }

    // set up ctrl+c to end session
    SetConsoleCtrlHandler(CtrlHandler, TRUE);

    // set up session properties
    // EVENT_TRACE_PROPERTIES is dynamically sized so you cant use stack or it will overflow
    ULONG bufferSize = sizeof(EVENT_TRACE_PROPERTIES) + (strlen(SESSION_NAME) + 1);
    SessionProperties = (EVENT_TRACE_PROPERTIES*)malloc(bufferSize);
    if (!SessionProperties) {
        printf("ERROR: Failed to allocate memory.\n");
        return 1;
    }

    ZeroMemory(SessionProperties, bufferSize);
    SessionProperties->Wnode.BufferSize = bufferSize;
    SessionProperties->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    SessionProperties->Wnode.ClientContext = 1; // QPC clock resolution
    //SessionProperties->Wnode.Guid = FileProviderGuid;
    SessionProperties->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    SessionProperties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    
    EnableProviders();

    EVENT_TRACE_LOGFILE traceFile = {0};
    traceFile.LoggerName = SESSION_NAME;
    traceFile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    traceFile.EventRecordCallback = EventCallback;
    
    traceHandle = OpenTrace(&traceFile);
    if (traceHandle == INVALID_PROCESSTRACE_HANDLE) {
        printf("ERROR: OpenTrace failed with error %lu\n", GetLastError());
        ControlTrace(SessionHandle, SESSION_NAME, SessionProperties, EVENT_TRACE_CONTROL_STOP);
        free(SessionProperties);
        return 1;
    }
    // stop any existing session of same name
    ControlTrace(0, SESSION_NAME, SessionProperties, EVENT_TRACE_CONTROL_STOP);

    if (InitQueue(&g_CriticalQueue, CRITICAL_QUEUE_SIZE) != SUCCESS) {
        printf("[dbg] failed to init queue\n");
    }
    if (InitQueue(&g_StandardQueue, STANDARD_QUEUE_SIZE) != SUCCESS) {
        printf("[dbg] failed to init queue\n");
    }

    // start trace session
    ULONG status = StartTrace(&SessionHandle, SESSION_NAME, SessionProperties);
    if (status != ERROR_SUCCESS) {
        printf("Failed to start ETW tracing session, error %lu\n", status);
        free(SessionProperties);
        return 1;
    }

    // Process events (blocks until stopped)
    status = ProcessTrace(&traceHandle, 1, NULL, NULL);
    if (status != ERROR_CANCELLED && status != ERROR_SUCCESS) {
        printf("ERROR: ProcessTrace failed with error %lu\n", status);
    }

    return 0;
}
