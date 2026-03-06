#include <windows.h>
#include <stdio.h>
#include <evntrace.h>
#include <evntcons.h>
#include <tdh.h>
#include <winnt.h>
#include "etw.h"

//?==================================================================================+
//?  This is the ETW consumer for the agent. This runs in a seperate process,        |
//?  and forwards the received events as telemetry packets to the agent via IPC.     |
//?  This should be ran as a service, so it will automatically respawn if shutdown.  |
//?==================================================================================+

BOOL singlePid = TRUE;
DWORD pid = 0;

// Microsoft-Windows-Kernel-File {EDD08927-9CC4-4E65-B970-C2560FB5C289}
GUID FileProviderGuid = { 0xEDD08927, 0x9CC4, 0x4E65, { 0xB9, 0x70, 0xC2, 0x56, 0x0F, 0xB5, 0xC2, 0x89 } };

// Microsoft-Windows-Kernel-Registry {70EB4F03-C1DE-4F73-A051-33D13D5413BD}
GUID RegistryProviderGuid = { 0x70EB4F03, 0xC1DE, 0x4F73, { 0xA0, 0x51, 0x33, 0xD1, 0x3D, 0x54, 0x13, 0xBD } };

// Microsoft-Windows-Kernel-Process {22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}
GUID ProcessProviderGuid = {0x22FB2CD6, 0x0E7B, 0x422B, { 0xA0, 0xC7, 0x2F, 0xAD, 0x1F, 0xD0, 0xE7, 0x16}};

// Microsoft-Windows-Threat-Intelligence {F4E1897C-BB5D-5668-F1D8-040F4D8DD344}
GUID ThreatIntelGuid = {0xF4E1897C, 0xBB5D, 0x5668, {0xF1, 0xD8, 0x04, 0x0F, 0x4D, 0x8D, 0xD3, 0x44}}; 


TRACEHANDLE SessionHandle = 0;
TRACEHANDLE traceHandle = 0;
EVENT_TRACE_PROPERTIES* SessionProperties = {0};

BOOL Running = TRUE;
BOOL trackAny = FALSE;


VOID WINAPI EventCallback(PEVENT_RECORD event) {
    if (!trackAny && !IsTracked(event->EventHeader.ProcessId)) {
        return;
    }

    SYSTEMTIME st;
    FILETIME ft;
    ft.dwLowDateTime = event->EventHeader.TimeStamp.LowPart;
    ft.dwHighDateTime = event->EventHeader.TimeStamp.HighPart;
    FileTimeToSystemTime(&ft, &st);
/*
    LPCSTR stars = "*********************************************************************";
    printf("\n%s\n", stars);
    printf("[%02d:%02d:%02d.%03d] ", st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
*/
    // check which provider
    if (IsEqualGUID(event->EventHeader.ProviderId, FileProviderGuid)) {
        switch (event->EventHeader.EventDescriptor.Id) {    
            case EVENT_FILE_CREATE:
            printf("FILE CREATE EVENT (%d), PID: %lu\n",
                event->EventHeader.EventDescriptor.Id, event->EventHeader.ProcessId);
                break;
            case EVENT_FILE_DELETE:
            printf("FILE DELETE EVENT (%d), PID: %lu\n",
                event->EventHeader.EventDescriptor.Id, event->EventHeader.ProcessId);
                break;
            case EVENT_FILE_READ:
            printf("FILE READ EVENT (%d), PID: %lu\n",
                event->EventHeader.EventDescriptor.Id, event->EventHeader.ProcessId);
                break;
            case EVENT_FILE_WRITE:
            printf("FILE WRITE EVENT (%d), PID: %lu\n",
                event->EventHeader.EventDescriptor.Id, event->EventHeader.ProcessId);
                break;
            case EVENT_FILE_RENAME:
            printf("FILE WRITE EVENT (%d), PID: %lu\n",
                event->EventHeader.EventDescriptor.Id, event->EventHeader.ProcessId);
                break;
            default:
            printf("UNKNOWN FILE EVENT (%d), PID: %lu\n",
                event->EventHeader.EventDescriptor.Id, event->EventHeader.ProcessId);
                break;
        }
        //* create telemetry packet and send it to agent
        size_t dataSize;
        BYTE* dataPacket = CreateFileEventPacket(event, &dataSize);
        int result = SendEtwTelemetryPacket(event, dataPacket, dataSize, TM_TYPE_ETW_FILE);
        if (result != 0) {
            printf("[debug] Failed to send file event packet, error: %d\n", result);
        }
    } else if (IsEqualGUID(event->EventHeader.ProviderId, RegistryProviderGuid)) {
        switch (event->EventHeader.EventDescriptor.Id) {    
            case EVENT_REG_CREATE_KEY:
            printf("REGISTRY CREATE KEY EVENT (%d), PID: %lu\n",
                event->EventHeader.EventDescriptor.Id, event->EventHeader.ProcessId);
                break;
            case EVENT_REG_DELETE_KEY:
            printf("REGISTRY DELETE KEY EVENT (%d), PID: %lu\n",
                event->EventHeader.EventDescriptor.Id, event->EventHeader.ProcessId);
                break;
            case EVENT_REG_SET_KEY_VALUE:
            printf("REGISTRY SET KEY EVENT (%d), PID: %lu\n",
                event->EventHeader.EventDescriptor.Id, event->EventHeader.ProcessId);
                break;
            default:
            printf("UNKNOWN REGISTRY EVENT (%d), PID: %lu\n",
                event->EventHeader.EventDescriptor.Id, event->EventHeader.ProcessId);
        }
        size_t dataSize;
        BYTE* dataPacket = CreateRegistryEventPacket(event, &dataSize);
        int result = SendEtwTelemetryPacket(event, dataPacket, dataSize, TM_TYPE_ETW_REG);
        if (result != 0) {
            printf("[debug] Failed to send registry event packet, error: %d\n", result);
        }
    } else if (IsEqualGUID(event->EventHeader.ProviderId, ProcessProviderGuid)) {
        switch (event->EventHeader.EventDescriptor.Id) {
            case 1:
            printf("PROCESS CREATE EVENT, PID: %lu\n",
            event->EventHeader.EventDescriptor.Id, event->EventHeader.ProcessId);
            break;
        }
    }

    //printf("\n%s\n", stars);
}


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


int main(int argc, char** argv) {
    if (!IsAdmin()) {
        printf("You must have elevated privileges to use ETW.\n");
        return 1;
    }

    if (argc >= 2) {
        pid = atoi(argv[1]);
        TrackProcess(pid);
        printf("Started tracking process %d\n", pid);
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

    printf("[debug] sizeof(FILE_EVENT): %d\n", sizeof(FILE_EVENT));
    printf("[debug] sizeof(REG_EVENT): %d\n", sizeof(REG_EVENT));
    printf("[debug] sizeof(TELEMETRY_HEADER): %d\n", sizeof(TELEMETRY_HEADER));
    printf("[debug] sizeof(PARAMETER): %d\n", sizeof(PARAMETER));

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
    
    // stop any existing session of same name
    ControlTrace(0, SESSION_NAME, SessionProperties, EVENT_TRACE_CONTROL_STOP);

    // start trace session
    ULONG status = StartTrace(&SessionHandle, SESSION_NAME, SessionProperties);
    if (status != ERROR_SUCCESS) {
        printf("Failed to start ETW tracing session, error %lu\n", status);
        free(SessionProperties);
        return 1;
    }

    ULONG64 fileKeywords = 
        //KERNEL_FILE_KEYWORD_FILEIO |        // required base for most events
        KERNEL_FILE_KEYWORD_FILENAME |      // path resolution
        KERNEL_FILE_KEYWORD_CREATE |        // file create
        KERNEL_FILE_KEYWORD_WRITE |         // file write
        KERNEL_FILE_KEYWORD_DELETE_PATH |   // delete
        KERNEL_FILE_KEYWORD_RENAME_SETLINK_PATH | // rename
        KERNEL_FILE_KEYWORD_CREATE_NEW_FILE; // new file creation

    /*if (!g_LightweightMode)  {
        fileKeywords |= KERNEL_FILE_KEYWORD_READ;
    }*/

    status = EnableTraceEx2(SessionHandle, &FileProviderGuid,
        EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_INFORMATION, fileKeywords, 0, 0, NULL);
    if (status != ERROR_SUCCESS) {
        printf("WARNING: Failed to enable File provider (error %lu)\n", status);
    }
    
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

    // Process events (blocks until stopped)
    status = ProcessTrace(&traceHandle, 1, NULL, NULL);
    if (status != ERROR_CANCELLED && status != ERROR_SUCCESS) {
        printf("ERROR: ProcessTrace failed with error %lu\n", status);
    }

    return 0;
}