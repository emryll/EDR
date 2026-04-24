#include <windows.h>
#include <ntdef.h>
#include <tdh.h>
#include <stdio.h>
#include "etw.h"

//?===========================================================+
//?   This file contains miscellaneous utility functions.     |
//?===========================================================+


BOOL IsAdmin() {
    BOOL isAdmin = FALSE;
    PSID adminGroup = NULL;
    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;

    if (AllocateAndInitializeSid(&NtAuthority, 2,
        SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
        0, 0, 0, 0, 0, 0, &adminGroup)) {
        CheckTokenMembership(NULL, adminGroup, &isAdmin);
        FreeSid(adminGroup);
    }
    return isAdmin;
}

//TODO: make this more memory efficient. also dont limit path to 260 chars
// The paths from events are wide strings and start with something like " \Device\HarddiskVolume".
// This function converts it to a normal ansi string path with drive letters. Caller must free string.
char* NormalizeEventPath(WCHAR* path) {
    //? should you also return string len?
    WCHAR drives[512] = {0};
    WCHAR deviceName[MAX_PATH] = {0};
    WCHAR driveLetter[3] = L"A:";
    WCHAR normalPath[MAX_PATH] = {0};

    // Get all logical drives' letters
    if (GetLogicalDriveStringsW(sizeof(drives) / sizeof(WCHAR), drives) == 0) {
        return FALSE;
    }
    
    // Iterate through each drive letter
    WCHAR* drive = drives;
    while (*drive) {
        driveLetter[0] = drive[0];
        
        // Query the device name for this drive letter
        if (QueryDosDeviceW(driveLetter, deviceName, MAX_PATH) != 0) {
            size_t deviceNameLen = wcslen(deviceName);
            
            // Check if path starts with this device name
            if (_wcsnicmp(path, deviceName, deviceNameLen) == 0) {
                swprintf(normalPath, MAX_PATH, L"%ls%ls", driveLetter, path + deviceNameLen);
                char* ansiPath = WideToAnsi(normalPath);
                
                return ansiPath;
            }
        }
        drive += wcslen(drive) + 1; // move to next one
    }
    return NULL;
}

// Only works with null terminated wide strings.
// Helper function to convert wide string to ansi. Caller must free the returned string.
char* WideToAnsi(WCHAR* wideStr) {
    // First call to get the required buffer size
    int sizeNeeded = WideCharToMultiByte(CP_UTF8, 0, wideStr, -1, NULL, 0, NULL, NULL);
    if (sizeNeeded == 0) {
        printf("[debug] failed to get size, error: %d\n", GetLastError());
        return NULL;
    }

    char* ansiStr = (char*)malloc(sizeNeeded);
    if (!ansiStr) {
        printf("[debug] failed to allocate memory\n");
        return NULL;
    }

    // Using UTF-8 for safer conversion (https://learn.microsoft.com/en-us/windows/win32/api/stringapiset/nf-stringapiset-widechartomultibyte)
    int result = WideCharToMultiByte(CP_UTF8, 0, wideStr, -1, ansiStr, sizeNeeded, NULL, NULL);
    if (result == 0) {
        printf("[debug] Failed to convert wide string to UTF8, error: %d\n", GetLastError());
        free(ansiStr);
        return NULL;
    }

    return ansiStr;
}

// Helper to convert a windows UNICODE_STRING into an ansi string
char* UnicodeStringToAnsi(UNICODE_STRING* ustr) {
    if (!ustr || !ustr->Buffer || ustr->Length == 0 || ustr->MaximumLength == 0) {
        if (!ustr) {
            printf("[debug] !ustr\n");
        }
        if (!ustr->Buffer) {
            printf("[debug] !ustr->Buffer\n");
        }
        if (ustr->Length == 0) {
            printf("[debug] !ustr->Length == 0\n");
            printf("[debug] test print: %ls\n", ustr);
        }
        return NULL;
    }
    if (ustr->Length % 2 != 0) {
        printf("[debug] length field not divisible by 2, cant be unicode_string\n");
        return NULL;
    }

    wprintf(L"[debug] unicode_string (%d): %ls\n", ustr->Length, ustr->Buffer);

    size_t wcharCount = ustr->Length / sizeof(WCHAR);
    // ensure null terminated string
    WCHAR* nullTmp = (WCHAR*)malloc((wcharCount + 1) * sizeof(WCHAR));
    memcpy(nullTmp, ustr->Buffer, ustr->Length);
    nullTmp[wcharCount] = L'\0';

    char* ansi = WideToAnsi(nullTmp);
    free(nullTmp);
    return ansi;
}

// Dump the raw bytes of a packet buffer (or any other buffer)
void DumpPacket(BYTE* packet, size_t packetSize) {
    for (size_t i = 0; i < packetSize; i++) {
        if (i%32==0) {
            printf("\n\t");
        }
        printf("%02X ", packet[i]);
    }
    printf("\n");
}

void PrintEventBasic(PEVENT_RECORD event) {
    SYSTEMTIME st;
    FILETIME ft;
    ft.dwLowDateTime = event->EventHeader.TimeStamp.LowPart;
    ft.dwHighDateTime = event->EventHeader.TimeStamp.HighPart;
    FileTimeToSystemTime(&ft, &st);
    printf("[%02d:%02d:%02d.%03d] ", st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);

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
    } else if (IsEqualGUID(event->EventHeader.ProviderId, ProcessProviderGuid)) {
        switch (event->EventHeader.EventDescriptor.Id) {
            case 1:
            printf("PROCESS CREATE EVENT, PID: %lu\n",
            event->EventHeader.EventDescriptor.Id, event->EventHeader.ProcessId);
            break;
        }
    } else {
        printf("EVENT FROM UNKNOWN PROVIDER\n");
    }
}

// Placeholder returns critical on all. Reworked soon...
BOOL IsCriticalEvent(PEVENT_RECORD event) {
    // - executable or remote memory alloc
    // - create thread, queue apc, set context
    // - others like ntsetinformationprocess (execution)
    return TRUE;
}

void LogError(const char* msg, ERROR_CODE err) {
    printf("[ERROR] %s: %s\n", msg, GetError(err));
    //TODO: log to disk
}

const char* GetError(ERROR_CODE err) {
    switch (err) {
        case SUCCESS:
            return "Success!";
        case ERROR_INVALID_QUEUE:
            return "invalid queue";
        case ERROR_FULL_QUEUE:
            return "full queue";
        case ERROR_EMPTY_QUEUE:
            return "empty queue";
        case ERROR_FAILED_WRITE:
            return "failed write";
        case ERROR_REALLOC:
            return "failed to realloc";
    }
    return "(unknown)";
}

// this function needs to be validated
time_t FiletimeToUnixMillis(FILETIME ft) {
    // Convert FILETIME to 64-bit value
    uint64_t t = ((uint64_t)ft.dwHighDateTime << 32) | ft.dwLowDateTime;

    // Subtract Windows epoch (1601) to Unix epoch (1970)
    t -= 116444736000000000ULL;

    // Convert from 100-nanoseconds to milliseconds
    return t / 10000ULL;
}