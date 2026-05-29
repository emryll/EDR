#ifndef PACKET_H
#define PACKET_H

#include <windows.h>

void SendDllInjectionAlert();
BYTE* GetGenericAlertPacket(LPCSTR);

TELEMETRY_HEADER GetTelemetryHeader(DWORD, size_t);

BYTE* BuildParameter(size_t*, DWORD, const char*, ...);
BYTE* BuildArrayParameter(size_t*, DWORD, const char*, void*, size_t);
BYTE* CreateParameterHeader(const char*, DWORD, DWORD, size_t*);

BYTE* GetAnsiArray(const char**, size_t, size_t*);
BYTE* GetUint32Array(DWORD*, size_t, size_t*);
BYTE* GetUint64Array(UINT64*, size_t, size_t*);
BYTE* GetBooleanArray(BOOL*, size_t, size_t*);

typedef enum {
    TM_TYPE_EMPTY_VALUE    = 0, // so agent does not parse empty values
    TM_TYPE_API_CALL       = 1,
    TM_TYPE_FILE_EVENT     = 2,
    TM_TYPE_REG_EVENT      = 3,
    TM_TYPE_TEXT_INTEGRITY = 4,
    TM_TYPE_IAT_INTEGRITY = 5,
    TM_TYPE_GENERIC_ALERT = 6,
} TM_PACKET_TYPE;

typedef enum {
  PARAMETER_ANSISTRING = 1
  PARAMETER_ASTR_ARRAY = 10
  PARAMETER_UINT32 = 2
  PARAMETER_UINT32_ARRAY = 20
  PARAMETER_UINT64 = 3
  PARAMETER_UINT64_ARRAY = 30
  PARAMETER_BOOLEAN = 4
  PARAMETER_BOOLEAN_ARRAY = 40
  PARAMETER_POINTER = 5
  PARAMETER_POINTER_ARRAY = 50
  PARAMETER_BYTES = 7
} PARAMETER_TYPE;

typedef struct {
    DWORD pid;
    char  command[64];
    char  arg[64];
} COMMAND;

typedef struct {
    DWORD pid;
    char  Heartbeat[64];
} HEARTBEAT;

// tampering.c
void heartbeat(HANDLE);

#endif
