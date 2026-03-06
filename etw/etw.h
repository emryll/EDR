#ifndef ETW_H
#define ETW_H

#include <windows.h>
#include <evntrace.h>
#include <tdh.h>

#define ETW_PIPE_NAME "\\\\.\\pipe\\em_etw"
#define COMMANDS_PIPE_NAME "\\\\.\\pipe\\em_cmd"
#define SESSION_NAME "testETWsession"
#define MAX_CMD_DATA 32

extern HANDLE hCmd;
extern HANDLE hEtw;
extern TRACEHANDLE SessionHandle;
extern TRACEHANDLE traceHandle;
extern EVENT_TRACE_PROPERTIES* SessionProperties;


typedef enum {
    TM_TYPE_ETW_FILE = 2,
    TM_TYPE_ETW_REG = 3,
} TM_TYPE;

// these enums are the event IDs
// https://github.com/jdu2600/Windows10EtwEvents
typedef enum {
    EVENT_FILE_CREATE = 12, // create/open
    EVENT_FILE_DELETE = 26,
    EVENT_FILE_READ = 15,
    EVENT_FILE_WRITE = 16,
    EVENT_FILE_RENAME = 27, // "RenamePath", rename happened

    EVENT_REG_CREATE_KEY = 1,
    EVENT_REG_OPEN_KEY = 2, // not used
    EVENT_REG_DELETE_KEY = 3,
    EVENT_REG_QUERY_KEY = 4, // not used
    EVENT_REG_SET_KEY_VALUE = 5,
    EVENT_REG_DELETE_KEY_VALUE = 6,
    EVENT_REG_SET_INFO_KEY = 11, // change key metadata (permissions, for example)
    EVENT_REG_CLOSE_KEY = 13, // not used
    EVENT_REG_SET_SECURITY_KEY = 15,
} ETW_EVENT_ID;

typedef enum {
    // Microsoft-Windows-Kernel-File
    KERNEL_FILE_KEYWORD_FILENAME = 0x10,
    KERNEL_FILE_KEYWORD_FILEIO = 0x20,
    KERNEL_FILE_KEYWORD_OP_END = 0x40,
    KERNEL_FILE_KEYWORD_CREATE = 0x80,
    KERNEL_FILE_KEYWORD_READ = 0x100,
    KERNEL_FILE_KEYWORD_WRITE = 0x200,
    KERNEL_FILE_KEYWORD_DELETE_PATH = 0x400,
    KERNEL_FILE_KEYWORD_RENAME_SETLINK_PATH = 0x800,
    KERNEL_FILE_KEYWORD_CREATE_NEW_FILE = 0x1000,
    // Microsoft-Windows-Kernel-Registry
    KERNEL_REGISTRY_KEYWORD_CREATE_KEY = 0x1000,
    KERNEL_REGISTRY_KEYWORD_DELETE_KEY = 0x4000,
    KERNEL_REGISTRY_KEYWORD_SET_VALUE = 0x100,
    KERNEL_REGISTRY_KEYWORD_DELETE_VALUE = 0x200,
    KERNEL_REGISTRY_KEYWORD_SET_INFORMATION = 0x40,
    KERNEL_REGISTRY_KEYWORD_SET_SECURITY = 0x4,
    // Microsoft-Windows-Kernel-Registry
    WINEVENT_KEYWORD_PROCESS = 0x10,
    WINEVENT_KEYWORD_THREAD = 0x20,
    WINEVENT_KEYWORD_IMAGE = 0x40,

} ETW_KEYWORD;

// this type describes packets received by this component from agent
typedef struct {
    DWORD type; // 0: empty, 1: shutdown, 2: ping
    WORD majorVersion;
    WORD minorVersion;
    size_t dataSize; // size of binary blob after this struct
} ETW_CMD;

// This describes different types of packets agent can send
typedef enum {
    ETW_CMD_EMPTY,
    ETW_CMD_SHUTDOWN,
    ETW_CMD_PLIST_ADD, 
    ETW_CMD_PLIST_REMOVE,
    ETW_CMD_PING, // not implemented (not in alpha)
} ETW_CMD_TYPE;
/*
// Standard telemetry header for sending data to agent. First part of packet.
typedef struct {
    DWORD pid;
    DWORD type;
    size_t dataSize;
    time_t timeStamp;
} TELEMETRY_HEADER;
*/
typedef struct {
    DWORD pid; // which process did it
    DWORD tid; // which thread did it
    DWORD type; // source; api call, file event, etc.
    DWORD eventId; // enum indicating which event it is (for example file create or OpenProcess)
    size_t dataSize; // total size of parameters, which come after header
    time_t timeStamp;
} TELEMETRY_HEADER;

// Second part of packet sent to agent. Microsoft-Windows-Kernel-File events
typedef struct {
    DWORD action;
    char path[260];
    DWORD attributeCount; // padding after this one
    size_t totalAttributesSize;
} FILE_EVENT;

// Second part of packet sent to agent. Microsoft-Windows-Kernel-Registry events
typedef struct {
    DWORD action;
    char path[260];
    DWORD attributeCount;
    size_t totalAttributesSize;
} REG_EVENT;

typedef struct {
    char name[60];
    DWORD type;
    size_t size;
} PARAMETER;

typedef enum {
    PARAMETER_EMPTY_VALUE,
    PARAMETER_ANSISTRING,
    PARAMETER_WIDESTRING,
    PARAMETER_POINTER,
    PARAMETER_DWORD,
    PARAMETER_UINT64,
    PARAMETER_BOOLEAN,
    PARAMETER_BYTES,
} PARAMETER_TYPE;

// this should be in tdh.h but isnt for some reason
typedef enum {
  TDH_INTYPE_NULL,
  TDH_INTYPE_UNICODESTRING,
  TDH_INTYPE_ANSISTRING,
  TDH_INTYPE_INT8,
  TDH_INTYPE_UINT8,
  TDH_INTYPE_INT16,
  TDH_INTYPE_UINT16,
  TDH_INTYPE_INT32,
  TDH_INTYPE_UINT32,
  TDH_INTYPE_INT64,
  TDH_INTYPE_UINT64,
  TDH_INTYPE_FLOAT,
  TDH_INTYPE_DOUBLE,
  TDH_INTYPE_BOOLEAN,
  TDH_INTYPE_BINARY,
  TDH_INTYPE_GUID,
  TDH_INTYPE_POINTER,
  TDH_INTYPE_FILETIME,
  TDH_INTYPE_SYSTEMTIME,
  TDH_INTYPE_SID,
  TDH_INTYPE_HEXINT32,
  TDH_INTYPE_HEXINT64,
  TDH_INTYPE_MANIFEST_COUNTEDSTRING,
  TDH_INTYPE_MANIFEST_COUNTEDANSISTRING,
  TDH_INTYPE_RESERVED24,
  TDH_INTYPE_MANIFEST_COUNTEDBINARY,
  TDH_INTYPE_COUNTEDSTRING,
  TDH_INTYPE_COUNTEDANSISTRING,
  TDH_INTYPE_REVERSEDCOUNTEDSTRING,
  TDH_INTYPE_REVERSEDCOUNTEDANSISTRING,
  TDH_INTYPE_NONNULLTERMINATEDSTRING,
  TDH_INTYPE_NONNULLTERMINATEDANSISTRING,
  TDH_INTYPE_UNICODECHAR,
  TDH_INTYPE_ANSICHAR,
  TDH_INTYPE_SIZET,
  TDH_INTYPE_HEXDUMP,
  TDH_INTYPE_WBEMSID
} TDH_INTYPE;

BOOL ReadFull(HANDLE, void*, DWORD);
BOOL InitializeComms();
char* NormalizeEventPath(WCHAR*);
char* ConvertWideToAnsi(WCHAR*);
BOOL WINAPI CtrlHandler(DWORD);
BOOL IsAdmin();

void DumpPacket(BYTE*, size_t);

BYTE* CreateParameter(char*, DWORD, DWORD, size_t*);
BYTE* CreateFileEventPacket(PEVENT_RECORD, size_t*);
BYTE* CreateRegistryEventPacket(PEVENT_RECORD, size_t*);
BOOL ParseFileEventParameter(PEVENT_RECORD, ULONG, PTRACE_EVENT_INFO, BYTE**, size_t*, FILE_EVENT*);
BOOL ParseRegEventParameter(PEVENT_RECORD, ULONG, PTRACE_EVENT_INFO, BYTE**, size_t*, REG_EVENT*);
int SendEtwTelemetryPacket(PEVENT_RECORD, BYTE*, size_t, DWORD);
TELEMETRY_HEADER GetTelemetryHeader(DWORD, DWORD, size_t, time_t);

#ifdef __cplusplus
extern "C" {
#endif
void TrackProcess(DWORD);
void UntrackProcess(DWORD);
BOOL IsTracked(DWORD);
#ifdef __cplusplus
}
#endif

#endif