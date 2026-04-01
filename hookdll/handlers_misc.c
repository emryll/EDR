#include <windows.h>
#include <winternl.h>
#include "hook.h"

//?=======================================================================================+
//?  These are the functions API hooks point to, which get triggered when a hooked API    |
//?   is called. Hook handlers forward information of the event to the agent via          |
//?   named pipes. Packets include API, dll, caller, and parameters with additional       |
//?   info about the call (args or context). Each handler follows the same blueprint.     |
//?                                                                                       |
//?  Handlers start by optionally checking if the call is interesting, and if it is       |
//?   deemed uninteresting, the call will pass through immediately without sending        |
//?   a packet. After the filtering, the telemetry packet gets built, and placed in the   |
//?   the packet queue. Finally the handlers pass the call through and return to caller.  |
//?                                                                                       |
//?  Hook handlers are only ever called by hooks; they should never be called directly.   |
//?=======================================================================================+

//* This file contains the hook handlers for APIs which don't fit under other categories

//*===================[ Token Apis ]=======================

BOOL AdjustTokenPrivileges_Handler(
    HANDLE            TokenHandle,
    BOOL              DisableAllPrivileges,
    PTOKEN_PRIVILEGES NewState,
    DWORD             BufferLength,
    PTOKEN_PRIVILEGES PreviousState,
    PDWORD            ReturnLength) {
    // create parameters
    size_t param1Size;
    BYTE* param1 = BuildParameter(&param1Size, PARAMETER_UINT32, "Handle", (DWORD)(ULONG_PTR)TokenHandle);
    size_t fnParamSize;
    BYTE* fnParam = BuildParameter(&fnParamSize, PARAMETER_ANSISTRING, "Func", "AdjustTokenPrivileges");
    size_t dllParamSize;
    BYTE* dllParam = BuildParameter(&dllParamSize, PARAMETER_ANSISTRING, "DllName", "advapi32.dll");

    size_t totalParamsSize = param1Size + fnParamSize + dllParamSize;
    TELEMETRY_HEADER header = GetTelemetryHeader(TM_TYPE_API_CALL, totalParamsSize);

    size_t packetSize = totalParamsSize + sizeof(header);
    BYTE* packet = (BYTE*)malloc(packetSize);

    // construct packet 
    memcpy(packet, &header, sizeof(header));
    memcpy(packet + sizeof(header), param1, param1Size);
    memcpy(packet + sizeof(header) + param1Size, fnParam, fnParamSize);
    memcpy(packet + sizeof(header) + param1Size + fnParamSize, dllParam, dllParamSize);

    free(param1);
    free(fnParam);
    free(dllParam);

    EnqueuePacket(g_StandardQueue, packet, packetSize);
    return ((ADJUSTTOKENPRIVS)HookList[HOOK_ADJUST_TOKEN_PRIVS].originalFunc)(TokenHandle, DisableAllPrivileges,
        NewState, BufferLength, PreviousState, ReturnLength);
}

BOOL OpenProcessToken_Handler(HANDLE ProcessHandle, DWORD DesiredAccess, PHANDLE TokenHandle) {
    // create parameters
    size_t param1Size;
    BYTE* param1 = BuildParameter(&param1Size, PARAMETER_UINT32, "TargetPid", GetProcessId(ProcessHandle));
    size_t param2Size;
    BYTE* param2 = BuildParameter(&param2Size, PARAMETER_UINT32, "Access", DesiredAccess);
    size_t fnParamSize;
    BYTE* fnParam = BuildParameter(&fnParamSize, PARAMETER_ANSISTRING, "Func", "OpenProcessToken");
    size_t dllParamSize;
    BYTE* dllParam = BuildParameter(&dllParamSize, PARAMETER_ANSISTRING, "DllName", "advapi32.dll");

    size_t totalParamsSize = param1Size + param2Size + fnParamSize + dllParamSize;
    TELEMETRY_HEADER header = GetTelemetryHeader(TM_TYPE_API_CALL, totalParamsSize);

    size_t packetSize = totalParamsSize + sizeof(header);
    BYTE* packet = (BYTE*)malloc(packetSize);

    // construct packet 
    memcpy(packet, &header, sizeof(header));
    memcpy(packet + sizeof(header), param1, param1Size);
    memcpy(packet + sizeof(header) + param1Size, param2, param2Size);
    memcpy(packet + sizeof(header) + param1Size + param2Size, fnParam, fnParamSize);
    memcpy(packet + sizeof(header) + param1Size + param2Size + fnParamSize, dllParam, dllParamSize);

    free(param1);
    free(param2);
    free(fnParam);
    free(dllParam);

    EnqueuePacket(g_StandardQueue, packet, packetSize);
    return ((OPENPROCESSTOKEN)HookList[HOOK_OPEN_PROCESS_TOKEN].originalFunc)(ProcessHandle, DesiredAccess, TokenHandle);
}

NTSTATUS NtOpenProcessToken_Handler(HANDLE ProcessHandle, DWORD DesiredAccess, PHANDLE TokenHandle) {
    // create parameters
    size_t param1Size;
    BYTE* param1 = BuildParameter(&param1Size, PARAMETER_UINT32, "TargetPid", GetProcessId(ProcessHandle));
    size_t param2Size;
    BYTE* param2 = BuildParameter(&param2Size, PARAMETER_UINT32, "Access", DesiredAccess);
    size_t fnParamSize;
    BYTE* fnParam = BuildParameter(&fnParamSize, PARAMETER_ANSISTRING, "Func", "NtOpenProcessToken");
    size_t dllParamSize;
    BYTE* dllParam = BuildParameter(&dllParamSize, PARAMETER_ANSISTRING, "DllName", "ntdll.dll");

    size_t totalParamsSize = param1Size + param2Size + fnParamSize + dllParamSize;
    TELEMETRY_HEADER header = GetTelemetryHeader(TM_TYPE_API_CALL, totalParamsSize);

    size_t packetSize = totalParamsSize + sizeof(header);
    BYTE* packet = (BYTE*)malloc(packetSize);

    // construct packet 
    memcpy(packet, &header, sizeof(header));
    memcpy(packet + sizeof(header), param1, param1Size);
    memcpy(packet + sizeof(header) + param1Size, param2, param2Size);
    memcpy(packet + sizeof(header) + param1Size + param2Size, fnParam, fnParamSize);
    memcpy(packet + sizeof(header) + param1Size + param2Size + fnParamSize, dllParam, dllParamSize);

    free(param1);
    free(param2);
    free(fnParam);
    free(dllParam);

    EnqueuePacket(g_StandardQueue, packet, packetSize);
    return ((NTOPENPROCESSTOKEN)HookList[HOOK_NT_OPEN_PROCESS_TOKEN].originalFunc)(ProcessHandle, DesiredAccess, TokenHandle);
}

NTSTATUS NtOpenProcessTokenEx_Handler(HANDLE ProcessHandle, DWORD DesiredAccess, ULONG HandleAttributes, PHANDLE TokenHandle) {
    // create parameters
    size_t param1Size;
    BYTE* param1 = BuildParameter(&param1Size, PARAMETER_UINT32, "TargetPid", GetProcessId(ProcessHandle));
    size_t param2Size;
    BYTE* param2 = BuildParameter(&param2Size, PARAMETER_UINT32, "Access", DesiredAccess);
    size_t fnParamSize;
    BYTE* fnParam = BuildParameter(&fnParamSize, PARAMETER_ANSISTRING, "Func", "NtOpenProcessTokenEx");
    size_t dllParamSize;
    BYTE* dllParam = BuildParameter(&dllParamSize, PARAMETER_ANSISTRING, "DllName", "ntdll.dll");

    size_t totalParamsSize = param1Size + param2Size + fnParamSize + dllParamSize;
    TELEMETRY_HEADER header = GetTelemetryHeader(TM_TYPE_API_CALL, totalParamsSize);

    size_t packetSize = totalParamsSize + sizeof(header);
    BYTE* packet = (BYTE*)malloc(packetSize);

    // construct packet 
    memcpy(packet, &header, sizeof(header));
    memcpy(packet + sizeof(header), param1, param1Size);
    memcpy(packet + sizeof(header) + param1Size, param2, param2Size);
    memcpy(packet + sizeof(header) + param1Size + param2Size, fnParam, fnParamSize);
    memcpy(packet + sizeof(header) + param1Size + param2Size + fnParamSize, dllParam, dllParamSize);

    free(param1);
    free(param2);
    free(fnParam);
    free(dllParam);

    EnqueuePacket(g_StandardQueue, packet, packetSize);
    return ((NTOPENPROCESSTOKENEX)HookList[HOOK_NT_OPEN_PROCESS_TOKEN_EX].originalFunc)(ProcessHandle, DesiredAccess, HandleAttributes, TokenHandle);
}

BOOL OpenThreadToken_Handler(
    HANDLE  ThreadHandle,
    DWORD   DesiredAccess,
    BOOL    OpenAsSelf,
    PHANDLE TokenHandle) {
    // create parameters
    size_t param1Size;
    BYTE* param1 = BuildParameter(&param1Size, PARAMETER_UINT32, "TargetPid", GetProcessIdOfThread(ThreadHandle));
    size_t param2Size;
    BYTE* param2 = BuildParameter(&param2Size, PARAMETER_UINT32, "TargetTid", GetThreadId(ThreadHandle));
    size_t param3Size;
    BYTE* param3 = BuildParameter(&param3Size, PARAMETER_UINT32, "Access", DesiredAccess);
    size_t param4Size;
    BYTE* param4 = BuildParameter(&param4Size, PARAMETER_BOOLEAN, "OpenAsSelf", OpenAsSelf);
    size_t fnParamSize;
    BYTE* fnParam = BuildParameter(&fnParamSize, PARAMETER_ANSISTRING, "Func", "OpenThreadToken");
    size_t dllParamSize;
    BYTE* dllParam = BuildParameter(&dllParamSize, PARAMETER_ANSISTRING, "DllName", "advapi32.dll");

    size_t totalParamsSize = param1Size + param2Size + param3Size + param4Size + fnParamSize + dllParamSize;
    TELEMETRY_HEADER header = GetTelemetryHeader(TM_TYPE_API_CALL, totalParamsSize);

    size_t packetSize = totalParamsSize + sizeof(header);
    BYTE* packet = (BYTE*)malloc(packetSize);

    // construct packet 
    memcpy(packet, &header, sizeof(header));
    memcpy(packet + sizeof(header), param1, param1Size);
    memcpy(packet + sizeof(header) + param1Size, param2, param2Size);
    memcpy(packet + sizeof(header) + param1Size + param2Size, param3, param3Size);
    memcpy(packet + sizeof(header) + param1Size + param2Size + param3Size, param4, param4Size);
    memcpy(packet + sizeof(header) + param1Size + param2Size + param3Size + param4Size, fnParam, fnParamSize);
    memcpy(packet + sizeof(header) + param1Size + param2Size + param3Size + param4Size + fnParamSize, dllParam, dllParamSize);

    free(param1);
    free(param2);
    free(param3);
    free(param4);
    free(fnParam);
    free(dllParam);

    EnqueuePacket(g_StandardQueue, packet, packetSize);
    return ((OPENTHREADTOKEN)HookList[HOOK_OPEN_THREAD_TOKEN].originalFunc)(ThreadHandle, DesiredAccess, OpenAsSelf, TokenHandle);
}

BOOL NtOpenThreadToken_Handler(
    HANDLE  ThreadHandle,
    ACCESS_MASK   DesiredAccess,
    BOOLEAN OpenAsSelf,
    PHANDLE TokenHandle) {
    // create parameters
    size_t param1Size;
    BYTE* param1 = BuildParameter(&param1Size, PARAMETER_UINT32, "TargetPid", GetProcessIdOfThread(ThreadHandle));
    size_t param2Size;
    BYTE* param2 = BuildParameter(&param2Size, PARAMETER_UINT32, "TargetTid", GetThreadId(ThreadHandle));
    size_t param3Size;
    BYTE* param3 = BuildParameter(&param3Size, PARAMETER_UINT32, "Access", DesiredAccess);
    size_t param4Size;
    BYTE* param4 = BuildParameter(&param4Size, PARAMETER_BOOLEAN, "OpenAsSelf", OpenAsSelf);
    size_t fnParamSize;
    BYTE* fnParam = BuildParameter(&fnParamSize, PARAMETER_ANSISTRING, "Func", "NtOpenThreadToken");
    size_t dllParamSize;
    BYTE* dllParam = BuildParameter(&dllParamSize, PARAMETER_ANSISTRING, "DllName", "ntdll.dll");

    size_t totalParamsSize = param1Size + param2Size + param3Size + param4Size + fnParamSize + dllParamSize;
    TELEMETRY_HEADER header = GetTelemetryHeader(TM_TYPE_API_CALL, totalParamsSize);

    size_t packetSize = totalParamsSize + sizeof(header);
    BYTE* packet = (BYTE*)malloc(packetSize);

    // construct packet 
    memcpy(packet, &header, sizeof(header));
    memcpy(packet + sizeof(header), param1, param1Size);
    memcpy(packet + sizeof(header) + param1Size, param2, param2Size);
    memcpy(packet + sizeof(header) + param1Size + param2Size, param3, param3Size);
    memcpy(packet + sizeof(header) + param1Size + param2Size + param3Size, param4, param4Size);
    memcpy(packet + sizeof(header) + param1Size + param2Size + param3Size + param4Size, fnParam, fnParamSize);
    memcpy(packet + sizeof(header) + param1Size + param2Size + param3Size + param4Size + fnParamSize, dllParam, dllParamSize);

    free(param1);
    free(param2);
    free(param3);
    free(param4);
    free(fnParam);
    free(dllParam);

    EnqueuePacket(g_StandardQueue, packet, packetSize);
    return ((NTOPENTHREADTOKEN)HookList[HOOK_NT_OPEN_THREAD_TOKEN].originalFunc)(ThreadHandle, DesiredAccess, OpenAsSelf, TokenHandle);
}

BOOL NtOpenThreadTokenEx_Handler(
    HANDLE  ThreadHandle,
    ACCESS_MASK   DesiredAccess,
    BOOLEAN OpenAsSelf,
    ULONG HandleAttributes,
    PHANDLE TokenHandle) {
    // create parameters
    size_t param1Size;
    BYTE* param1 = BuildParameter(&param1Size, PARAMETER_UINT32, "TargetPid", GetProcessIdOfThread(ThreadHandle));
    size_t param2Size;
    BYTE* param2 = BuildParameter(&param2Size, PARAMETER_UINT32, "TargetTid", GetThreadId(ThreadHandle));
    size_t param3Size;
    BYTE* param3 = BuildParameter(&param3Size, PARAMETER_UINT32, "Access", DesiredAccess);
    size_t param4Size;
    BYTE* param4 = BuildParameter(&param4Size, PARAMETER_BOOLEAN, "OpenAsSelf", OpenAsSelf);
    size_t fnParamSize;
    BYTE* fnParam = BuildParameter(&fnParamSize, PARAMETER_ANSISTRING, "Func", "NtOpenThreadTokenEx");
    size_t dllParamSize;
    BYTE* dllParam = BuildParameter(&dllParamSize, PARAMETER_ANSISTRING, "DllName", "ntdll.dll");

    size_t totalParamsSize = param1Size + param2Size + param3Size + param4Size + fnParamSize + dllParamSize;
    TELEMETRY_HEADER header = GetTelemetryHeader(TM_TYPE_API_CALL, totalParamsSize);

    size_t packetSize = totalParamsSize + sizeof(header);
    BYTE* packet = (BYTE*)malloc(packetSize);

    // construct packet 
    memcpy(packet, &header, sizeof(header));
    memcpy(packet + sizeof(header), param1, param1Size);
    memcpy(packet + sizeof(header) + param1Size, param2, param2Size);
    memcpy(packet + sizeof(header) + param1Size + param2Size, param3, param3Size);
    memcpy(packet + sizeof(header) + param1Size + param2Size + param3Size, param4, param4Size);
    memcpy(packet + sizeof(header) + param1Size + param2Size + param3Size + param4Size, fnParam, fnParamSize);
    memcpy(packet + sizeof(header) + param1Size + param2Size + param3Size + param4Size + fnParamSize, dllParam, dllParamSize);

    free(param1);
    free(param2);
    free(param3);
    free(param4);
    free(fnParam);
    free(dllParam);

    EnqueuePacket(g_StandardQueue, packet, packetSize);
    return ((NTOPENTHREADTOKENEX)HookList[HOOK_NT_OPEN_THREAD_TOKEN_EX].originalFunc)(ThreadHandle, DesiredAccess, OpenAsSelf, HandleAttributes, TokenHandle);
}

BOOL DuplicateToken_Handler(
    HANDLE                       ExistingTokenHandle,
    SECURITY_IMPERSONATION_LEVEL ImpersonationLevel,
    PHANDLE                      DuplicateTokenHandle) {
    // create parameters
    size_t param1Size;
    BYTE* param1 = BuildParameter(&param1Size, PARAMETER_UINT32, "ImpersonationLevel", ImpersonationLevel);
    size_t param2Size;
    BYTE* param2 = BuildParameter(&param2Size, PARAMETER_UINT32, "Handle", (DWORD)(ULONG_PTR)ExistingTokenHandle);
    size_t fnParamSize;
    BYTE* fnParam = BuildParameter(&fnParamSize, PARAMETER_ANSISTRING, "Func", "DuplicateToken");
    size_t dllParamSize;
    BYTE* dllParam = BuildParameter(&dllParamSize, PARAMETER_ANSISTRING, "DllName", "advapi32.dll");

    size_t totalParamsSize = param1Size + param2Size + fnParamSize + dllParamSize;
    TELEMETRY_HEADER header = GetTelemetryHeader(TM_TYPE_API_CALL, totalParamsSize);

    size_t packetSize = totalParamsSize + sizeof(header);
    BYTE* packet = (BYTE*)malloc(packetSize);

    // construct packet 
    memcpy(packet, &header, sizeof(header));
    memcpy(packet + sizeof(header), param1, param1Size);
    memcpy(packet + sizeof(header) + param1Size, param2, param2Size);
    memcpy(packet + sizeof(header) + param1Size + param2Size, fnParam, fnParamSize);
    memcpy(packet + sizeof(header) + param1Size + param2Size + fnParamSize, dllParam, dllParamSize);

    free(param1);
    free(param2);
    free(fnParam);
    free(dllParam);

    EnqueuePacket(g_StandardQueue, packet, packetSize);
    return ((DUPLICATETOKEN)HookList[HOOK_DUPLICATE_TOKEN].originalFunc)(ExistingTokenHandle, ImpersonationLevel, DuplicateTokenHandle);
}

BOOL DuplicateTokenEx_Handler(
    HANDLE                       hExistingToken,
    DWORD                        dwDesiredAccess,
    LPSECURITY_ATTRIBUTES        lpTokenAttributes,
    SECURITY_IMPERSONATION_LEVEL ImpersonationLevel,
    TOKEN_TYPE                   TokenType,
    PHANDLE                      phNewToken) {
    // create parameters
    size_t param1Size;
    BYTE* param1 = BuildParameter(&param1Size, PARAMETER_UINT32, "ImpersonationLevel", ImpersonationLevel);
    size_t param2Size;
    BYTE* param2 = BuildParameter(&param2Size, PARAMETER_UINT32, "Handle", (DWORD)(ULONG_PTR)ExistingTokenHandle);
    size_t param3Size;
    BYTE* param3 = BuildParameter(&param3Size, PARAMETER_UINT32, "Access", dwDesiredAccess);
    size_t fnParamSize;
    BYTE* fnParam = BuildParameter(&fnParamSize, PARAMETER_ANSISTRING, "Func", "DuplicateTokenEx");
    size_t dllParamSize;
    BYTE* dllParam = BuildParameter(&dllParamSize, PARAMETER_ANSISTRING, "DllName", "advapi32.dll");

    size_t totalParamsSize = param1Size + param2Size + param3Size + fnParamSize + dllParamSize;
    TELEMETRY_HEADER header = GetTelemetryHeader(TM_TYPE_API_CALL, totalParamsSize);

    size_t packetSize = totalParamsSize + sizeof(header);
    BYTE* packet = (BYTE*)malloc(packetSize);

    // construct packet 
    memcpy(packet, &header, sizeof(header));
    memcpy(packet + sizeof(header), param1, param1Size);
    memcpy(packet + sizeof(header) + param1Size, param2, param2Size);
    memcpy(packet + sizeof(header) + param1Size + param2Size, param3, param3Size);
    memcpy(packet + sizeof(header) + param1Size + param2Size + param3Size, fnParam, fnParamSize);
    memcpy(packet + sizeof(header) + param1Size + param2Size + param3Size + fnParamSize, dllParam, dllParamSize);

    free(param1);
    free(param2);
    free(param3);
    free(fnParam);
    free(dllParam);

    EnqueuePacket(g_StandardQueue, packet, packetSize);
    return ((DUPLICATETOKENEX)HookList[HOOK_DUPLICATE_TOKEN_EX].originalFunc)(hExistingToken, dwDesiredAccess,
        lpTokenAttributes, ImpersonationLevel, TokenType, phNewToken);
}

NTSTATUS NtDuplicateToken_Handler(
    HANDLE ExistingTokenHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    BOOLEAN EffectiveOnly,
    TOKEN_TYPE Type,
    PHANDLE NewTokenHandle) {
    // create parameters
    size_t param1Size;
    BYTE* param1 = BuildParameter(&param1Size, PARAMETER_UINT32, "Access", DesiredAccess);
    size_t param2Size;
    BYTE* param2 = BuildParameter(&param2Size, PARAMETER_UINT32, "Handle", (DWORD)(ULONG_PTR)ExistingTokenHandle);
    size_t fnParamSize;
    BYTE* fnParam = BuildParameter(&fnParamSize, PARAMETER_ANSISTRING, "Func", "NtDuplicateToken");
    size_t dllParamSize;
    BYTE* dllParam = BuildParameter(&dllParamSize, PARAMETER_ANSISTRING, "DllName", "ntdll.dll");

    size_t totalParamsSize = param1Size + param2Size + fnParamSize + dllParamSize;
    TELEMETRY_HEADER header = GetTelemetryHeader(TM_TYPE_API_CALL, totalParamsSize);

    size_t packetSize = totalParamsSize + sizeof(header);
    BYTE* packet = (BYTE*)malloc(packetSize);

    // construct packet 
    memcpy(packet, &header, sizeof(header));
    memcpy(packet + sizeof(header), param1, param1Size);
    memcpy(packet + sizeof(header) + param1Size, param2, param2Size);
    memcpy(packet + sizeof(header) + param1Size + param2Size, fnParam, fnParamSize);
    memcpy(packet + sizeof(header) + param1Size + param2Size + fnParamSize, dllParam, dllParamSize);

    free(param1);
    free(param2);
    free(fnParam);
    free(dllParam);

    EnqueuePacket(g_StandardQueue, packet, packetSize);
    return ((NTDUPLICATETOKEN)HookList[HOOK_NT_DUPLICATE_TOKEN].originalFunc)(ExistingTokenHandle,
        DesiredAccess, ObjectAttributes, EffectiveOnly, Type, NewTokenHandle);
}

//*==================[ Object Duplication ]======================


BOOL DuplicateHandle_Handler(
    HANDLE   hSourceProcessHandle,
    HANDLE   hSourceHandle,
    HANDLE   hTargetProcessHandle,
    LPHANDLE lpTargetHandle,
    DWORD    dwDesiredAccess,
    BOOL     bInheritHandle,
    DWORD    dwOptions) {
    // create parameters
    size_t param1Size;
    BYTE* param1 = BuildParameter(&param1Size, PARAMETER_UINT32, "Access", dwDesiredAccess);
    size_t param2Size;
    BYTE* param2 = BuildParameter(&param2Size, PARAMETER_UINT32, "Handle", (DWORD)(ULONG_PTR)hSourceHandle);
    size_t param3Size;
    BYTE* param3 = BuildParameter(&param3Size, PARAMETER_UINT32, "TargetPid", GetProcessId(hSourceProcessHandle));
    size_t fnParamSize;
    BYTE* fnParam = BuildParameter(&fnParamSize, PARAMETER_ANSISTRING, "Func", "DuplicateHandle");
    size_t dllParamSize;
    BYTE* dllParam = BuildParameter(&dllParamSize, PARAMETER_ANSISTRING, "DllName", "kernel32.dll");

    size_t totalParamsSize = param1Size + param2Size + param3Size + fnParamSize + dllParamSize;
    TELEMETRY_HEADER header = GetTelemetryHeader(TM_TYPE_API_CALL, totalParamsSize);

    size_t packetSize = totalParamsSize + sizeof(header);
    BYTE* packet = (BYTE*)malloc(packetSize);

    // construct packet 
    memcpy(packet, &header, sizeof(header));
    memcpy(packet + sizeof(header), param1, param1Size);
    memcpy(packet + sizeof(header) + param1Size, param2, param2Size);
    memcpy(packet + sizeof(header) + param1Size + param2Size, param3, param3Size);
    memcpy(packet + sizeof(header) + param1Size + param2Size + param3Size, fnParam, fnParamSize);
    memcpy(packet + sizeof(header) + param1Size + param2Size + param3Size + fnParamSize, dllParam, dllParamSize);

    free(param1);
    free(param2);
    free(param3);
    free(fnParam);
    free(dllParam);

    EnqueuePacket(g_StandardQueue, packet, packetSize);
    return ((DUPLICATEHANDLE)HookList[HOOK_DUPLICATE_HANDLE].originalFunc)(hSourceProcessHandle, hSourceHandle,
        hTargetProcessHandle, lpTargetHandle, dwDesiredAccess, bInheritHandle, dwOptions);
}

NTSTATUS NtDuplicateObject_Handler(
    HANDLE SourceProcessHandle,
    HANDLE SourceHandle,
    HANDLE TargetProcessHandle,
    PHANDLE TargetHandle,
    ACCESS_MASK DesiredAccess,
    ULONG HandleAttributes,
    ULONG Options) {
    // create parameters
    size_t param1Size;
    BYTE* param1 = BuildParameter(&param1Size, PARAMETER_UINT32, "Access", DesiredAccess);
    size_t param2Size;
    BYTE* param2 = BuildParameter(&param2Size, PARAMETER_UINT32, "Handle", (DWORD)(ULONG_PTR)SourceHandle);
    size_t param3Size;
    BYTE* param3 = BuildParameter(&param3Size, PARAMETER_UINT32, "TargetPid", GetProcessId(SourceProcessHandle));
    size_t fnParamSize;
    BYTE* fnParam = BuildParameter(&fnParamSize, PARAMETER_ANSISTRING, "Func", "NtDuplicateObject");
    size_t dllParamSize;
    BYTE* dllParam = BuildParameter(&dllParamSize, PARAMETER_ANSISTRING, "DllName", "ntdll.dll");

    size_t totalParamsSize = param1Size + param2Size + param3Size + fnParamSize + dllParamSize;
    TELEMETRY_HEADER header = GetTelemetryHeader(TM_TYPE_API_CALL, totalParamsSize);

    size_t packetSize = totalParamsSize + sizeof(header);
    BYTE* packet = (BYTE*)malloc(packetSize);

    // construct packet 
    memcpy(packet, &header, sizeof(header));
    memcpy(packet + sizeof(header), param1, param1Size);
    memcpy(packet + sizeof(header) + param1Size, param2, param2Size);
    memcpy(packet + sizeof(header) + param1Size + param2Size, param3, param3Size);
    memcpy(packet + sizeof(header) + param1Size + param2Size + param3Size, fnParam, fnParamSize);
    memcpy(packet + sizeof(header) + param1Size + param2Size + param3Size + fnParamSize, dllParam, dllParamSize);

    free(param1);
    free(param2);
    free(param3);
    free(fnParam);
    free(dllParam);

    EnqueuePacket(g_StandardQueue, packet, packetSize);
    return ((NTDUPLICATEOBJECT)HookList[HOOK_NT_DUPLICATE_OBJECT].originalFunc)(SourceProcessHandle, SourceHandle,
        TargetProcessHandle, TargetHandle, DesiredAccess, HandleAttributes, Options);
}

//TODO:================[ Worker Factory Apis ]===================


//*=========================[ Other ]======================


// Hooked for testing purposes, shouldn't be enabled outside dev builds
int MessageBoxA_Handler(HWND hWnd, LPCSTR caption, LPCSTR text, UINT type) {
  // create parameters
  size_t param1Size;
  BYTE* param1 = BuildParameter(&param1Size, PARAMETER_ANSISTRING, "Caption", caption);
  size_t param2Size;
  BYTE* param2 = BuildParameter(&param2Size, PARAMETER_ANSISTRING, "Text", text);
  size_t param3Size;
  BYTE* param3 = BuildParameter(&param3Size, PARAMETER_UINT32, "Type", type);
  size_t fnParamSize;
  BYTE* fnParam = BuildParameter(fnParamSize, PARAMETER_ANSISTRING, "Func", "MessageBoxA");
  size_t dllParamSize;
  BYTE* dllParam = BuildParameter(dllParamSize, PARAMETER_ANSISTRING, "DllName", "user32.dll");

  size_t totalParamsSize = param1Size + param2Size + param3Size + fnParamSize + dllParamSize;
  TELEMETRY_HEADER header = GetTelemetryHeader(TM_TYPE_API_CALL, totalParamsSize);

  size_t packetSize = totalParamsSize + sizeof(header);
  BYTE* packet = (BYTE*)malloc(packetSize);

  // construct packet
  memcpy(packet, &header, sizeof(header));
  memcpy(packet, param1, param1Size);
  memcpy(packet + param1Size, param2, param2Size);
  memcpy(packet + param1Size + param2Size, param3, param3Size);
  memcpy(packet + param1Size + param2Size + param3Size, fnParam, fnParamSize);
  memcpy(packet + param1Size + param2Size + param3Size + fnParamSize, dllParam, dllParamSize);

  free(param1);
  free(param2);
  free(param3);
  free(fnParam);
  free(dllParam);

  EnqueuePacket(g_StandardQueue, packet, packetSize);
  return ((MESSAGEBOXA)HookList[HOOK_MESSAGE_BOX_A].originalFunc)(hWnd, "Hooked!", "Hooked!", type);
}
