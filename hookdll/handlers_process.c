#include <windows.h>
#include <winternl.h>
#include "hook.h"

//?=======================================================================+
//?  Files beginning with handlers_ contain API hook handler functions.   |
//?    They are only called by the hooks, never anywhere else.            |
//?  This file contains the handlers for APIs dealing with processes.     |
//?=======================================================================+


//*===============[ Create Process ]===========================

BOOL CreateProcessA_Handler(
    LPCSTR                lpApplicationName,
    LPSTR                 lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL                  bInheritHandles,
    DWORD                 dwCreationFlags,
    LPVOID                lpEnvironment,
    LPCSTR                lpCurrentDirectory,
    LPSTARTUPINFOA        lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation) {
    // create parameters
    size_t param1Size;
    BYTE* param1 = BuildParameter(&param1Size, PARAMETER_ANSISTRING, "TargetPath", lpApplicationName);
    size_t param2Size;
    BYTE* param2 = BuildParameter(&param2Size, PARAMETER_ANSISTRING, "CmdLine", lpCommandLine);
    size_t param3Size;
    BYTE* param3 = BuildParameter(&param3Size, PARAMETER_UINT32, "Flags", dwCreationFlags);
    size_t fnParamSize;
    BYTE* fnParam = BuildParameter(&fnParamSize, PARAMETER_ANSISTRING, "Func", "CreateProcessA");
    size_t dllParamSize;
    BYTE* dllParam = BuildParameter(&dllParamSize, PARAMETER_ANSISTRING, "DllName", "kernel32.dll");

    size_t totalParamsSize = param1Size + param2Size + param3Size + fnParamSize + dllParamSize;
    TELEMETRY_HEADER header = GetTelemetryHeader(TM_TYPE_API_CALL, totalParamsSize);

    size_t packetSize = totalParamsSize + sizeof(header);
    BYTE* packet = (BYTE*)malloc(packetSize)

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
    return ((CREATEPROCESSA)HookList[HOOK_CREATE_PROCESS_A].originalFunc)(lpApplicationName, lpCommandLine, lpProcessAttributes,
    lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
}

BOOL CreateProcessW_Handler(
    LPCWSTR                lpApplicationName,
    LPWSTR                 lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL                  bInheritHandles,
    DWORD                 dwCreationFlags,
    LPVOID                lpEnvironment,
    LPCWSTR                lpCurrentDirectory,
    LPSTARTUPINFOW        lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation) {
    // create parameters
    size_t param1Size;
    char* targetPath = WideToAnsi(lpApplicationName);
    BYTE* param1 = BuildParameter(&param1Size, PARAMETER_ANSISTRING, "TargetPath", targetPath);
    size_t param2Size;
    char* cmdLine = WideToAnsi(lpCommandLine);
    BYTE* param2 = BuildParameter(&param2Size, PARAMETER_ANSISTRING, "CmdLine", cmdLine);
    size_t param3Size;
    BYTE* param3 = BuildParameter(&param3Size, PARAMETER_UINT32, "Flags", dwCreationFlags);
    size_t fnParamSize;
    BYTE* fnParam = BuildParameter(&fnParamSize, PARAMETER_ANSISTRING, "Func", "CreateProcessW");
    size_t dllParamSize;
    BYTE* dllParam = BuildParameter(&dllParamSize, PARAMETER_ANSISTRING, "DllName", "kernel32.dll");

    size_t totalParamsSize = param1Size + param2Size + param3Size + fnParamSize + dllParamSize;
    TELEMETRY_HEADER header = GetTelemetryHeader(TM_TYPE_API_CALL, totalParamsSize);

    size_t packetSize = totalParamsSize + sizeof(header);
    BYTE* packet = (BYTE*)malloc(packetSize)

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
    free(targetPath); // allocated string
    free(cmdLine); // allocated string

    EnqueuePacket(g_StandardQueue, packet, packetSize);
    return ((CREATEPROCESSW)HookList[HOOK_CREATE_PROCESS_W].originalFunc)(lpApplicationName, lpCommandLine, lpProcessAttributes,
    lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
}

BOOL CreateProcessAsUserA_Handler(
    HANDLE                hToken,
    LPCSTR                lpApplicationName,
    LPSTR                 lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL                  bInheritHandles,
    DWORD                 dwCreationFlags,
    LPVOID                lpEnvironment,
    LPCSTR                lpCurrentDirectory,
    LPSTARTUPINFOA        lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation) {
    // create parameters
    size_t param1Size;
    BYTE* param1 = BuildParameter(&param1Size, PARAMETER_ANSISTRING, "TargetPath", lpApplicationName);
    size_t param2Size;
    BYTE* param2 = BuildParameter(&param2Size, PARAMETER_ANSISTRING, "CmdLine", lpCommandLine);
    size_t param3Size;
    BYTE* param3 = BuildParameter(&param3Size, PARAMETER_UINT32, "Flags", dwCreationFlags);
    size_t param4Size;
    BYTE* param4 = BuildParameter(&param4Size, PARAMETER_UINT32, "Token", (DWORD)(ULONG_PTR)hToken);
    size_t fnParamSize;
    BYTE* fnParam = BuildParameter(&fnParamSize, PARAMETER_ANSISTRING, "Func", "CreateProcessAsUserA");
    size_t dllParamSize;
    BYTE* dllParam = BuildParameter(&dllParamSize, PARAMETER_ANSISTRING, "DllName", "kernel32.dll");

    size_t totalParamsSize = param1Size + param2Size + param3Size + param4Size + fnParamSize + dllParamSize;
    TELEMETRY_HEADER header = GetTelemetryHeader(TM_TYPE_API_CALL, totalParamsSize);

    size_t packetSize = totalParamsSize + sizeof(header);
    BYTE* packet = (BYTE*)malloc(packetSize)

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
    return ((CREATEPROCESSASUSERA)HookList[HOOK_CREATE_PROCESS_AS_USER_A].originalFunc)(hToken, lpApplicationName, lpCommandLine,
    lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
}

BOOL CreateProcessAsUserW_Handler(
    HANDLE                hToken,
    LPCWSTR                lpApplicationName,
    LPWSTR                 lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL                  bInheritHandles,
    DWORD                 dwCreationFlags,
    LPVOID                lpEnvironment,
    LPCWSTR                lpCurrentDirectory,
    LPSTARTUPINFOW        lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation) {
    // create parameters
    size_t param1Size;
    char* targetPath = WideToAnsi(lpApplicationName);
    BYTE* param1 = BuildParameter(&param1Size, PARAMETER_ANSISTRING, "TargetPath", targetPath);
    size_t param2Size;
    char* cmdLine = WideToAnsi(lpCommandLine);
    BYTE* param2 = BuildParameter(&param2Size, PARAMETER_ANSISTRING, "CmdLine", cmdLine);
    size_t param3Size;
    BYTE* param3 = BuildParameter(&param3Size, PARAMETER_UINT32, "Flags", dwCreationFlags);
    size_t param4Size;
    BYTE* param4 = BuildParameter(&param4Size, PARAMETER_UINT32, "Token", (DWORD)(ULONG_PTR)hToken);
    size_t fnParamSize;
    BYTE* fnParam = BuildParameter(&fnParamSize, PARAMETER_ANSISTRING, "Func", "CreateProcessAsUserW");
    size_t dllParamSize;
    BYTE* dllParam = BuildParameter(&dllParamSize, PARAMETER_ANSISTRING, "DllName", "kernel32.dll");

    size_t totalParamsSize = param1Size + param2Size + param3Size + param4Size + fnParamSize + dllParamSize;
    TELEMETRY_HEADER header = GetTelemetryHeader(TM_TYPE_API_CALL, totalParamsSize);

    size_t packetSize = totalParamsSize + sizeof(header);
    BYTE* packet = (BYTE*)malloc(packetSize)

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
    free(targetPath); // allocated string
    free(cmdLine); // allocated string

    EnqueuePacket(g_StandardQueue, packet, packetSize);
    return ((CREATEPROCESSASUSERW)HookList[HOOK_CREATE_PROCESS_AS_USER_W].originalFunc)(hToken, lpApplicationName, lpCommandLine,
    lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
}


NTSTATUS NtCreateProcess_Handler(
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    PCOBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ParentProcess,
    BOOLEAN InheritObjectTable,
    HANDLE SectionHandle,
    HANDLE DebugPort,
    HANDLE TokenHandle) {
    // create parameters
    size_t param1Size;
    BYTE* param1 = BuildParameter(&param1Size, PARAMETER_UINT32, "ParentPid", GetProcessId(ParentProcess));
    size_t param2Size;
    BYTE* param2 = BuildParameter(&param2Size, PARAMETER_UINT32, "SectionHandle", (DWORD)(ULONG_PTR)SectionHandle);
    size_t param3Size;
    BYTE* param3 = BuildParameter(&param3Size, PARAMETER_UINT32, "Token", (DWORD)(ULONG_PTR)TokenHandle);
    size_t fnParamSize;
    BYTE* fnParam = BuildParameter(&fnParamSize, PARAMETER_ANSISTRING, "Func", "CreateProcessA");
    size_t dllParamSize;
    BYTE* dllParam = BuildParameter(&dllParamSize, PARAMETER_ANSISTRING, "DllName", "kernel32.dll");

    size_t totalParamsSize = param1Size + param2Size + param3Size + fnParamSize + dllParamSize;
    TELEMETRY_HEADER header = GetTelemetryHeader(TM_TYPE_API_CALL, totalParamsSize);

    size_t packetSize = totalParamsSize + sizeof(header);
    BYTE* packet = (BYTE*)malloc(packetSize)

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
    return ((NTCREATEPROCESS)HookList[HOOK_NT_CREATE_PROCESS].originalFunc)(ProcessHandle, DesiredAccess,
        ObjectAttributes, ParentProcess, InheritObjectTable, SectionHandle, DebugPort, TokenHandle);
}

NTSTATUS NtCreateProcessEx_Handler(
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    PCOBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ParentProcess,
    ULONG Flags,
    HANDLE SectionHandle,
    HANDLE DebugPort,
    HANDLE TokenHandle,
    ULONG Reserved) {
    // create parameters
    size_t param1Size;
    BYTE* param1 = BuildParameter(&param1Size, PARAMETER_UINT32, "ParentPid", GetProcessId(ParentProcess));
    size_t param2Size;
    BYTE* param2 = BuildParameter(&param2Size, PARAMETER_UINT32, "Flags", Flags);
    size_t param3Size;
    BYTE* param3 = BuildParameter(&param3Size, PARAMETER_UINT32, "SectionHandle", (DWORD)(ULONG_PTR)SectionHandle);
    size_t param4Size;
    BYTE* param4 = BuildParameter(&param4Size, PARAMETER_UINT32, "Token", (DWORD)(ULONG_PTR)TokenHandle);
    size_t fnParamSize;
    BYTE* fnParam = BuildParameter(&fnParamSize, PARAMETER_ANSISTRING, "Func", "NtCreateProcessEx");
    size_t dllParamSize;
    BYTE* dllParam = BuildParameter(&dllParamSize, PARAMETER_ANSISTRING, "DllName", "ntdll.dll");

    size_t totalParamsSize = param1Size + param2Size + param3Size + param4Size + fnParamSize + dllParamSize;
    TELEMETRY_HEADER header = GetTelemetryHeader(TM_TYPE_API_CALL, totalParamsSize);

    size_t packetSize = totalParamsSize + sizeof(header);
    BYTE* packet = (BYTE*)malloc(packetSize)

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
    return ((NTCREATEPROCESSEX)HookList[HOOK_NT_CREATE_PROCESS_EX].originalFunc)(ProcessHandle, DesiredAccess,
        ObjectAttributes, ParentProcess, Flags, SectionHandle, DebugPort, TokenHandle, Reserved);
}

NTSTATUS NtCreateUserProcess_Handler(
    PHANDLE ProcessHandle,
    PHANDLE ThreadHandle,
    ACCESS_MASK ProcessDesiredAccess,
    ACCESS_MASK ThreadDesiredAccess,
    PCOBJECT_ATTRIBUTES ProcessObjectAttributes,
    PCOBJECT_ATTRIBUTES ThreadObjectAttributes,
    ULONG ProcessFlags, // PROCESS_CREATE_FLAGS_*
    ULONG ThreadFlags, // THREAD_CREATE_FLAGS_*
    void* ProcessParameters, //PTRL_USR_PROCESS_PARAMETERS
    void* CreateInfo, // PPS_CREATE_INFO
    void* AttributeList) {
    // create parameters
    size_t param1Size;
    BYTE* param1 = BuildParameter(&param1Size, PARAMETER_UINT32, "ProcessFlags", ProcessFlags);
    size_t param2Size;
    BYTE* param2 = BuildParameter(&param2Size, PARAMETER_UINT32, "ThreadFlags", ThreadFlags);
    size_t fnParamSize;
    BYTE* fnParam = BuildParameter(&fnParamSize, PARAMETER_ANSISTRING, "Func", "NtCreateUserProcess");
    size_t dllParamSize;
    BYTE* dllParam = BuildParameter(&dllParamSize, PARAMETER_ANSISTRING, "DllName", "ntdll.dll");

    size_t totalParamsSize = param1Size + param2Size + fnParamSize + dllParamSize;
    TELEMETRY_HEADER header = GetTelemetryHeader(TM_TYPE_API_CALL, totalParamsSize);

    size_t packetSize = totalParamsSize + sizeof(header);
    BYTE* packet = (BYTE*)malloc(packetSize)

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
    return ((NTCREATEUSERPROCESS)HookList[HOOK_NT_CREATE_USER_PROCESS].originalFunc)(ProcessHandle, ThreadHandle,
        ProcessDesiredAccess, ThreadDesiredAccess, ProcessObjectAttributes, ThreadObjectAttributes, ProcessFlags, ThreadFlags, ProcessParameters, CreateInfo, AttributeList);
}

//*==================[ Open Process ]=============================

HANDLE OpenProcess_Handler(DWORD access, BOOL inherit, DWORD pid) {
    // create parameters
    size_t param1Size;
    BYTE* param1 = BuildParameter(&param1Size, PARAMETER_UINT32, "Access", access);
    size_t param2Size;
    BYTE* param2 = BuildParameter(&param2Size, PARAMETER_UINT32, "TargetPid", pid);
    size_t fnParamSize;
    BYTE* fnParam = BuildParameter(&fnParamSize, PARAMETER_ANSISTRING, "Func", "OpenProcess");
    size_t dllParamSize;
    BYTE* dllParam = BuildParameter(&dllParamSize, PARAMETER_ANSISTRING, "DllName", "kernel32.dll");

    size_t totalParamsSize = param1Size + param2Size + fnParamSize + dllParamSize;
    TELEMETRY_HEADER header = GetTelemetryHeader(TM_TYPE_API_CALL, totalParamsSize);

    size_t packetSize = totalParamsSize + sizeof(header);
    BYTE* packet = (BYTE*)malloc(packetSize)

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
    return ((OPENPROCESS)HookList[HOOK_OPEN_PROCESS].originalFunc)(access, inherit, pid);
}

NTSTATUS NtOpenProcess_Handler(
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    PCOBJECT_ATTRIBUTES ObjectAttributes,
    PCLIENT_ID ClientId) {
    // create parameters
    size_t param1Size;
    BYTE* param1 = BuildParameter(&param1Size, PARAMETER_UINT32, "Access", DesiredAccess);
    size_t param2Size;
    BYTE* param2 = BuildParameter(&param2Size, PARAMETER_UINT32, "TargetPid", (DWORD)(ULONG_PTR))ClientId->UniqueProcess;
    size_t fnParamSize;
    BYTE* fnParam = BuildParameter(&fnParamSize, PARAMETER_ANSISTRING, "Func", "NtOpenProcess");
    size_t dllParamSize;
    BYTE* dllParam = BuildParameter(&dllParamSize, PARAMETER_ANSISTRING, "DllName", "ntdll.dll");

    size_t totalParamsSize = param1Size + param2Size + fnParamSize + dllParamSize;
    TELEMETRY_HEADER header = GetTelemetryHeader(TM_TYPE_API_CALL, totalParamsSize);

    size_t packetSize = totalParamsSize + sizeof(header);
    BYTE* packet = (BYTE*)malloc(packetSize)

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
    return ((NTOPENPROCESS)HookList[HOOK_NT_OPEN_PROCESS].originalFunc)(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
}

//*==================[ Process Properties ]=============================

BOOL TerminateProcess_Handler(HANDLE hProcess, UINT uExitCode) {
    // create parameters
    size_t param1Size;
    DWORD pid = GetProcessId(hProcess);
    BYTE* param1 = BuildParameter(&param1Size, PARAMETER_UINT32, "TargetPid", pid);
    size_t fnParamSize;
    BYTE* fnParam = BuildParameter(&fnParamSize, PARAMETER_ANSISTRING, "Func", "TerminateProcess");
    size_t dllParamSize;
    BYTE* dllParam = BuildParameter(&dllParamSize, PARAMETER_ANSISTRING, "DllName", "kernel32.dll");

    size_t totalParamsSize = param1Size + fnParamSize + dllParamSize;
    TELEMETRY_HEADER header = GetTelemetryHeader(TM_TYPE_API_CALL, totalParamsSize);

    size_t packetSize = totalParamsSize + sizeof(header);
    BYTE* packet = (BYTE*)malloc(packetSize)

    // construct packet 
    memcpy(packet, &header, sizeof(header));
    memcpy(packet + sizeof(header), param1, param1Size);
    memcpy(packet + sizeof(header) + param1Size, fnParam, fnParamSize);
    memcpy(packet + sizeof(header) + param1Size + fnParamSize, dllParam, dllParamSize);

    free(param1);
    free(fnParam);
    free(dllParam);

    EnqueuePacket(g_StandardQueue, packet, packetSize);
    if (IsEdrProcess(pid)) {
        return ERROR_ACCESS_DENIED;
    }
    return ((TERMINATEPROCESS)HookList[HOOK_TERMINATE_PROCESS].originalFunc)(hProcess, uExitCode);
}

NTSTATUS NtTerminateProcess_Handler(HANDLE hProcess, NTSTATUS ExitStatus) {
    // create parameters
    size_t param1Size;
    DWORD pid = GetProcessId(hProcess);
    BYTE* param1 = BuildParameter(&param1Size, PARAMETER_UINT32, "TargetPid", pid);
    size_t fnParamSize;
    BYTE* fnParam = BuildParameter(&fnParamSize, PARAMETER_ANSISTRING, "Func", "NtTerminateProcess");
    size_t dllParamSize;
    BYTE* dllParam = BuildParameter(&dllParamSize, PARAMETER_ANSISTRING, "DllName", "ntdll.dll");

    size_t totalParamsSize = param1Size + fnParamSize + dllParamSize;
    TELEMETRY_HEADER header = GetTelemetryHeader(TM_TYPE_API_CALL, totalParamsSize);

    size_t packetSize = totalParamsSize + sizeof(header);
    BYTE* packet = (BYTE*)malloc(packetSize)

    // construct packet 
    memcpy(packet, &header, sizeof(header));
    memcpy(packet + sizeof(header), param1, param1Size);
    memcpy(packet + sizeof(header) + param1Size, fnParam, fnParamSize);
    memcpy(packet + sizeof(header) + param1Size + fnParamSize, dllParam, dllParamSize);

    free(param1);
    free(fnParam);
    free(dllParam);

    EnqueuePacket(g_StandardQueue, packet, packetSize);
    if (IsEdrProcess(pid)) {
        return ERROR_ACCESS_DENIED;
    }
    return ((NTTERMINATEPROCESS)HookList[HOOK_NT_TERMINATE_PROCESS].originalFunc)(hProcess, ExitStatus);
}


NTSTATUS NtSuspendProcess_Handler(HANDLE hProcess) {
    // create parameters
    size_t param1Size;
    DWORD pid = GetProcessId(hProcess);
    BYTE* param1 = BuildParameter(&param1Size, PARAMETER_UINT32, "TargetPid", pid);
    size_t fnParamSize;
    BYTE* fnParam = BuildParameter(&fnParamSize, PARAMETER_ANSISTRING, "Func", "NtSuspendProcess");
    size_t dllParamSize;
    BYTE* dllParam = BuildParameter(&dllParamSize, PARAMETER_ANSISTRING, "DllName", "ntdll.dll");

    size_t totalParamsSize = param1Size + fnParamSize + dllParamSize;
    TELEMETRY_HEADER header = GetTelemetryHeader(TM_TYPE_API_CALL, totalParamsSize);

    size_t packetSize = totalParamsSize + sizeof(header);
    BYTE* packet = (BYTE*)malloc(packetSize)

    // construct packet 
    memcpy(packet, &header, sizeof(header));
    memcpy(packet + sizeof(header), param1, param1Size);
    memcpy(packet + sizeof(header) + param1Size, fnParam, fnParamSize);
    memcpy(packet + sizeof(header) + param1Size + fnParamSize, dllParam, dllParamSize);

    free(param1);
    free(fnParam);
    free(dllParam);

    EnqueuePacket(g_StandardQueue, packet, packetSize);
    if (IsEdrProcess(pid)) {
        return ERROR_ACCESS_DENIED;
    }
    return ((NTSUSPENDPROCESS)HookList[HOOK_NT_SUSPEND_PROCESS].originalFunc)(hProcess);
}

NTSTATUS NtResumeProcess_Handler(HANDLE hProcess) {
    // create parameters
    size_t param1Size;
    DWORD pid = GetProcessId(hProcess);
    BYTE* param1 = BuildParameter(&param1Size, PARAMETER_UINT32, "TargetPid", pid);
    size_t fnParamSize;
    BYTE* fnParam = BuildParameter(&fnParamSize, PARAMETER_ANSISTRING, "Func", "NtResumeProcess");
    size_t dllParamSize;
    BYTE* dllParam = BuildParameter(&dllParamSize, PARAMETER_ANSISTRING, "DllName", "ntdll.dll");

    size_t totalParamsSize = param1Size + fnParamSize + dllParamSize;
    TELEMETRY_HEADER header = GetTelemetryHeader(TM_TYPE_API_CALL, totalParamsSize);

    size_t packetSize = totalParamsSize + sizeof(header);
    BYTE* packet = (BYTE*)malloc(packetSize)

    // construct packet 
    memcpy(packet, &header, sizeof(header));
    memcpy(packet + sizeof(header), param1, param1Size);
    memcpy(packet + sizeof(header) + param1Size, fnParam, fnParamSize);
    memcpy(packet + sizeof(header) + param1Size + fnParamSize, dllParam, dllParamSize);

    free(param1);
    free(fnParam);
    free(dllParam);

    EnqueuePacket(g_StandardQueue, packet, packetSize);
    if (IsEdrProcess(pid)) {
        return ERROR_ACCESS_DENIED;
    }
    return ((NTRESUMEPROCESS)HookList[HOOK_NT_RESUME_PROCESS].originalFunc)(hProcess);
}

NTSTATUS NtSetInformationProcess_Handler(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength) {
    // create parameters
    size_t param1Size;
    BYTE* param1 = BuildParameter(&param1Size, PARAMETER_UINT32, "TargetPid", GetProcessId(ProcessHandle));
    size_t param2Size;
    BYTE* param2 = BuildParameter(&param2Size, PARAMETER_UINT32, "InfoClass", ProcessInformationClass);
    size_t fnParamSize;
    BYTE* fnParam = BuildParameter(&fnParamSize, PARAMETER_ANSISTRING, "Func", "NtSetInformationProcess");
    size_t dllParamSize;
    BYTE* dllParam = BuildParameter(&dllParamSize, PARAMETER_ANSISTRING, "DllName", "ntdll.dll");

    size_t totalParamsSize = param1Size + param2Size + fnParamSize + dllParamSize;
    TELEMETRY_HEADER header = GetTelemetryHeader(TM_TYPE_API_CALL, totalParamsSize);

    size_t packetSize = totalParamsSize + sizeof(header);
    BYTE* packet = (BYTE*)malloc(packetSize)

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

    EnqueuePacket(g_CriticalQueue, packet, packetSize);
    return ((NTSETINFOPROCESS)HookList[HOOK_NT_SET_INFO_PROCESS].originalFunc)(ProcessHandle,
        ProcessInformationClass, ProcessInformation, ProcessInformationLength);
}