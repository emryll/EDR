#include <windows.h>
#include <winternl.h>
#include "hook.h"

//*==============================[ Opening Thread ]================================

HANDLE OpenThread_Handler(DWORD DesiredAccess, BOOL InheritHandle, DWORD ThreadId) {
    // need to get handle in advance for pid
    HANDLE hThread = ((OPENTHREAD)HookList[HOOK_OPEN_THREAD].originalFunc)(DesiredAccess, InheritHandle, ThreadId);       
    DWORD pid = GetProcessIdOfThread(hThread);

    size_t param1Size;
    BYTE* param1 = BuildParameter(&param1Size, PARAMETER_UINT32, "TargetTid", ThreadId);
    size_t param2Size;
    BYTE* param2 = BuildParameter(&param2Size, PARAMETER_UINT32, "TargetPid", pid);
    size_t param3Size;
    BYTE* param3 = BuildParameter(&param3Size, PARAMETER_UINT32, "Access", DesiredAccess);
    size_t fnParamSize;
    BYTE* fnParam = BuildParameter(&fnParamSize, PARAMETER_ANSISTRING, "Func", "OpenThread");
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
    return hThread;
}

NTSTATUS NtOpenThread_Handler(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, PCOBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId) {
    // need to get handle in advance for pid
    NTSTATUS status = ((NTOPENTHREAD)HookList[HOOK_NT_OPEN_THREAD].originalFunc)(ThreadHandle, DesiredAccess, ObjectAttributes, ClientId);       
    DWORD pid = GetProcessIdOfThread(ThreadHandle);

    size_t param1Size;
    BYTE* param1 = BuildParameter(&param1Size, PARAMETER_UINT32, "TargetTid", GetThreadId(ThreadHandle));
    size_t param2Size;
    BYTE* param2 = BuildParameter(&param2Size, PARAMETER_UINT32, "TargetPid", pid);
    size_t param3Size;
    BYTE* param3 = BuildParameter(&param3Size, PARAMETER_UINT32, "Access", DesiredAccess);
    size_t fnParamSize;
    BYTE* fnParam = BuildParameter(&fnParamSize, PARAMETER_ANSISTRING, "Func", "NtOpenThread");
    size_t dllParamSize;
    BYTE* dllParam = BuildParameter(&dllParamSize, PARAMETER_ANSISTRING, "DllName", "ntdll.dll");

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
    return status;
}

//*============================[ Creating Threads ]=====================================

LPVOID CreateFiber_Handler(
    SIZE_T                dwStackSize,
    LPFIBER_START_ROUTINE lpStartAddress,
    LPVOID                lpParameter) {

    size_t param1Size;
    BYTE* param1 = BuildParameter(&param1Size, PARAMETER_POINTER, "Address", lpStartAddress);
    size_t fnParamSize;
    BYTE* fnParam = BuildParameter(&fnParamSize, PARAMETER_ANSISTRING, "Func", "CreateFiber");
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
    return ((CREATEFIBER)HookList[HOOK_CREATE_FIBER].originalFunc)(dwStackSize, lpStartAddress, lpParameter);       
}

LPVOID CreateFiberEx_Handler(
    SIZE_T                dwStackCommitSize,
    SIZE_T                dwStackReserveSize,
    DWORD                 dwFlags,
    LPFIBER_START_ROUTINE lpStartAddress,
    LPVOID                lpParameter) {

    size_t param1Size;
    BYTE* param1 = BuildParameter(&param1Size, PARAMETER_UINT32, "Flags", dwFlags);
    size_t param2Size;
    BYTE* param2 = BuildParameter(&param2Size, PARAMETER_POINTER, "Address", lpStartAddress);
    size_t fnParamSize;
    BYTE* fnParam = BuildParameter(&fnParamSize, PARAMETER_ANSISTRING, "Func", "CreateFiberEx");
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
    return ((CREATEFIBEREX)HookList[HOOK_CREATE_FIBER_EX].originalFunc)(dwStackCommitSize, dwStackReserveSize, dwFlags, lpStartAddress, lpParameter);
}

HANDLE CreateThread_Handler(
    LPSECURITY_ATTRIBUTES   lpThreadAttributes,
    SIZE_T                  dwStackSize,
    LPTHREAD_START_ROUTINE  lpStartAddress,
    LPVOID                  lpParameter,
    DWORD                   dwCreationFlags,
    LPDWORD                 lpThreadId) {

    size_t param1Size;
    BYTE* param1 = BuildParameter(&param1Size, PARAMETER_UINT32, "Flags", dwCreationFlags);
    size_t param2Size;
    BYTE* param2 = BuildParameter(&param2Size, PARAMETER_POINTER, "Address", lpStartAddress);
    size_t fnParamSize;
    BYTE* fnParam = BuildParameter(&fnParamSize, PARAMETER_ANSISTRING, "Func", "CreateThread");
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
    return ((CREATETHREAD)HookList[HOOK_CREATE_THREAD].originalFunc)(lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId);
}


HANDLE CreateRemoteThread_Handler(
    HANDLE                 hProcess,
    LPSECURITY_ATTRIBUTES  lpThreadAttributes,
    SIZE_T                 dwStackSize,
    LPTHREAD_START_ROUTINE lpStartAddress,
    LPVOID                 lpParameter,
    DWORD                  dwCreationFlags,
    LPDWORD                lpThreadId) {
    size_t param1Size;
    BYTE* param1 = BuildParameter(&param1Size, PARAMETER_UINT32, "Flags", dwCreationFlags);
    size_t param2Size;
    BYTE* param2 = BuildParameter(&param2Size, PARAMETER_POINTER, "Address", lpStartAddress);
    DWORD pid = GetProcessId(hProcess);
    size_t param3Size;
    BYTE* param3 = BuildParameter(&param3Size, PARAMETER_UINT32, "TargetPid", pid);
    size_t fnParamSize;
    BYTE* fnParam = BuildParameter(&fnParamSize, PARAMETER_ANSISTRING, "Func", "CreateRemoteThread");
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

    EnqueuePacket(g_CriticalQueue, packet, packetSize);
    // detect DLL hijacking by checking if start address is LoadLibrary*
    if (PointsToLibraryLoad(lpStartAddress)) {
        printf("\nDetected thread creation attempt in LoadLibrary address, access denied.\n");
        SendDllInjectionAlert();
        SetLastError(ERROR_ACCESS_DENIED);
        return NULL;
    }
    return ((CREATEREMOTETHREAD)HookList[HOOK_CREATE_REMOTE_THREAD].originalFunc)(hProcess, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId);
}

HANDLE CreateRemoteThreadEx_Handler(
    HANDLE                       hProcess,
    LPSECURITY_ATTRIBUTES        lpThreadAttributes,
    SIZE_T                       dwStackSize,
    LPTHREAD_START_ROUTINE       lpStartAddress,
    LPVOID                       lpParameter,
    DWORD                        dwCreationFlags,
    LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList,
    LPDWORD                      lpThreadId) {

    size_t param1Size;
    BYTE* param1 = BuildParameter(&param1Size, PARAMETER_UINT32, "Flags", dwCreationFlags);
    size_t param2Size;
    BYTE* param2 = BuildParameter(&param2Size, PARAMETER_POINTER, "Address", lpStartAddress);
    DWORD pid = GetProcessId(hProcess);
    size_t param3Size;
    BYTE* param3 = BuildParameter(&param3Size, PARAMETER_UINT32, "TargetPid", pid);
    size_t fnParamSize;
    BYTE* fnParam = BuildParameter(&fnParamSize, PARAMETER_ANSISTRING, "Func", "CreateRemoteThreadEx");
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

    EnqueuePacket(g_CriticalQueue, packet, packetSize);

    // detect DLL hijacking by checking if start address is LoadLibrary*
    if (PointsToLibraryLoad(lpStartAddress)) {
        printf("\nDetected thread creation attempt in LoadLibrary address, access denied.\n");
        SendDllInjectionAlert();
        SetLastError(ERROR_ACCESS_DENIED);
        return NULL;
    } else {
        return ((CREATEREMOTETHREADEX)HookList[HOOK_CREATE_REMOTE_THREAD_EX].originalFunc)(hProcess, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpAttributeList, lpThreadId);
    }
}

NTSTATUS NtCreateThread_Handler(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    PCOBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ProcessHandle,
    PCLIENT_ID ClientId,
    PCONTEXT ThreadContext,
    void* InitialTeb, //PINITIAL_TEB
    BOOL CreateSuspended) {
    if (GetProcessId(ProcessHandle) == GetCurrentProcessId()) {
    return ((NTCREATETHREAD)HookList[HOOK_NT_CREATE_THREAD].originalFunc)(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, ClientId, ThreadContext, InitialTeb, CreateSuspended);
    }

    // create parameters
    size_t param1Size;
    BYTE* param1 = BuildParameter(&param1Size, PARAMETER_POINTER, "Address", ThreadContext->Rip);
    size_t param2Size; //TODO: should this be in flags instead?
    BYTE* param2 = BuildParameter(&param2Size, PARAMETER_BOOLEAN, "CreateSuspended", CreateSuspended);
    size_t param3Size;
    GetProcessId(ProcessHandle);
    BYTE* param3 = BuildParameter(&param3Size, PARAMETER_UINT32, "TargetPid", pid);
    size_t fnParamSize;
    BYTE* fnParam = BuildParameter(&fnParamSize, PARAMETER_ANSISTRING, "Func", "NtCreateThread");
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

    EnqueuePacket(g_CriticalQueue, packet, packetSize);
    // detect DLL hijacking by checking if start address is LoadLibrary*
    if (PointsToLibraryLoad(ThreadContext->Rip)) {
        printf("\nDetected thread creation attempt in LoadLibrary address, access denied.\n");
        SendDllInjectionAlert();
        SetLastError(ERROR_ACCESS_DENIED);
        return NULL;
    }
    return ((NTCREATETHREAD)HookList[HOOK_NT_CREATE_THREAD].originalFunc)(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, ClientId, ThreadContext, InitialTeb, CreateSuspended);
}

NTSTATUS NtCreateThreadEx_Handler(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    PCOBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ProcessHandle,
    void* StartRoutine, //PUSER_THREAD_START_ROUTINE
    PVOID Argument,
    ULONG CreateFlags,
    SIZE_T ZeroBits,
    SIZE_T StackSize,
    SIZE_T MaximumStackSize,
    void* AttributeList) { // PPS_ATTRIBUTE_LIST

    // create parameters
    size_t param1Size;
    BYTE* param1 = BuildParameter(&param1Size, PARAMETER_POINTER, "Address", StartRoutine);
    size_t param2Size;
    BYTE* param2 = BuildParameter(&param2Size, PARAMETER_UINT32, "Flags", CreateFlags);
    size_t param3Size;
    GetProcessId(ProcessHandle);
    BYTE* param3 = BuildParameter(&param3Size, PARAMETER_UINT32, "TargetPid", pid);
    size_t fnParamSize;
    BYTE* fnParam = BuildParameter(&fnParamSize, PARAMETER_ANSISTRING, "Func", "NtCreateThreadEx");
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

    EnqueuePacket(g_CriticalQueue, packet, packetSize);
    // detect DLL hijacking by checking if start address is LoadLibrary*
    if (PointsToLibraryLoad(StartRoutine)) {
        printf("\nDetected thread creation attempt in LoadLibrary address, access denied.\n");
        SendDllInjectionAlert();
        SetLastError(ERROR_ACCESS_DENIED);
        return NULL;
    }
    return ((NTCREATETHREADEX)HookList[HOOK_NT_CREATE_THREAD_EX].originalFunc)(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, StartRoutine, Argument, CreateFlags, ZeroBits, StackSize, MaximumStackSize, AttributeList);
}

//*==============================[ APC Queueing ]================================

DWORD QueueUserAPC_Handler(PAPCFUNC pfnAPC, HANDLE hThread, ULONG_PTR dwData) {
    // create parameters
    size_t param1Size;
    BYTE* param1 = BuildParameter(&param1Size, PARAMETER_POINTER, "Address", pfnAPC);
    size_t param2Size;
    BYTE* param2 = BuildParameter(&param2Size, PARAMETER_UINT32, "TargetTid", GetThreadId(hThread));
    size_t param3Size;
    BYTE* param3 = BuildParameter(&param3Size, PARAMETER_UINT32, "TargetPid", GetProcessIdOfThread(hThread));
    size_t fnParamSize;
    BYTE* fnParam = BuildParameter(&fnParamSize, PARAMETER_ANSISTRING, "Func", "QueueUserAPC");
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

    EnqueuePacket(g_CriticalQueue, packet, packetSize);
    if (PointsToLibraryLoad(pfnAPC)) {
        printf("\nDetected thread creation attempt in LoadLibrary address, access denied.\n");
        SendDllInjectionAlert();
        SetLastError(ERROR_ACCESS_DENIED);
        return NULL;
    }
    return ((QUEUEUSERAPC)HookList[HOOK_QUEUE_USER_APC].originalFunc)(pfnAPC, hThread, dwData);
}

BOOL QueueUserAPC2_Handler(PAPCFUNC ApcRoutine, HANDLE Thread, ULONG_PTR Data, QUEUE_USER_APC_FLAGS Flags) {
    // create parameters
    size_t param1Size;
    BYTE* param1 = BuildParameter(&param1Size, PARAMETER_POINTER, "Address", ApcRoutine);
    size_t param2Size;
    BYTE* param2 = BuildParameter(&param2Size, PARAMETER_UINT32, "TargetTid", GetThreadId(Thread));
    size_t param3Size;
    BYTE* param3 = BuildParameter(&param3Size, PARAMETER_UINT32, "TargetPid", GetProcessIdOfThread(Thread));
    size_t param4Size;
    BYTE* param4 = BuildParameter(&param4Size, PARAMETER_UINT32, "Flags", Flags);
    size_t fnParamSize;
    BYTE* fnParam = BuildParameter(&fnParamSize, PARAMETER_ANSISTRING, "Func", "QueueUserAPC2");
    size_t dllParamSize;
    BYTE* dllParam = BuildParameter(&dllParamSize, PARAMETER_ANSISTRING, "DllName", "kernel32.dll");

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

    EnqueuePacket(g_CriticalQueue, packet, packetSize);
    if (PointsToLibraryLoad(ApcRoutine)) {
        printf("\nDetected thread creation attempt in LoadLibrary address, access denied.\n");
        SendDllInjectionAlert();
        SetLastError(ERROR_ACCESS_DENIED);
        return NULL;
    }
    return ((QUEUEUSERAPC2)HookList[HOOK_QUEUE_USER_APC2].originalFunc)(ApcRoutine, Thread, Data, Flags);
}

NTSTATUS NtQueueApcThread_Handler(HANDLE Thread, PPS_APC_ROUTINE ApcRoutine, PVOID ApcArgument1, PVOID ApcArgument2, PVOID ApcArgument3) {
    // create parameters
    size_t param1Size;
    BYTE* param1 = BuildParameter(&param1Size, PARAMETER_POINTER, "Address", ApcRoutine);
    size_t param2Size;
    BYTE* param2 = BuildParameter(&param2Size, PARAMETER_UINT32, "TargetTid", GetThreadId(Thread));
    size_t param3Size;
    BYTE* param3 = BuildParameter(&param3Size, PARAMETER_UINT32, "TargetPid", GetProcessIdOfThread(Thread));
    size_t fnParamSize;
    BYTE* fnParam = BuildParameter(&fnParamSize, PARAMETER_ANSISTRING, "Func", "NtQueueApcThread");
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

    EnqueuePacket(g_CriticalQueue, packet, packetSize);
    if (PointsToLibraryLoad(ApcRoutine)) {
        printf("\nDetected thread creation attempt in LoadLibrary address, access denied.\n");
        SendDllInjectionAlert();
        SetLastError(ERROR_ACCESS_DENIED);
        return NULL;
    }
    return ((NTQUEUEAPCTHREAD)HookList[HOOK_NT_QUEUE_APC_THREAD].originalFunc)(Thread, ApcRoutine, ApcArgument1, ApcArgument2, ApcArgument3);
}

NTSTATUS NtQueueApcThreadEx_Handler(HANDLE Thread, HANDLE ReserveHandle, PPS_APC_ROUTINE ApcRoutine, PVOID ApcArgument1, PVOID ApcArgument2, PVOID ApcArgument3) {
    // create parameters
    size_t param1Size;
    BYTE* param1 = BuildParameter(&param1Size, PARAMETER_POINTER, "Address", ApcRoutine);
    size_t param2Size;
    BYTE* param2 = BuildParameter(&param2Size, PARAMETER_UINT32, "TargetTid", GetThreadId(Thread));
    size_t param3Size;
    BYTE* param3 = BuildParameter(&param3Size, PARAMETER_UINT32, "TargetPid", GetProcessIdOfThread(Thread));
    size_t fnParamSize;
    BYTE* fnParam = BuildParameter(&fnParamSize, PARAMETER_ANSISTRING, "Func", "NtQueueApcThreadEx");
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

    EnqueuePacket(g_CriticalQueue, packet, packetSize);
    if (PointsToLibraryLoad(ApcRoutine)) {
        printf("\nDetected thread creation attempt in LoadLibrary address, access denied.\n");
        SendDllInjectionAlert();
        SetLastError(ERROR_ACCESS_DENIED);
        return NULL;
    }
    return ((NTQUEUEAPCTHREADEX)HookList[HOOK_NT_QUEUE_APC_THREAD_EX].originalFunc)(Thread, ReserveHandle, ApcRoutine, ApcArgument1, ApcArgument2, ApcArgument3);
}

NTSTATUS NtQueueApcThreadEx2_Handler(HANDLE Thread, HANDLE ReserveHandle, ULONG Flags, PPS_APC_ROUTINE ApcRoutine, PVOID ApcArgument1, PVOID ApcArgument2, PVOID ApcArgument3) {
    // create parameters
    size_t param1Size;
    BYTE* param1 = BuildParameter(&param1Size, PARAMETER_POINTER, "Address", ApcRoutine);
    size_t param2Size;
    BYTE* param2 = BuildParameter(&param2Size, PARAMETER_UINT32, "TargetTid", GetThreadId(Thread));
    size_t param3Size;
    BYTE* param3 = BuildParameter(&param3Size, PARAMETER_UINT32, "TargetPid", GetProcessIdOfThread(Thread));
    size_t param4Size;
    BYTE* param4 = BuildParameter(&param4Size, PARAMETER_UINT32, "Flags", Flags);
    size_t fnParamSize;
    BYTE* fnParam = BuildParameter(&fnParamSize, PARAMETER_ANSISTRING, "Func", "NtQueueApcThreadEx2");
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

    EnqueuePacket(g_CriticalQueue, packet, packetSize);
    if (PointsToLibraryLoad(ApcRoutine)) {
        printf("\nDetected thread creation attempt in LoadLibrary address, access denied.\n");
        SendDllInjectionAlert();
        SetLastError(ERROR_ACCESS_DENIED);
        return NULL;
    }
    return ((NTQUEUEAPCTHREADEX2)HookList[HOOK_NT_QUEUE_APC_THREAD_EX2].originalFunc)(Thread, ReserveHandle, Flags, ApcRoutine, ApcArgument1, ApcArgument2, ApcArgument3);
}

//*===========================[ Thread Properties ]===============================

BOOL SetThreadContext_Handler(HANDLE hThread, const CONTEXT* lpContext) {
    // create parameters
    size_t param1Size;
    BYTE* param1 = BuildParameter(&param1Size, PARAMETER_POINTER, "Address", lpContext->Rip);
    size_t param2Size;
    BYTE* param2 = BuildParameter(&param2Size, PARAMETER_UINT32, "TargetTid", GetThreadId(hThread));
    size_t param3Size;
    BYTE* param3 = BuildParameter(&param3Size, PARAMETER_UINT32, "TargetPid", GetProcessIdOfThread(hThread));
    size_t fnParamSize;
    BYTE* fnParam = BuildParameter(&fnParamSize, PARAMETER_ANSISTRING, "Func", "SetThreadContext");
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

    EnqueuePacket(g_CriticalQueue, packet, packetSize);
    if (PointsToLibraryLoad(lpContext->Rip)) {
        printf("\nDetected thread creation attempt in LoadLibrary address, access denied.\n");
        SendDllInjectionAlert();
        SetLastError(ERROR_ACCESS_DENIED);
        return NULL;
    }
    return ((SETTHREADCONTEXT)HookList[HOOK_SET_THREAD_CONTEXT].originalFunc)(hThread, lpContext);
}

BOOL GetThreadContext_Handler(HANDLE hThread, LPCONTEXT lpContext) {
    // create parameters
    size_t param1Size;
    BYTE* param1 = BuildParameter(&param1Size, PARAMETER_UINT32, "TargetTid", GetThreadId(hThread));
    size_t param2Size;
    BYTE* param2 = BuildParameter(&param2Size, PARAMETER_UINT32, "TargetPid", GetProcessIdOfThread(hThread));
    size_t fnParamSize;
    BYTE* fnParam = BuildParameter(&fnParamSize, PARAMETER_ANSISTRING, "Func", "GetThreadContext");
    size_t dllParamSize;
    BYTE* dllParam = BuildParameter(&dllParamSize, PARAMETER_ANSISTRING, "DllName", "kernel32.dll");

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
    return ((GETTHREADCONTEXT)HookList[HOOK_GET_THREAD_CONTEXT].originalFunc)(hThread, lpContext);
}

NTSTATUS NtSetContextThread_Handler(HANDLE Thread, PCONTEXT Context) {
    // create parameters
    size_t param1Size;
    BYTE* param1 = BuildParameter(&param1Size, PARAMETER_POINTER, "Address", Context->Rip);
    size_t param2Size;
    BYTE* param2 = BuildParameter(&param2Size, PARAMETER_UINT32, "TargetTid", GetThreadId(Thread));
    size_t param3Size;
    BYTE* param3 = BuildParameter(&param3Size, PARAMETER_UINT32, "TargetPid", GetProcessIdOfThread(Thread));
    size_t fnParamSize;
    BYTE* fnParam = BuildParameter(&fnParamSize, PARAMETER_ANSISTRING, "Func", "NtSetContextThread");
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

    EnqueuePacket(g_CriticalQueue, packet, packetSize);
    if (PointsToLibraryLoad(Context->Rip)) {
        printf("\nDetected thread creation attempt in LoadLibrary address, access denied.\n");
        SendDllInjectionAlert();
        SetLastError(ERROR_ACCESS_DENIED);
        return NULL;
    }
    return ((NTSETCONTEXTTHREAD)HookList[HOOK_SET_CONTEXT_THREAD].originalFunc)(Thread, Context);
}

NTSTATUS NtGetContextThread_Handler(HANDLE Thread, PCONTEXT Context) {
    // create parameters
    size_t param1Size;
    BYTE* param1 = BuildParameter(&param1Size, PARAMETER_UINT32, "TargetPid", GetProcessIdOfThread(Thread));
    size_t param2Size;
    BYTE* param2 = BuildParameter(&param2Size, PARAMETER_UINT32, "TargetTid", GetThreadId(Thread));
    size_t fnParamSize;
    BYTE* fnParam = BuildParameter(&fnParamSize, PARAMETER_ANSISTRING, "Func", "NtGetContextThread");
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
    return ((NTGETCONTEXTTHREAD)HookList[HOOK_GET_CONTEXT_THREAD].originalFunc)(Thread, Context);
}

HRESULT SetThreadDescription_Handler(HANDLE Thread, PCWSTR Description) {
    // create parameters
    size_t param1Size;
    BYTE* param1 = BuildParameter(&param1Size, PARAMETER_UINT32, "TargetPid", GetProcessIdOfThread(Thread));
    size_t param2Size;
    BYTE* param2 = BuildParameter(&param2Size, PARAMETER_UINT32, "TargetTid", GetThreadId(Thread));
    size_t fnParamSize;
    BYTE* fnParam = BuildParameter(&fnParamSize, PARAMETER_ANSISTRING, "Func", "SetThreadDescription");
    size_t dllParamSize;
    BYTE* dllParam = BuildParameter(&dllParamSize, PARAMETER_ANSISTRING, "DllName", "kernel32.dll");

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
    return ((SETTHREADDESCRIPTION)HookList[HOOK_SET_THREAD_DESCRIPTION].originalFunc)(Thread, Description);
}

HRESULT GetThreadDescription_Handler(HANDLE Thread, PWSTR* Description) {
    // create parameters
    size_t param1Size;
    BYTE* param1 = BuildParameter(&param1Size, PARAMETER_UINT32, "TargetPid", GetProcessIdOfThread(Thread));
    size_t param2Size;
    BYTE* param2 = BuildParameter(&param2Size, PARAMETER_UINT32, "TargetTid", GetThreadId(Thread));
    size_t fnParamSize;
    BYTE* fnParam = BuildParameter(&fnParamSize, PARAMETER_ANSISTRING, "Func", "GetThreadDescription");
    size_t dllParamSize;
    BYTE* dllParam = BuildParameter(&dllParamSize, PARAMETER_ANSISTRING, "DllName", "kernel32.dll");

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
    return ((GETTHREADDESCRIPTION)HookList[HOOK_GET_THREAD_DESCRIPTION].originalFunc)(Thread, Description);
}

NTSTATUS NtSetInformationThread_Handler(
    HANDLE ThreadHandle,
    THREADINFOCLASS ThreadInfoClass,
    PVOID ThreadInformation,
    ULONG ThreadInfoLength) {

    // create parameters
    size_t param1Size;
    BYTE* param1 = BuildParameter(&param1Size, PARAMETER_UINT32, "TargetPid", GetProcessIdOfThread(ThreadHandle));
    size_t param2Size;
    BYTE* param2 = BuildParameter(&param2Size, PARAMETER_UINT32, "TargetTid", GetThreadId(ThreadHandle));
    size_t param3Size;
    BYTE* param3 = BuildParameter(&param3Size, PARAMETER_UINT32, "InfoClass", ThreadInfoClass);
    size_t fnParamSize;
    BYTE* fnParam = BuildParameter(&fnParamSize, PARAMETER_ANSISTRING, "Func", "NtSetInformationThread");
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

    EnqueuePacket(g_CriticalQueue, packet, packetSize);
    return ((NTSETINFOTHREAD)HookList[HOOK_NT_SET_INFO_THREAD].originalFunc)(ThreadHandle, ThreadInfoClass, ThreadInformation, ThreadInfoLength);
}

NTSTATUS NtSetThreadExecutionState_Handler(EXECUTION_STATE NewFlags, EXECUTION_STATE* PreviousFlags) {
    // create parameters
    size_t param1Size;
    BYTE* param1 = BuildParameter(&param1Size, PARAMETER_UINT32, "Flags", NewFlags);
    size_t fnParamSize;
    BYTE* fnParam = BuildParameter(&fnParamSize, PARAMETER_ANSISTRING, "Func", "NtSetThreadExecutionState");
    size_t dllParamSize;
    BYTE* dllParam = BuildParameter(&dllParamSize, PARAMETER_ANSISTRING, "DllName", "ntdll.dll");

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
    return ((NTSETTHREADEXEC)HookList[HOOK_NT_SET_THREAD_EXEC].originalFunc)(NewFlags, PreviousFlags);
}

EXECUTION_STATE SetThreadExecutionState_Handler(EXECUTION_STATE Flags) {
    // create parameters
    size_t param1Size;
    BYTE* param1 = BuildParameter(&param1Size, PARAMETER_UINT32, "Flags", Flags);
    size_t fnParamSize;
    BYTE* fnParam = BuildParameter(&fnParamSize, PARAMETER_ANSISTRING, "Func", "SetThreadExecutionState");
    size_t dllParamSize;
    BYTE* dllParam = BuildParameter(&dllParamSize, PARAMETER_ANSISTRING, "DllName", "kernel32.dll");

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
    return ((SETTHREADEXEC)HookList[HOOK_SET_THREAD_EXEC].originalFunc)(Flags);
}

DWORD SuspendThread_Handler(HANDLE hThread) {
    // create parameters
    size_t param1Size;
    BYTE* param1 = BuildParameter(&param1Size, PARAMETER_UINT32, "TargetPid", GetProcessIdOfThread(hThread));
    size_t param2Size;
    BYTE* param2 = BuildParameter(&param2Size, PARAMETER_UINT32, "TargetTid", GetThreadId(hThread));
    size_t fnParamSize;
    BYTE* fnParam = BuildParameter(fnParamSize, PARAMETER_ANSISTRING, "Func", "SuspendThread");
    size_t dllParamSize;
    BYTE* dllParam = BuildParameter(dllParamSize, PARAMETER_ANSISTRING, "DllName", "kernel32.dll");

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
    return ((SUSPENDTHREAD)HookList[HOOK_SUSPEND_THREAD].originalFunc)(hThread);
}

DWORD ResumeThread_Handler(HANDLE hThread) {
    // create parameters
    size_t param1Size;
    BYTE* param1 = BuildParameter(&param1Size, PARAMETER_UINT32, "TargetPid", GetProcessIdOfThread(hThread));
    size_t param2Size;
    BYTE* param2 = BuildParameter(&param2Size, PARAMETER_UINT32, "TargetTid", GetThreadId(hThread));
    size_t fnParamSize;
    BYTE* fnParam = BuildParameter(&fnParamSize, PARAMETER_ANSISTRING, "Func", "ResumeThread");
    size_t dllParamSize;
    BYTE* dllParam = BuildParameter(&dllParamSize, PARAMETER_ANSISTRING, "DllName", "kernel32.dll");

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
    return ((RESUMETHREAD)HookList[HOOK_RESUME_THREAD].originalFunc)(hThread);
}

DWORD TerminateThread_Handler(HANDLE hThread, DWORD dwExitCode) {
    // create parameters
    size_t param1Size;
    BYTE* param1 = BuildParameter(&param1Size, PARAMETER_UINT32, "TargetPid", GetProcessIdOfThread(hThread));
    size_t param2Size;
    BYTE* param2 = BuildParameter(&param2Size, PARAMETER_UINT32, "TargetTid", GetThreadId(hThread));
    size_t fnParamSize;
    BYTE* fnParam = BuildParameter(&fnParamSize, PARAMETER_ANSISTRING, "Func", "TerminateThread");
    size_t dllParamSize;
    BYTE* dllParam = BuildParameter(&dllParamSize, PARAMETER_ANSISTRING, "DllName", "kernel32.dll");

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
    return ((TERMINATETHREAD)HookList[HOOK_TERMINATE_THREAD].originalFunc)(hThread, dwExitCode);
}

NTSTATUS NtSuspendThread_Handler(HANDLE hThread, PULONG PrevSuspendCount) {
    // create parameters
    size_t param1Size;
    BYTE* param1 = BuildParameter(&param1Size, PARAMETER_UINT32, "TargetPid", GetProcessIdOfThread(hThread));
    size_t param2Size;
    BYTE* param2 = BuildParameter(&param2Size, PARAMETER_UINT32, "TargetTid", GetThreadId(hThread));
    size_t fnParamSize;
    BYTE* fnParam = BuildParameter(&fnParamSize, PARAMETER_ANSISTRING, "Func", "NtSuspendThread");
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
    return ((NTSUSPENDTHREAD)HookList[HOOK_NT_SUSPEND_THREAD].originalFunc)(hThread, PrevSuspendCount);
}

NTSTATUS NtResumeThread_Handler(HANDLE hThread, PULONG PrevSuspendCount) {
    // create parameters
    size_t param1Size;
    BYTE* param1 = BuildParameter(&param1Size, PARAMETER_UINT32, "TargetPid", GetProcessIdOfThread(hThread));
    size_t param2Size;
    BYTE* param2 = BuildParameter(&param2Size, PARAMETER_UINT32, "TargetTid", GetThreadId(hThread));
    size_t fnParamSize;
    BYTE* fnParam = BuildParameter(&fnParamSize, PARAMETER_ANSISTRING, "Func", "NtResumeThread");
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
    return ((NTRESUMETHREAD)HookList[HOOK_NT_RESUME_THREAD].originalFunc)(hThread, PrevSuspendCount);
}

NTSTATUS NtTerminateThread_Handler(HANDLE hThread, NTSTATUS ExitStatus) {
    // create parameters
    size_t param1Size;
    BYTE* param1 = BuildParameter(&param1Size, PARAMETER_UINT32, "TargetPid", GetProcessIdOfThread(hThread));
    size_t param2Size;
    BYTE* param2 = BuildParameter(&param2Size, PARAMETER_UINT32, "TargetTid", GetThreadId(hThread));
    size_t fnParamSize;
    BYTE* fnParam = BuildParameter(&fnParamSize, PARAMETER_ANSISTRING, "Func", "NtTerminateThread");
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
    return ((NTTERMINATETHREAD)HookList[HOOK_NT_TERMINATE_THREAD].originalFunc)(hThread, ExitStatus);
}
