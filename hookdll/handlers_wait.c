#include <windows.h>
#include "hook.h"

DWORD WaitForSingleObject_Handler(HANDLE hObject, DWORD dwMillis) {
    // create parameters
    size_t param1Size;
    BYTE* param1 = BuildParameter(&param1Size, PARAMETER_UINT32, "Wait", dwMillis);
    size_t fnParamSize;
    BYTE* fnParam = BuildParameter(&fnParamSize, PARAMETER_ANSISTRING, "Func", "WaitForSingleObject");
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
    return ((WAITFORSINGLEOBJECT)HookList[HOOK_WAIT_FOR_SINGLE_OBJECT].originalFunc)(hObject, dwMillis);
}

DWORD WaitForSingleObjectEx_Handler(HANDLE hObject, DWORD dwMillis, BOOL bAlertable) {
    // create parameters
    size_t param1Size;
    BYTE* param1 = BuildParameter(&param1Size, PARAMETER_UINT32, "Wait", dwMillis);
    size_t param2Size;
    BYTE* param2 = BuildParameter(&param2Size, PARAMETER_BOOLEAN, "Alertable", bAlertable);
    size_t fnParamSize;
    BYTE* fnParam = BuildParameter(&fnParamSize, PARAMETER_ANSISTRING, "Func", "WaitForSingleObjectEx");
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
    return ((WAITFORSINGLEOBJECTEX)HookList[HOOK_WAIT_FOR_SINGLE_OBJECT_EX].originalFunc)(hObject, dwMillis, bAlertable);
}

DWORD WaitForMultipleObjects_Handler(DWORD nCount, const HANDLE* lpHandles, BOOL bWaitAll, DWORD dwMillis) {
    // create parameters
    size_t param1Size;
    BYTE* param1 = BuildParameter(&param1Size, PARAMETER_UINT32, "Wait", dwMillis);
    size_t fnParamSize;
    BYTE* fnParam = BuildParameter(&fnParamSize, PARAMETER_ANSISTRING, "Func", "WaitForMultipleObjects");
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
    return ((WAITFORMULTIPLEOBJECTS)HookList[HOOK_WAIT_FOR_MULTIPLE_OBJECTS].originalFunc)(nCount, lpHandles, bWaitAll, dwMillis);
}

DWORD WaitForMultipleObjectsEx_Handler(DWORD nCount, const HANDLE* lpHandles, BOOL bWaitAll, DWORD dwMillis, BOOL bAlertable) {
    // create parameters
    size_t param1Size;
    BYTE* param1 = BuildParameter(&param1Size, PARAMETER_UINT32, "Wait", dwMillis);
    size_t param2Size;
    BYTE* param2 = BuildParameter(&param2Size, PARAMETER_BOOLEAN, "Alertable", bAlertable);
    size_t fnParamSize;
    BYTE* fnParam = BuildParameter(&fnParamSize, PARAMETER_ANSISTRING, "Func", "WaitForMultipleObjectsEx");
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
    return ((WAITFORMULTIPLEOBJECTSEX)HookList[HOOK_WAIT_FOR_MULTIPLE_OBJECTS_EX].originalFunc)(nCount, lpHandles, bWaitAll, dwMillis, bAlertable);
}

BOOL WaitOnAddress_Handler(
    volatile VOID *Address,
    PVOID         CompareAddress,
    SIZE_T        AddressSize,
    DWORD         dwMillis) {
    // create parameters
    size_t param1Size;
    BYTE* param1 = BuildParameter(&param1Size, PARAMETER_UINT32, "Wait", dwMillis);
    size_t fnParamSize;
    BYTE* fnParam = BuildParameter(&fnParamSize, PARAMETER_ANSISTRING, "Func", "WaitOnAddress");
    size_t dllParamSize;
    BYTE* dllParam = BuildParameter(&dllParamSize, PARAMETER_ANSISTRING, "DllName", "api-ms-win-core-synch-l1-2-0.dll");

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
    return ((WAITONADDRESS)HookList[HOOK_WAIT_ON_ADDRESS].originalFunc)(Address, CompareAddress, AddressSize, dwMillis);
}

DWORD MsgWaitForMultipleObjects_Handler(
    DWORD        nCount,
    const HANDLE *pHandles,
    BOOL         fWaitAll,
    DWORD        dwMillis,
    DWORD        dwWakeMask) {
    // create parameters
    size_t param1Size;
    BYTE* param1 = BuildParameter(&param1Size, PARAMETER_UINT32, "Wait", dwMillis);
    size_t fnParamSize;
    BYTE* fnParam = BuildParameter(&fnParamSize, PARAMETER_ANSISTRING, "Func", "MsgWaitForMultipleObjects");
    size_t dllParamSize;
    BYTE* dllParam = BuildParameter(&dllParamSize, PARAMETER_ANSISTRING, "DllName", "user32.dll");

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
    return ((MSGWAITFORMULTIPLE)HookList[HOOK_MSG_WAIT_FOR_MULTIPLE].originalFunc)(nCount, pHandles, fWaitAll, dwMillis, dwWakeMask);
}

DWORD MsgWaitForMultipleObjectsEx_Handler(
    DWORD        nCount,
    const HANDLE *pHandles,
    DWORD        dwMillis,
    DWORD        dwWakeMask,
    DWORD       dwFlags) {
    // create parameters
    size_t param1Size;
    BYTE* param1 = BuildParameter(&param1Size, PARAMETER_UINT32, "Wait", dwMillis);
    size_t param2Size;
    BYTE* param2 = BuildParameter(&param2Size, PARAMETER_BOOLEAN, "Alertable", TRUE);
    size_t param3Size;
    BYTE* param3 = BuildParameter(&param3Size, PARAMETER_UINT32, "Flags", dwFlags);
    size_t fnParamSize;
    BYTE* fnParam = BuildParameter(&fnParamSize, PARAMETER_ANSISTRING, "Func", "MsgWaitForMultipleObjectsEx");
    size_t dllParamSize;
    BYTE* dllParam = BuildParameter(&dllParamSize, PARAMETER_ANSISTRING, "DllName", "user32.dll");

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
    return ((MSGWAITFORMULTIPLEEX)HookList[HOOK_MSG_WAIT_FOR_MULTIPLE_EX].originalFunc)(nCount, pHandles, dwMillis, dwWakeMask, dwFlags);
}

DWORD SignalObjectAndWait_Handler(
    HANDLE hObjectToSignal,
    HANDLE hObjectToWaitOn,
    DWORD  dwMillis,
    BOOL   bAlertable) {
    // create parameters
    size_t param1Size;
    BYTE* param1 = BuildParameter(&param1Size, PARAMETER_UINT32, "Wait", dwMillis);
    size_t param2Size;
    BYTE* param2 = BuildParameter(&param2Size, PARAMETER_BOOLEAN, "Alertable", bAlertable);
    size_t fnParamSize;
    BYTE* fnParam = BuildParameter(&fnParamSize, PARAMETER_ANSISTRING, "Func", "SignalObjectAndWait");
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
    return ((SIGNALOBJECTANDWAIT)HookList[HOOK_SIGNAL_OBJECT_AND_WAIT].originalFunc)(hObjectToSignal, hObjectToWaitOn, dwMillis, bAlertable);
}

DWORD SleepEx_Handler(DWORD dwMillis, BOOL bAlertable) {
    // create parameters
    size_t param1Size;
    BYTE* param1 = BuildParameter(&param1Size, PARAMETER_UINT32, "Wait", dwMillis);
    size_t param2Size;
    BYTE* param2 = BuildParameter(&param2Size, PARAMETER_BOOLEAN, "Alertable", bAlertable);
    size_t fnParamSize;
    BYTE* fnParam = BuildParameter(&fnParamSize, PARAMETER_ANSISTRING, "Func", "SleepEx");
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
    return ((SLEEPEX)HookList[HOOK_SLEEP_EX].originalFunc)(dwMillis, bAlertable);
}

VOID Sleep_Handler(DWORD dwMillis) {
    // create parameters
    size_t param1Size;
    BYTE* param1 = BuildParameter(&param1Size, PARAMETER_UINT32, "Wait", dwMillis);
    size_t fnParamSize;
    BYTE* fnParam = BuildParameter(&fnParamSize, PARAMETER_ANSISTRING, "Func", "Sleep");
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
    return ((SLEEP)HookList[HOOK_SLEEP].originalFunc)(dwMillis);
}