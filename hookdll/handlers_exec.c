#include <windows.h>
#include <winternl.h>
#include "hook.h"

HHOOK SetWindowsHookExA(int idHook, HOOKPROC lpfn, HINSTANCE hmod, DWORD dwThreadId) {
    // create parameters
    size_t param1Size;
    BYTE* param1 = BuildParameter(&param1Size, PARAMETER_ANSISTRING, "HookId", idHook);
    size_t param2Size;
    BYTE* param2 = BuildParameter(&param2Size, PARAMETER_UINT32, "ThreadId", dwThreadId);
    size_t param3Size;
    BYTE* param3 = BuildParameter(&param3Size, PARAMETER_POINTER, "Module", hmod);
    size_t param4Size;
    BYTE* param4 = BuildParameter(&param4Size, PARAMETER_POINTER, "Function", lpfn);
    size_t fnParamSize;
    BYTE* fnParam = BuildParameter(fnParamSize, PARAMETER_ANSISTRING, "Func", "SetWindowsHookExA");
    size_t dllParamSize;
    BYTE* dllParam = BuildParameter(dllParamSize, PARAMETER_ANSISTRING, "DllName", "user32.dll");

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
    return ((SETWINDOWSHOOKEXA)HookList[HOOK_SET_WINDOWS_HOOK_EX_A].originalFunc)(idHook, lpfn, hmod, dwThreadId);
}
HHOOK SetWindowsHookExW(int idHook, HOOKPROC lpfn, HINSTANCE hmod, DWORD dwThreadId) {
    // create parameters
    size_t param1Size;
    BYTE* param1 = BuildParameter(&param1Size, PARAMETER_ANSISTRING, "HookId", idHook);
    size_t param2Size;
    BYTE* param2 = BuildParameter(&param2Size, PARAMETER_UINT32, "ThreadId", dwThreadId);
    size_t param3Size;
    BYTE* param3 = BuildParameter(&param3Size, PARAMETER_POINTER, "Module", hmod);
    size_t param4Size;
    BYTE* param4 = BuildParameter(&param4Size, PARAMETER_POINTER, "Function", lpfn);
    size_t fnParamSize;
    BYTE* fnParam = BuildParameter(fnParamSize, PARAMETER_ANSISTRING, "Func", "SetWindowsHookExW");
    size_t dllParamSize;
    BYTE* dllParam = BuildParameter(dllParamSize, PARAMETER_ANSISTRING, "DllName", "user32.dll");

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
    return ((SETWINDOWSHOOKEXW)HookList[HOOK_SET_WINDOWS_HOOK_EX_W].originalFunc)(idHook, lpfn, hmod, dwThreadId);
}

UINT SetWinEventHook_Handler(
   DWORD eventMin, 
   DWORD eventMax, 
   HMODULE hmodWinEventProc, 
   WINEVENTPROC pfnWinEventProc, 
   DWORD idProcess, 
   DWORD idThread, 
   DWORD dwFlags) {

    // create parameters
    size_t param1Size;
    BYTE* param1 = BuildParameter(&param1Size, PARAMETER_UINT32, "Flags", dwFlags);
    size_t param2Size;
    BYTE* param2 = BuildParameter(&param2Size, PARAMETER_POINTER, "Module", hmodWinEventProc);
    size_t param3Size;
    BYTE* param3 = BuildParameter(&param3Size, PARAMETER_POINTER, "Function", pfnWinEventProc);
    size_t param4Size;
    BYTE* param4 = BuildParameter(&param4Size, PARAMETER_UINT32, "TargetPid", idProcess);
    size_t param5Size;
    BYTE* param5 = BuildParameter(&param5Size, PARAMETER_UINT32, "TargetTid", idThread);
    size_t param6Size;
    BYTE* param6 = BuildParameter(&param6Size, PARAMETER_UINT32, "EventMin", eventMin);
    size_t param7Size;
    BYTE* param7 = BuildParameter(&param7Size, PARAMETER_UINT32, "EventMax", eventMax);
    size_t fnParamSize;
    BYTE* fnParam = BuildParameter(fnParamSize, PARAMETER_ANSISTRING, "Func", "SetWinEventHook");
    size_t dllParamSize;
    BYTE* dllParam = BuildParameter(dllParamSize, PARAMETER_ANSISTRING, "DllName", "user32.dll");

    size_t totalParamsSize = param1Size + param2Size + param3Size + param4Size + param5Size + param6Size + param7Size + fnParamSize + dllParamSize;
    TELEMETRY_HEADER header = GetTelemetryHeader(TM_TYPE_API_CALL, totalParamsSize);

    size_t packetSize = totalParamsSize + sizeof(header);
    BYTE* packet = (BYTE*)malloc(packetSize);

    // construct packet 
    memcpy(packet, &header, sizeof(header));
    memcpy(packet + sizeof(header), param1, param1Size);
    memcpy(packet + sizeof(header) + param1Size, param2, param2Size);
    memcpy(packet + sizeof(header) + param1Size + param2Size, param3, param3Size);
    memcpy(packet + sizeof(header) + param1Size + param2Size + param3Size, param4, param4Size);
    memcpy(packet + sizeof(header) + param1Size + param2Size + param3Size + param4Size, param5, param5Size);
    memcpy(packet + sizeof(header) + param1Size + param2Size + param3Size + param4Size + param5Size, param6, param6Size);
    memcpy(packet + sizeof(header) + param1Size + param2Size + param3Size + param4Size + param5Size + param6Size, param7, param7Size);
    memcpy(packet + sizeof(header) + param1Size + param2Size + param3Size + param4Size + param5Size + param6Size + param7Size, fnParam, fnParamSize);
    memcpy(packet + sizeof(header) + param1Size + param2Size + param3Size + param4Size + param5Size + param6Size + param7Size + fnParamSize, dllParam, dllParamSize);

    free(param1);
    free(param2);
    free(param3);
    free(param4);
    free(param5);
    free(param6);
    free(param7);
    free(fnParam);
    free(dllParam);

    EnqueuePacket(g_CriticalQueue, packet, packetSize);
    return ((SETWINEVENTHOOK)HookList[HOOK_SET_WIN_EVENT_HOOK].originalFunc)(eventMin, eventMax, hmodWinEventProc, pfnWinEventProc, idProcess, idThread, dwFlags);
}

UINT WinExec_Handler(LPCSTR lpCmdLine, UINT uCmdShow) {
    // create parameters
    size_t param1Size;
    BYTE* param1 = BuildParameter(&param1Size, PARAMETER_ANSISTRING, "CmdLine", lpCmdLine);
    size_t param2Size;
    BYTE* param2 = BuildParameter(&param2Size, PARAMETER_UINT32, "ShowCmd", uCmdShow);
    size_t fnParamSize;
    BYTE* fnParam = BuildParameter(fnParamSize, PARAMETER_ANSISTRING, "Func", "WinExec");
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

    EnqueuePacket(g_CriticalQueue, packet, packetSize);
    return ((WINEXEC)HookList[HOOK_WIN_EXEC].originalFunc)(lpCmdline, uCmdShow);
}

HINSTANCE ShellExecuteA_Handler(
    HWND hWnd,
    LPCSTR lpOperation,
    LPCSTR lpFile,
    LPCSTR lpParameters,
    LPCSTR lpDirectory,
    INT nShowCmd) {
    
    // create parameters
    size_t param1Size;
    BYTE* param1 = BuildParameter(&param1Size, PARAMETER_ANSISTRING, "Operation", lpOperation);
    size_t param2Size;
    BYTE* param2 = BuildParameter(&param2Size, PARAMETER_ANSISTRING, "TargetFile", lpFile);
    size_t param3Size;
    BYTE* param3 = BuildParameter(&param3Size, PARAMETER_ANSISTRING, "Parameters", lpParameters);
    size_t param4Size;
    BYTE* param4 = BuildParameter(&param4Size, PARAMETER_ANSISTRING, "Directory", lpDirectory);
    size_t param5Size;
    BYTE* param5 = BuildParameter(&param5Size, PARAMETER_UINT32, "ShowCmd", nShowCmd);
    size_t fnParamSize;
    BYTE* fnParam = BuildParameter(fnParamSize, PARAMETER_ANSISTRING, "Func", "ShellExecuteA");
    size_t dllParamSize;
    BYTE* dllParam = BuildParameter(dllParamSize, PARAMETER_ANSISTRING, "DllName", "shell32.dll");

    size_t totalParamsSize = param1Size + param2Size + param3Size + param4Size + param5Size + fnParamSize + dllParamSize;
    TELEMETRY_HEADER header = GetTelemetryHeader(TM_TYPE_API_CALL, totalParamsSize);

    size_t packetSize = totalParamsSize + sizeof(header);
    BYTE* packet = (BYTE*)malloc(packetSize);

    // construct packet 
    memcpy(packet, &header, sizeof(header));
    memcpy(packet + sizeof(header), param1, param1Size);
    memcpy(packet + sizeof(header) + param1Size, param2, param2Size);
    memcpy(packet + sizeof(header) + param1Size + param2Size, param3, param3Size);
    memcpy(packet + sizeof(header) + param1Size + param2Size + param3Size, param4, param4Size);
    memcpy(packet + sizeof(header) + param1Size + param2Size + param3Size + param4Size, param5, param5Size);
    memcpy(packet + sizeof(header) + param1Size + param2Size + param3Size + param4Size + param5Size, fnParam, fnParamSize);
    memcpy(packet + sizeof(header) + param1Size + param2Size + param3Size + param4Size + param5Size + fnParamSize, dllParam, dllParamSize);


    free(param1);
    free(param2);
    free(param3);
    free(param4);
    free(param5);
    free(fnParam);
    free(dllParam);

    EnqueuePacket(g_CriticalQueue, packet, packetSize);
    return ((SHELLEXECUTEA)HookList[HOOK_SHELL_EXECUTE_A].originalFunc)(hWnd, lpOperation, lpFile, lpParameters, lpDirectory, nShowCmd);
}

HINSTANCE ShellExecuteW_Handler(
    HWND hWnd,
    LPCWSTR lpOperation,
    LPCWSTR lpFile,
    LPCWSTR lpParameters,
    LPCWSTR lpDirectory,
    INT nShowCmd) {
    
    // create parameters
    size_t param1Size;
    char* op = WideToAnsi(lpOperation);
    BYTE* param1 = BuildParameter(&param1Size, PARAMETER_ANSISTRING, "Operation", op);
    size_t param2Size;
    char* file = WideToAnsi(lpFile);
    BYTE* param2 = BuildParameter(&param2Size, PARAMETER_ANSISTRING, "TargetFile", file);
    size_t param3Size;
    char* parameters = WideToAnsi(lpParameters);
    BYTE* param3 = BuildParameter(&param3Size, PARAMETER_ANSISTRING, "Parameters", parameters);
    size_t param4Size;
    char* dir = WideToAnsi(lpDirectory);
    BYTE* param4 = BuildParameter(&param4Size, PARAMETER_ANSISTRING, "Directory", dir);
    size_t param5Size;
    BYTE* param5 = BuildParameter(&param5Size, PARAMETER_UINT32, "ShowCmd", nShowCmd);
    size_t fnParamSize;
    BYTE* fnParam = BuildParameter(fnParamSize, PARAMETER_ANSISTRING, "Func", "ShellExecuteW");
    size_t dllParamSize;
    BYTE* dllParam = BuildParameter(dllParamSize, PARAMETER_ANSISTRING, "DllName", "shell32.dll");

    size_t totalParamsSize = param1Size + param2Size + param3Size + param4Size + param5Size + fnParamSize + dllParamSize;
    TELEMETRY_HEADER header = GetTelemetryHeader(TM_TYPE_API_CALL, totalParamsSize);

    size_t packetSize = totalParamsSize + sizeof(header);
    BYTE* packet = (BYTE*)malloc(packetSize);

    // construct packet 
    memcpy(packet, &header, sizeof(header));
    memcpy(packet + sizeof(header), param1, param1Size);
    memcpy(packet + sizeof(header) + param1Size, param2, param2Size);
    memcpy(packet + sizeof(header) + param1Size + param2Size, param3, param3Size);
    memcpy(packet + sizeof(header) + param1Size + param2Size + param3Size, param4, param4Size);
    memcpy(packet + sizeof(header) + param1Size + param2Size + param3Size + param4Size, param5, param5Size);
    memcpy(packet + sizeof(header) + param1Size + param2Size + param3Size + param4Size + param5Size, fnParam, fnParamSize);
    memcpy(packet + sizeof(header) + param1Size + param2Size + param3Size + param4Size + param5Size + fnParamSize, dllParam, dllParamSize);

    free(param1);
    free(param2);
    free(param3);
    free(param4);
    free(param5);
    free(fnParam);
    free(dllParam);
    free(parameters); // allocated string
    free(file); // allocated string
    free(dir); // allocated string
    free(op); // allocated string

    EnqueuePacket(g_CriticalQueue, packet, packetSize);
    return ((SHELLEXECUTEW)HookList[HOOK_SHELL_EXECUTE_W].originalFunc)(hWnd, lpOperation, lpFile, lpParameters, lpDirectory, nShowCmd);
}

BOOL ShellExecuteExA_Handler(SHELLEXECUTEINFOA* pExecInfo) {
    // create parameters
    size_t param1Size;
    BYTE* param1 = BuildParameter(&param1Size, PARAMETER_ANSISTRING, "Operation", pExecInfo->lpVerb);
    size_t param2Size;
    BYTE* param2 = BuildParameter(&param2Size, PARAMETER_ANSISTRING, "TargetFile", pExecInfo->lpFile);
    size_t param3Size;
    BYTE* param3 = BuildParameter(&param3Size, PARAMETER_ANSISTRING, "Parameters", pExecInfo->lpParameters);
    size_t param4Size;
    BYTE* param4 = BuildParameter(&param4Size, PARAMETER_ANSISTRING, "Directory", pExecInfo->lpDirectory);
    size_t param5Size;
    BYTE* param5 = BuildParameter(&param5Size, PARAMETER_UINT32, "ShowCmd", pExecInfo->nShow);
    size_t fnParamSize;
    BYTE* fnParam = BuildParameter(fnParamSize, PARAMETER_ANSISTRING, "Func", "ShellExecuteExA");
    size_t dllParamSize;
    BYTE* dllParam = BuildParameter(dllParamSize, PARAMETER_ANSISTRING, "DllName", "shell32.dll");

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
    memcpy(packet + sizeof(header) + param1Size + param2Size + param3Size + param4Size, param5, param5Size);
    memcpy(packet + sizeof(header) + param1Size + param2Size + param3Size + param4Size + param5Size, fnParam, fnParamSize);
    memcpy(packet + sizeof(header) + param1Size + param2Size + param3Size + param4Size + param5Size + fnParamSize, dllParam, dllParamSize);

    free(param1);
    free(param2);
    free(param3);
    free(param4);
    free(param5);
    free(fnParam);
    free(dllParam);

    EnqueuePacket(g_CriticalQueue, packet, packetSize);
    return ((SHELLEXECUTEEXA)HookList[HOOK_SHELL_EXECUTE_EX_A].originalFunc)(pExecInfo);
}

BOOL ShellExecuteExW_Handler(SHELLEXECUTEINFOW* pExecInfo) {
    // create parameters
    size_t param1Size;
    BYTE* param1 = BuildParameter(&param1Size, PARAMETER_ANSISTRING, "Operation", pExecInfo->lpVerb);
    size_t param2Size;
    BYTE* param2 = BuildParameter(&param2Size, PARAMETER_ANSISTRING, "TargetFile", pExecInfo->lpFile);
    size_t param3Size;
    BYTE* param3 = BuildParameter(&param3Size, PARAMETER_ANSISTRING, "Parameters", pExecInfo->lpParameters);
    size_t param4Size;
    BYTE* param4 = BuildParameter(&param4Size, PARAMETER_ANSISTRING, "Directory", pExecInfo->lpDirectory);
    size_t param5Size;
    BYTE* param5 = BuildParameter(&param5Size, PARAMETER_UINT32, "ShowCmd", pExecInfo->nShow);
    size_t fnParamSize;
    BYTE* fnParam = BuildParameter(fnParamSize, PARAMETER_ANSISTRING, "Func", "ShellExecuteExW");
    size_t dllParamSize;
    BYTE* dllParam = BuildParameter(dllParamSize, PARAMETER_ANSISTRING, "DllName", "shell32.dll");

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
    memcpy(packet + sizeof(header) + param1Size + param2Size + param3Size + param4Size, param5, param5Size);
    memcpy(packet + sizeof(header) + param1Size + param2Size + param3Size + param4Size + param5Size, fnParam, fnParamSize);
    memcpy(packet + sizeof(header) + param1Size + param2Size + param3Size + param4Size + param5Size + fnParamSize, dllParam, dllParamSize);

    free(param1);
    free(param2);
    free(param3);
    free(param4);
    free(param5);
    free(fnParam);
    free(dllParam);

    EnqueuePacket(g_CriticalQueue, packet, packetSize);
    return ((SHELLEXECUTEEXW)HookList[HOOK_SHELL_EXECUTE_EX_W].originalFunc)(pExecInfo);
}


PVOID AddVeh_Handler(ULONG First, PVECTORED_EXCEPTION_HANDLER Handler) {
    size_t param1Size;
    BYTE* param1 = BuildParameter(&param1Size, PARAMETER_POINTER, "Address", Handler);
    size_t param2Size;
    BYTE* param2 = BuildParameter(&param2Size, PARAMETER_BOOLEAN, "First", First);
    size_t fnParamSize;
    BYTE* fnParam = BuildParameter(fnParamSize, PARAMETER_ANSISTRING, "Func", "AddVectoredExceptionHandler");
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

    EnqueuePacket(g_CriticalQueue, packet, packetSize);
    return ((ADDVEH)HookList[HOOK_ADD_VEH].originalFunc)(First, Handler);
}

PVOID RtlAddVeh_Handler(ULONG First, PVECTORED_EXCEPTION_HANDLER Handler) {
    size_t param1Size;
    BYTE* param1 = BuildParameter(&param1Size, PARAMETER_POINTER, "Address", Handler);
    size_t param2Size;
    BYTE* param2 = BuildParameter(&param2Size, PARAMETER_BOOLEAN, "First", First);
    size_t fnParamSize;
    BYTE* fnParam = BuildParameter(fnParamSize, PARAMETER_ANSISTRING, "Func", "RtlAddVectoredExceptionHandler");
    size_t dllParamSize;
    BYTE* dllParam = BuildParameter(dllParamSize, PARAMETER_ANSISTRING, "DllName", "ntdll.dll");

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

    EnqueuePacket(g_CriticalQueue, packet, packetSize);
    return ((RTLADDVEH)HookList[HOOK_RTL_ADD_VEH].originalFunc)(First, Handler);
}

HMODULE LoadLibraryA_Handler(LPCSTR lpLibFileName) {
    size_t param1Size;
    BYTE* param1 = BuildParameter(&param1Size, PARAMETER_ANSISTRING, "Module", lpLibFileName);
    size_t fnParamSize;
    BYTE* fnParam = BuildParameter(fnParamSize, PARAMETER_ANSISTRING, "Func", "LoadLibraryA");
    size_t dllParamSize;
    BYTE* dllParam = BuildParameter(dllParamSize, PARAMETER_ANSISTRING, "DllName", "kernel32.dll");

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

    EnqueuePacket(g_CriticalQueue, packet, packetSize);
    return ((LOADLIBRARYA)HookList[HOOK_LOAD_LIBRARY_A].originalFunc)(lpLibFileName);
}

HMODULE LoadLibraryW_Handler(LPCWSTR lpLibFileName) {
    size_t param1Size;
    char* modName = WideToAnsi(lpLibFileName);
    BYTE* param1 = BuildParameter(&param1Size, PARAMETER_ANSISTRING, "Module", modName);
    size_t fnParamSize;
    BYTE* fnParam = BuildParameter(fnParamSize, PARAMETER_ANSISTRING, "Func", "LoadLibraryW");
    size_t dllParamSize;
    BYTE* dllParam = BuildParameter(dllParamSize, PARAMETER_ANSISTRING, "DllName", "kernel32.dll");

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
    free(modName); // allocated string

    EnqueuePacket(g_CriticalQueue, packet, packetSize);
    return ((LOADLIBRARYW)HookList[HOOK_LOAD_LIBRARY_W].originalFunc)(lpLibFileName);
}

HMODULE LoadLibraryExA_Handler(LPCSTR lpLibFileName, HANDLE hFile, DWORD dwFlags) {
    size_t param1Size;
    BYTE* param1 = BuildParameter(&param1Size, PARAMETER_ANSISTRING, "Module", lpLibFileName);
    size_t param2Size;
    BYTE* param2 = BuildParameter(&param2Size, PARAMETER_ANSISTRING, "Flags", dwFlags);
    size_t fnParamSize;
    BYTE* fnParam = BuildParameter(fnParamSize, PARAMETER_ANSISTRING, "Func", "LoadLibraryExA");
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

    EnqueuePacket(g_CriticalQueue, packet, packetSize);
    return ((LOADLIBRARYEXA)HookList[HOOK_LOAD_LIBRARY_EX_A].originalFunc)(lpLibFileName, hFile, dwFlags);
}

HMODULE LoadLibraryExW_Handler(LPCWSTR lpLibFileName, HANDLE hFile, DWORD dwFlags) {
    size_t param1Size;
    char* modName = WideToAnsi(lpLibFileName);
    BYTE* param1 = BuildParameter(&param1Size, PARAMETER_ANSISTRING, "Module", modName);
    size_t param2Size;
    BYTE* param2 = BuildParameter(&param2Size, PARAMETER_ANSISTRING, "Flags", dwFlags);
    size_t fnParamSize;
    BYTE* fnParam = BuildParameter(fnParamSize, PARAMETER_ANSISTRING, "Func", "LoadLibraryExA");
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
    free(modName); // allocated string

    EnqueuePacket(g_CriticalQueue, packet, packetSize);
    return ((LOADLIBRARYEXW)HookList[HOOK_LOAD_LIBRARY_EX_W].originalFunc)(lpLibFileName, hFile, dwFlags);
}

NTSTATUS LdrLoadDll_Handler(PCWSTR DllPath, PULONG DllCharacteristics, PCUNICODE_STRING DllName, PVOID* DllHandle) {
    size_t param1Size;
    char* modName = UnicodeStringToAnsi(DllName);
    BYTE* param1 = BuildParameter(&param1Size, PARAMETER_ANSISTRING, "Module", modName);
    size_t param2Size;
    char* dllPath = WideToAnsi(DllPath);
    BYTE* param2 = BuildParameter(&param2Size, PARAMETER_ANSISTRING, "DllPath", dllPath);
    size_t fnParamSize;
    BYTE* fnParam = BuildParameter(fnParamSize, PARAMETER_ANSISTRING, "Func", "LdrLoadDll");
    size_t dllParamSize;
    BYTE* dllParam = BuildParameter(dllParamSize, PARAMETER_ANSISTRING, "DllName", "ntdll.dll");

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
    free(modName); // allocated string
    free(dllPath); // allocated string

    EnqueuePacket(g_CriticalQueue, packet, packetSize);
    return ((LDRLOADDLL)HookList[HOOK_LDR_LOAD_DLL].originalFunc)(DllPath, DllCharacteristics, DllName, DllHandle);
}

BOOL SetDefaultDllDirectories_Handler(DWORD DirectoryFlags) {
    size_t param1Size;
    BYTE* param1 = BuildParameter(&param1Size, PARAMETER_ANSISTRING, "Flags", DirectoryFlags);
    size_t fnParamSize;
    BYTE* fnParam = BuildParameter(fnParamSize, PARAMETER_ANSISTRING, "Func", "SetDefaultDllDirectories");
    size_t dllParamSize;
    BYTE* dllParam = BuildParameter(dllParamSize, PARAMETER_ANSISTRING, "DllName", "kernel32.dll");

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

    EnqueuePacket(g_CriticalQueue, packet, packetSize);
    return ((SETDEFAULTDLLDIRS)HookList[HOOK_SET_DEFAULT_DLL_DIRS].originalFunc)(DirectoryFlags);
}