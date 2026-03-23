#include "hook.h"


FARPROC GetProcAddress_Handler(HMODULE hModule, LPCSTR lpProcName) {
  size_t param1Size;
  BYTE* param1 = BuildParameter(param1Size, PARAMETER_ANSISTRING, "Function", lpProcName);
  size_t fnParamSize;
  BYTE* fnParam = BuildParameter(fnParamSize, PARAMETER_ANSISTRING, "Func", "GetProcAddress");
  size_t dllParamSize;
  BYTE* dllParam = BuildParameter(dllParamSize, PARAMETER_ANSISTRING, "DllName", "kernel32.dll");

  size_t totalParamsSize = param1Size + fnParamSize + dllParamSize;
  TELEMETRY_HEADER header = GetTelemetryHeader(TM_TYPE_API_CALL, totalParamsSize);

  size_t packetSize = totalParamsSize + sizeof(header);
  BYTE* packet = (BYTE*)malloc(packetSize);

  memcpy(packet, &header, sizeof(header));
  memcpy(packet + sizeof(header), param1, param1Size);
  memcpy(packet + sizeof(header) + param1Size, fnParam, fnParamSize);
  memcpy(packet + sizeof(header) + param1Size + fnParamSize, dllParam, dllParamSize);

  free(param1);
  free(fnParam);
  free(dllParam);

  EnqueuePacket(g_StandardQueue, packet, packetSize);
  return ((GETPROCADDRESS)HookList[HOOK_GET_PROC_ADDRESS].originalFunc)(hModule, lpProcName);
}

HMODULE GetModuleHandleA_Handler(LPCSTR lpModuleName) {
  size_t param1Size;
  BYTE* param1 = BuildParameter(param1Size, PARAMETER_ANSISTRING, "Module", lpModuleName);
  size_t fnParamSize;
  BYTE* fnParam = BuildParameter(fnParamSize, PARAMETER_ANSISTRING, "Func", "GetModuleHandleA");
  size_t dllParamSize;
  BYTE* dllParam = BuildParameter(dllParamSize, PARAMETER_ANSISTRING, "DllName", "kernel32.dll");

  size_t totalParamsSize = param1Size + fnParamSize + dllParamSize;
  TELEMETRY_HEADER header = GetTelemetryHeader(TM_TYPE_API_CALL, totalParamsSize);

  size_t packetSize = totalParamsSize + sizeof(header);
  BYTE* packet = (BYTE*)malloc(packetSize);

  memcpy(packet, &header, sizeof(header));
  memcpy(packet + sizeof(header), param1, param1Size);
  memcpy(packet + sizeof(header) + param1Size, fnParam, fnParamSize);
  memcpy(packet + sizeof(header) + param1Size + fnParamSize, dllParam, dllParamSize);

  free(param1);
  free(fnParam);
  free(dllParam);

  EnqueuePacket(g_StandardQueue, packet, packetSize);
  return ((GETMODULEHANDLEA)HookList[HOOK_GET_MODULE_HANDLE_A].originalFunc)(lpModuleName);
}

HMODULE GetModuleHandleW_Handler(LPCWSTR lpModuleName) {
  size_t param1Size;
  char* modName = WideToAnsi(lpModuleName);
  BYTE* param1 = BuildParameter(param1Size, PARAMETER_ANSISTRING, "Module", modName);
  size_t fnParamSize;
  BYTE* fnParam = BuildParameter(fnParamSize, PARAMETER_ANSISTRING, "Func", "GetModuleHandleA");
  size_t dllParamSize;
  BYTE* dllParam = BuildParameter(dllParamSize, PARAMETER_ANSISTRING, "DllName", "kernel32.dll");

  size_t totalParamsSize = param1Size + fnParamSize + dllParamSize;
  TELEMETRY_HEADER header = GetTelemetryHeader(TM_TYPE_API_CALL, totalParamsSize);

  size_t packetSize = totalParamsSize + sizeof(header);
  BYTE* packet = (BYTE*)malloc(packetSize);

  memcpy(packet, &header, sizeof(header));
  memcpy(packet + sizeof(header), param1, param1Size);
  memcpy(packet + sizeof(header) + param1Size, fnParam, fnParamSize);
  memcpy(packet + sizeof(header) + param1Size + fnParamSize, dllParam, dllParamSize);

  free(param1);
  free(fnParam);
  free(dllParam);
  free(modName); // allocated string

  EnqueuePacket(g_StandardQueue, packet, packetSize);
  return ((GETMODULEHANDLEW)HookList[HOOK_GET_MODULE_HANDLE_W].originalFunc)(lpModuleName);
}

BOOL GetModuleHandleExA_Handler(DWORD dwFlags, LPCSTR lpModuleName, HMODULE* phModule) {
  size_t param1Size;
  BYTE* param1 = BuildParameter(param1Size, PARAMETER_ANSISTRING, "Module", lpModuleName);
  size_t param2Size;
  BYTE* param2 = BuildParameter(param2Size, PARAMETER_UINT32, "Flags", dwFlags);
  size_t fnParamSize;
  BYTE* fnParam = BuildParameter(fnParamSize, PARAMETER_ANSISTRING, "Func", "GetModuleHandleA");
  size_t dllParamSize;
  BYTE* dllParam = BuildParameter(dllParamSize, PARAMETER_ANSISTRING, "DllName", "kernel32.dll");

  size_t totalParamsSize = param1Size + param2Size + fnParamSize + dllParamSize;
  TELEMETRY_HEADER header = GetTelemetryHeader(TM_TYPE_API_CALL, totalParamsSize);

  size_t packetSize = totalParamsSize + sizeof(header);
  BYTE* packet = (BYTE*)malloc(packetSize);

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
  return ((GETMODULEHANDLEEXA)HookList[HOOK_GET_MODULE_HANDLE_EX_A].originalFunc)(dwFlags, lpModuleName, phModule);
}

BOOL GetModuleHandleExA_Handler(DWORD dwFlags, LPCSTR lpModuleName, HMODULE* phModule) {
  size_t param1Size;
  char* modName = WideToAnsi(lpModuleName);
  BYTE* param1 = BuildParameter(param1Size, PARAMETER_ANSISTRING, "Module", modName);
  size_t param2Size;
  BYTE* param2 = BuildParameter(param2Size, PARAMETER_UINT32, "Flags", dwFlags);
  size_t fnParamSize;
  BYTE* fnParam = BuildParameter(fnParamSize, PARAMETER_ANSISTRING, "Func", "GetModuleHandleA");
  size_t dllParamSize;
  BYTE* dllParam = BuildParameter(dllParamSize, PARAMETER_ANSISTRING, "DllName", "kernel32.dll");

  size_t totalParamsSize = param1Size + param2Size + fnParamSize + dllParamSize;
  TELEMETRY_HEADER header = GetTelemetryHeader(TM_TYPE_API_CALL, totalParamsSize);

  size_t packetSize = totalParamsSize + sizeof(header);
  BYTE* packet = (BYTE*)malloc(packetSize);

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

  EnqueuePacket(g_StandardQueue, packet, packetSize);
  return ((GETMODULEHANDLEEXW)HookList[HOOK_GET_MODULE_HANDLE_EX_W].originalFunc)(dwFlags, lpModuleName, phModule);
}


BOOL IsDebuggerPresent_Handler() {
  size_t fnParamSize;
  BYTE* fnParam = BuildParameter(fnParamSize, PARAMETER_ANSISTRING, "Func", "IsDebuggerPresent");
  size_t dllParamSize;
  BYTE* dllParam = BuildParameter(dllParamSize, PARAMETER_ANSISTRING, "DllName", "kernel32.dll");

  size_t totalParamsSize = fnParamSize + dllParamSize;
  TELEMETRY_HEADER header = GetTelemetryHeader(TM_TYPE_API_CALL, totalParamsSize);

  size_t packetSize = totalParamsSize + sizeof(header);
  BYTE* packet = (BYTE*)malloc(packetSize);

  memcpy(packet, &header, sizeof(header));
  memcpy(packet + sizeof(header), fnParam, fnParamSize);
  memcpy(packet + sizeof(header) + fnParamSize, dllParam, dllParamSize);

  free(fnParam);
  free(dllParam);

  EnqueuePacket(g_StandardQueue, packet, packetSize);
  return ((ISDEBUGGERPRESENT)HookList[HOOK_IS_DEBUGGER_PRESENT].originalFunc)();
}

//TODO: FindWindowA
//TODO: FindWindowW
//TODO: FindWindowExA
//TODO: FindWindowExW
//TODO: NtUserFindWindowEx

//TODO: Thread32First
//TODO: Thread32Next

//TODO: Process32First
//TODO: Process32Next
//TODO: Process32FirstW
//TODO: Process32NextW

//TODO: Module32First
//TODO: Module32Next
//TODO: Module32FirstW
//TODO: Module32NextW

HANDLE CreateTh32Snapshot_Handler(DWORD dwFlags, DWORD th32ProcessId) {
  size_t param1Size;
  BYTE* param1 = BuildParameter(param1Size, PARAMETER_UINT32, "Flags", dwFlags);
  size_t param2Size;
  BYTE* param2 = BuildParameter(param2Size, PARAMETER_UINT32, "TargetPid", th32ProcessId);
  size_t fnParamSize;
  BYTE* fnParam = BuildParameter(fnParamSize, PARAMETER_ANSISTRING, "Func", "IsDebuggerPresent");
  size_t dllParamSize;
  BYTE* dllParam = BuildParameter(dllParamSize, PARAMETER_ANSISTRING, "DllName", "kernel32.dll");

  size_t totalParamsSize = param1Size + param2Size + fnParamSize + dllParamSize;
  TELEMETRY_HEADER header = GetTelemetryHeader(TM_TYPE_API_CALL, totalParamsSize);

  size_t packetSize = totalParamsSize + sizeof(header);
  BYTE* packet = (BYTE*)malloc(packetSize);

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
  return ((CREATETH32SNAPSHOT)HookList[HOOK_CREATE_TH32_SNAPSHOT].originalFunc)(dwFlags, th32ProcessId);
}

//TODO: NtQueryInformationProcess
//TODO: NtQueryInformationThread
//TODO: NtQuerySystemInformation
//TODO: NtQuerySystemInformationEx
NTSTATUS NtQuerySystemInformation_Handler(
  SYSTEM_INFORMATION_CLASS SystemInfoClass,
  PVOID SystemInformation,
  ULONG SystemInformationLength,
  PULONG ReturnLength) {

  EnqueuePacket(g_StandardQueue, packet, packetSize);
  return ((NTQUERYSYSTEMINFO)HookList[HOOK_NT_QUERY_SYSTEM_INFO].originalFunc)(dwFlags, th32ProcessId);
}
