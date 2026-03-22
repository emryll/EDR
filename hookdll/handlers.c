#include <windows.h>
#include <winternl.h>
#include <stdio.h>
#include <time.h>
#include "hook.h"

#define STATUS_ACCESS_DENIED 0xC0000022
//?================================================================================+
//?   These are the functions API hooks point to, for now they are just simply     |
//?   sending the call and args to agent via named pipes. Currently the telemetry  |
//?   packets are very inefficient, however they will be redesigned soon...        |
//?================================================================================+

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
  BYTE* fnParam = BuildParameter(fnParamSize, PARAMETER_ANSISTRING, "Func", "CreateRemoteThread");
  size_t dllParamSize;
  BYTE* dllParam = BuildParameter(dllParamSize, PARAMETER_ANSISTRING, "DllName", "kernel32.dll");

  size_t totalParamsSize = param1Size + param2Size + param3Size + fnParamSize + dllParamSize;
  TELEMETRY_HEADER header = GetTelemetryHeader(TM_TYPE_API_CALL, totalParamsSize);

  size_t packetSize = totalParamsSize + sizeof(header);
  BYTE* packet = (BYTE*)malloc(totalParamsSize + )

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
  BYTE* fnParam = BuildParameter(fnParamSize, PARAMETER_ANSISTRING, "Func", "CreateRemoteThreadEx");
  size_t dllParamSize;
  BYTE* dllParam = BuildParameter(dllParamSize, PARAMETER_ANSISTRING, "DllName", "kernel32.dll");

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
  return ((CREATEREMOTETHREADEX)HookList[HOOK_CREATE_REMOTE_THREAD_EX].originalFunc)(hProcess, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpAttributeList, lpThreadId);
}



LPVOID VirtualAlloc_Handler(LPVOID lpAddress, SIZE_T dwSize, DWORD  flAllocationType, DWORD  flProtect) {
  if (!HasExecutable(flProtect) && flAllocationType&PAGE_GUARD == 0) {
    return ((VIRTUALALLOC)HookList[HOOK_VIRTUAL_ALLOC].originalFunc)(lpAddress, dwSize, flAllocationType, flProtect);
  }

  // params:
  // - Address
  // - Protection
  // - AllocType
  // - AllocSize

  // create parameters
  size_t param1Size;
  BYTE* param1 = BuildParameter(&param1Size, PARAMETER_POINTER, "Address", lpAddress);
  size_t param2Size;
  BYTE* param2 = BuildParameter(&param2Size, PARAMETER_UINT32, "Protection", flProtect);
  size_t param3Size;
  BYTE* param3 = BuildParameter(&param3Size, PARAMETER_UINT32, "AllocType", flAllocationType);
  size_t param4Size;
  BYTE* param4 = BuildParameter(&param4Size, PARAMETER_UINT64, "AllocSize", dwSize);
  size_t fnParamSize;
  BYTE* fnParam = BuildParameter(fnParamSize, PARAMETER_ANSISTRING, "Func", "VirtualAlloc");
  size_t dllParamSize;
  BYTE* dllParam = BuildParameter(dllParamSize, PARAMETER_ANSISTRING, "DllName", "kernel32.dll");

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
  return ((VIRTUALALLOC)HookList[HOOK_VIRTUAL_ALLOC].originalFunc)(lpAddress, dwSize, flAllocationType, flProtect);
}

LPVOID VirtualAlloc2_Handler(
    HANDLE                 Process,
    PVOID                  BaseAddress,
    SIZE_T                 Size,
    ULONG                  AllocationType,
    ULONG                  PageProtection,
    MEM_EXTENDED_PARAMETER *ExtendedParameters,
    ULONG                  ParameterCount) {
  // create parameters
  size_t param1Size;
  BYTE* param1 = BuildParameter(&param1Size, PARAMETER_POINTER, "Address", BaseAddress);
  size_t param2Size;
  BYTE* param2 = BuildParameter(&param2Size, PARAMETER_UINT32, "Protection", PageProtection);
  size_t param3Size;
  BYTE* param3 = BuildParameter(&param3Size, PARAMETER_UINT32, "AllocType", AllocationType);
  size_t param4Size;
  BYTE* param4 = BuildParameter(&param4Size, PARAMETER_UINT64, "AllocSize", Size);
  DWORD pid = GetProcessId(Process);
  size_t param5Size;
  BYTE* param5 = BuildParameter(&param5Size, PARAMETER_UINT32, "TargetPid", pid);
  size_t fnParamSize;
  BYTE* fnParam = BuildParameter(fnParamSize, PARAMETER_ANSISTRING, "Func", "VirtualAlloc2");
  size_t dllParamSize;
  BYTE* dllParam = BuildParameter(dllParamSize, PARAMETER_ANSISTRING, "DllName", "kernel32.dll");

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
  return ((VIRTUALALLOC2)HookList[HOOK_VIRTUAL_ALLOC2].originalFunc)(Process, BaseAddress, Size, AllocationType, PageProtection, ExtendedParameters, ParameterCount);
}

LPVOID VirtualAllocEx_Handler(
    HANDLE hProcess,
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD  flAllocationType,
    DWORD  flProtect) {
  // create parameters
  size_t param1Size;
  BYTE* param1 = BuildParameter(&param1Size, PARAMETER_POINTER, "Address", lpAddress);
  size_t param2Size;
  BYTE* param2 = BuildParameter(&param2Size, PARAMETER_UINT32, "Protection", flProtect);
  size_t param3Size;
  BYTE* param3 = BuildParameter(&param3Size, PARAMETER_UINT32, "AllocType", flAllocationType);
  size_t param4Size;
  BYTE* param4 = BuildParameter(&param4Size, PARAMETER_UINT64, "AllocSize", dwSize);
  DWORD pid = GetProcessId(hProcess);
  size_t param5Size;
  BYTE* param5 = BuildParameter(&param5Size, PARAMETER_UINT32, "TargetPid", pid);
  size_t fnParamSize;
  BYTE* fnParam = BuildParameter(fnParamSize, PARAMETER_ANSISTRING, "Func", "VirtualAllocEx");
  size_t dllParamSize;
  BYTE* dllParam = BuildParameter(dllParamSize, PARAMETER_ANSISTRING, "DllName", "kernel32.dll");

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
  return ((VIRTUALALLOCEX)HookList[HOOK_VIRTUAL_ALLOC_EX].originalFunc)(hProcess, lpAddress, dwSize, flAllocationType, flProtect);
}

BOOL VirtualProtect_Handler(LPVOID lpAddress, SIZE_T dwSize, DWORD  flNewProtect, PDWORD lpflOldProtect) {
  if (!HasExecutable(flNewProtect)) {
    return ((VIRTUALPROTECT)HookList[HOOK_VIRTUAL_PROTECT].originalFunc)(lpAddress, dwSize, flNewProtect, lpflOldProtect);
  }
  // create parameters
  size_t param1Size;
  BYTE* param1 = BuildParameter(&param1Size, PARAMETER_POINTER, "NewProtect", flNewProtect);
  size_t param2Size;
  BYTE* param2 = BuildParameter(&param2Size, PARAMETER_UINT32, "OldProtect", lpflOldProtect);
  size_t fnParamSize;
  BYTE* fnParam = BuildParameter(fnParamSize, PARAMETER_ANSISTRING, "Func", "VirtualProtect");
  size_t dllParamSize;
  BYTE* dllParam = BuildParameter(dllParamSize, PARAMETER_ANSISTRING, "DllName", "kernel32.dll");

  // create header and total packet
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
  return ((VIRTUALPROTECT)HookList[HOOK_VIRTUAL_PROTECT].originalFunc)(lpAddress, dwSize, flNewProtect, lpflOldProtect);
}

BOOL VirtualProtectEx_Handler(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD  flNewProtect, PDWORD lpflOldProtect) {
  // create parameters
  size_t param1Size;
  BYTE* param1 = BuildParameter(&param1Size, PARAMETER_POINTER, "NewProtect", flNewProtect);
  size_t param2Size;
  BYTE* param2 = BuildParameter(&param2Size, PARAMETER_UINT32, "OldProtect", lpflOldProtect);
  DWORD pid = GetProcessId(hProcess);
  size_t param3Size;
  BYTE* param3 = BuildParameter(&param3Size, PARAMETER_UINT32, "TargetPid", pid);
  size_t fnParamSize;
  BYTE* fnParam = BuildParameter(fnParamSize, PARAMETER_ANSISTRING, "Func", "VirtualProtectEx");
  size_t dllParamSize;
  BYTE* dllParam = BuildParameter(dllParamSize, PARAMETER_ANSISTRING, "DllName", "kernel32.dll");

  // create header and total packet
  size_t totalParamsSize = param1Size + param2Size + param3Size + param4Size + param5Size + fnParamSize + dllParamSize;
  TELEMETRY_HEADER header = GetTelemetryHeader(TM_TYPE_API_CALL, totalParamsSize);

  size_t packetSize = totalParamsSize + sizeof(header);
  BYTE* packet = (BYTE*)malloc(packetSize);
  
  // construct packet 
  memcpy(packet, &header, sizeof(header));
  memcpy(packet + sizeof(header), param1, param1Size);
  memcpy(packet + sizeof(header) + param1Size, param2, param2Size);
  memcpy(packet + sizeof(header) + param1Size + param2Size, param3, param3Size);
  memcpy(packet + sizeof(header) + param1Size + param2Size + param3Size, fnParam, fnParamSize);
  memcpy(packet + sizeof(header) + param1Size + param2Size + param3Size + fnParam, dllParam, dllParamSize);

  free(param1);
  free(param2);
  free(param3);
  free(fnParam);
  free(dllParam);

  EnqueuePacket(g_CriticalQueue, packet, packetSize);
  return ((VIRTUALPROTECTEX)HookList[HOOK_VIRTUAL_PROTECT_EX].originalFunc)(hProcess, lpAddress, dwSize, flNewProtect, lpflOldProtect);
}

NTSTATUS NtProtectVM_Handler(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtection,
    PULONG OldProtection) {
  // create parameters
  size_t param1Size;
  BYTE* param1 = BuildParameter(&param1Size, PARAMETER_POINTER, "NewProtect", NewProtection);
  size_t param2Size;
  BYTE* param2 = BuildParameter(&param2Size, PARAMETER_UINT32, "OldProtect", OldProtection);
  DWORD pid = GetProcessId(ProcessHandle);
  size_t param3Size;
  BYTE* param3 = BuildParameter(&param3Size, PARAMETER_UINT32, "TargetPid", pid);
  size_t fnParamSize;
  BYTE* fnParam = BuildParameter(fnParamSize, PARAMETER_ANSISTRING, "Func", "NtProtectVirtualMemory");
  size_t dllParamSize;
  BYTE* dllParam = BuildParameter(dllParamSize, PARAMETER_ANSISTRING, "DllName", "ntdll.dll");

  // create header and total packet
  size_t totalParamsSize = param1Size + param2Size + param3Size + param4Size + param5Size + fnParamSize + dllParamSize;
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
  return ((NTPROTECTVM)HookList[HOOK_NT_PROTECT_VM].originalFunc)(ProcessHandle, BaseAddress, RegionSize, NewProtection, OldProtection);
}

NTSTATUS NtAllocateVM_Handler(
    HANDLE    ProcessHandle,
    PVOID     *BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T   RegionSize,
    ULONG     AllocationType,
    ULONG     Protect) {

  // parameters:
  // - Address
  // - Protection
  // - AllocType
  // - AllocSize
  // - TargetPid

  // create parameters
  size_t param1Size;
  //! IMPORTANT: this parameter is faulty, same with other virtual allocs
  // the address is typically emtpy in api args, you need to get it after the api call
  BYTE* param1 = BuildParameter(&param1Size, PARAMETER_POINTER, "Address", *BaseAddress);
  size_t param2Size;
  BYTE* param2 = BuildParameter(&param2Size, PARAMETER_UINT32, "Protection", Protect);
  size_t param3Size;
  BYTE* param3 = BuildParameter(&param3Size, PARAMETER_UINT32, "AllocType", AllocationType);
  size_t param4Size;
  BYTE* param4 = BuildParameter(&param4Size, PARAMETER_UINT64, "AllocSize", RegionSize);
  DWORD pid = GetProcessId(ProcessHandle);
  size_t param5Size;
  BYTE* param5 = BuildParameter(&param5Size, PARAMETER_UINT32, "TargetPid", pid);
  size_t fnParamSize;
  BYTE* fnParam = BuildParameter(fnParamSize, PARAMETER_ANSISTRING, "Func", "NtAllocateVirtualMemory");
  size_t dllParamSize;
  BYTE* dllParam = BuildParameter(dllParamSize, PARAMETER_ANSISTRING, "DllName", "ntdll.dll");

  size_t totalParamsSize = param1Size + param2Size + param3Size + param4Size + param5Size;
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
  return ((NTALLOCVM)HookList[HOOK_NT_ALLOC_VM].originalFunc)(ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);
}

NTSTATUS NtAllocateVMEx_Handler(
    HANDLE    ProcessHandle,
    PVOID     *BaseAddress,
    PSIZE_T   RegionSize,
    ULONG     AllocationType,
    ULONG     Protect,
    PMEM_EXTENDED_PARAMETER ExtendedParameters,
    ULONG ExtendedParameterCount) {
  // create parameters
  size_t param1Size;
  //! IMPORTANT: this parameter is faulty, same with other virtual allocs
  // the address is typically emtpy in api args, you need to get it after the api call
  BYTE* param1 = BuildParameter(&param1Size, PARAMETER_POINTER, "Address", *BaseAddress);
  size_t param2Size;
  BYTE* param2 = BuildParameter(&param2Size, PARAMETER_UINT32, "Protection", Protect);
  size_t param3Size;
  BYTE* param3 = BuildParameter(&param3Size, PARAMETER_UINT32, "AllocType", AllocationType);
  size_t param4Size;
  BYTE* param4 = BuildParameter(&param4Size, PARAMETER_UINT64, "AllocSize", RegionSize);
  DWORD pid = GetProcessId(ProcessHandle);
  size_t param5Size;
  BYTE* param5 = BuildParameter(&param5Size, PARAMETER_UINT32, "TargetPid", pid);
  size_t fnParamSize;
  BYTE* fnParam = BuildParameter(fnParamSize, PARAMETER_ANSISTRING, "Func", "NtAllocateVirtualMemoryEx");
  size_t dllParamSize;
  BYTE* dllParam = BuildParameter(dllParamSize, PARAMETER_ANSISTRING, "DllName", "ntdll.dll");

  size_t totalParamsSize = param1Size + param2Size + param3Size + param4Size + param5Size;
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
  return ((NTALLOCVMEX)HookList[HOOK_NT_ALLOC_VM_EX].originalFunc)(ProcessHandle, BaseAddress, RegionSize, AllocationType, Protect, ExtendedParameters, ExtendedParameterCount);
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
  BYTE* fnParam = BuildParameter(fnParamSize, PARAMETER_ANSISTRING, "Func", "NtCreateThread");
  size_t dllParamSize;
  BYTE* dllParam = BuildParameter(dllParamSize, PARAMETER_ANSISTRING, "DllName", "ntdll.dll");

  size_t totalParamsSize = param1Size + param2Size + param3Size;
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
  BYTE* param2 = BuildParameter(&param2Size, PARAMETER_BOOLEAN, "Flags", CreateFlags);
  size_t param3Size;
  GetProcessId(ProcessHandle);
  BYTE* param3 = BuildParameter(&param3Size, PARAMETER_UINT32, "TargetPid", pid);
  size_t fnParamSize;
  BYTE* fnParam = BuildParameter(fnParamSize, PARAMETER_ANSISTRING, "Func", "NtCreateThreadEx");
  size_t dllParamSize;
  BYTE* dllParam = BuildParameter(dllParamSize, PARAMETER_ANSISTRING, "DllName", "ntdll.dll");

  size_t totalParamsSize = param1Size + param2Size + param3Size;
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
  return ((NTCREATETHREADEX)HookList[HOOK_NT_CREATE_THREAD_EX].originalFunc)(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, StartRoutine, Argument, CreateFlags, ZeroBits, StackSize, MaximumStackSize, AttributeList);
}
/*
DWORD QueueUserAPC_Handler(PAPCFUNC arg0, HANDLE arg1, ULONG_PTR arg2) {
    TELEMETRY tm;
    GetHookBaseTelemetryPacket(&tm, "kernel32.dll", HOOK_QUEUE_USER_APC);
    FillEmptyArgs(&tm, 3);

    tm.data.apiCall.args[0].arg.ptrValue = arg0;
    tm.data.apiCall.args[0].type = API_ARG_TYPE_PTR;

    tm.data.apiCall.args[1].arg.ptrValue = arg1;
    tm.data.apiCall.args[1].type = API_ARG_TYPE_PTR;

    tm.data.apiCall.args[2].arg.ptrValue = arg2;
    tm.data.apiCall.args[2].type = API_ARG_TYPE_PTR;

    DWORD dwBytesWritten;
    WriteFile(hTelemetry, &tm, sizeof(tm), &dwBytesWritten, NULL);
    return ((QUEUEUSERAPC)HookList[HOOK_QUEUE_USER_APC].originalFunc)(arg0, arg1, arg2);
}

BOOL QueueUserAPC2_Handler(PAPCFUNC arg0, HANDLE arg1, ULONG_PTR arg2, QUEUE_USER_APC_FLAGS arg3) {
    TELEMETRY tm;
    GetHookBaseTelemetryPacket(&tm, "kernel32.dll", HOOK_QUEUE_USER_APC2);
    FillEmptyArgs(&tm, 4);

    tm.data.apiCall.args[0].arg.ptrValue = arg0;
    tm.data.apiCall.args[0].type = API_ARG_TYPE_PTR;

    tm.data.apiCall.args[1].arg.ptrValue = arg1;
    tm.data.apiCall.args[1].type = API_ARG_TYPE_PTR;

    tm.data.apiCall.args[2].arg.ptrValue = arg2;
    tm.data.apiCall.args[2].type = API_ARG_TYPE_PTR;

    tm.data.apiCall.args[3].arg.ptrValue = arg3;
    tm.data.apiCall.args[3].type = API_ARG_TYPE_PTR;

    DWORD dwBytesWritten;
    WriteFile(hTelemetry, &tm, sizeof(tm), &dwBytesWritten, NULL);
    return ((QUEUEUSERAPC2)HookList[HOOK_QUEUE_USER_APC2].originalFunc)(arg0, arg1, arg2, arg3);
}
*/
HANDLE OpenProcess_Handler(DWORD access, BOOL inherit, DWORD pid) {
  // create parameters
  size_t param1Size;
  BYTE* param1 = BuildParameter(&param1Size, PARAMETER_UINT32, "TargetPid", pid);
  size_t param2Size;
  BYTE* param2 = BuildParameter(&param2Size, PARAMETER_UINT32, "Access", access);
  size_t fnParamSize;
  BYTE* fnParam = BuildParameter(fnParamSize, PARAMETER_ANSISTRING, "Func", "OpenProcess");
  size_t dllParamSize;
  BYTE* dllParam = BuildParameter(dllParamSize, PARAMETER_ANSISTRING, "DllName", "kernel32.dll");

  size_t totalParamsSize = param1Size + param2Size;
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
  return ((OPENPROCESS)HookList[HOOK_OPEN_PROCESS].originalFunc)(access, inherit, pid);
}

NTSTATUS NtOpenProcess_Handler(
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    PCOBJECT_ATTRIBUTES ObjectAttributes,
    PCLIENT_ID ClientId) {
  // create parameters
  size_t param1Size;
  DWORD pid = GetProcessId(ProcessHandle);
  BYTE* param1 = BuildParameter(&param1Size, PARAMETER_UINT32, "TargetPid", pid);
  size_t param2Size;
  BYTE* param2 = BuildParameter(&param2Size, PARAMETER_UINT32, "Access", DesiredAccess);
  size_t fnParamSize;
  BYTE* fnParam = BuildParameter(fnParamSize, PARAMETER_ANSISTRING, "Func", "NtOpenProcess");
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

  EnqueuePacket(g_StandardQueue, packet, packetSize);
  return ((NTOPENPROCESS)HookList[HOOK_NT_OPEN_PROCESS].originalFunc)(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
}
/*
BOOL SetThreadContext_Handler(HANDLE arg0, const CONTEXT arg1) {
    TELEMETRY tm;
    GetHookBaseTelemetryPacket(&tm, "kernel32.dll", "SetThreadContext");
    FillEmptyArgs(&tm, 2);

    tm.data.apiCall.args[0].arg.ptrValue = arg0;
    tm.data.apiCall.args[0].type = API_ARG_TYPE_PTR;

    tm.data.apiCall.args[1].arg.ptrValue = arg1;
    tm.data.apiCall.args[1].type = API_ARG_TYPE_PTR;
    
    DWORD dwBytesWritten;
    WriteFile(hTelemetry, &tm, sizeof(tm), &dwBytesWritten, NULL);
    return ((SETTHREADCONTEXT)HookList[HOOK_SET_THREAD_CONTEXT].originalFunc)(arg0, arg1);
}
*/
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
  BYTE* fnParam = BuildParameter(fnParamSize, PARAMETER_ANSISTRING, "Func", "NtOpenProcess");
  size_t dllParamSize;
  BYTE* dllParam = BuildParameter(dllParamSize, PARAMETER_ANSISTRING, "DllName", "ntdll.dll");

  size_t totalParamsSize = param1Size + param2Size + fnParamSize + dllParamSize;
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
  BYTE* fnParam = BuildParameter(fnParamSize, PARAMETER_ANSISTRING, "Func", "CreateProcessA");
  size_t dllParamSize;
  BYTE* dllParam = BuildParameter(dllParamSize, PARAMETER_ANSISTRING, "DllName", "kernel32.dll");

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

  //params:
  //- TargetPath
  //- CmdLine
  //- flags
  
  size_t param1Size;
  char* appName = WideToAnsi(lpApplicationName);
  BYTE* param1 = BuildParameter(&param1Size, PARAMETER_ANSISTRING, "TargetPath", appName);
  size_t param2Size;
  char* cmdLine = WideToAnsi(lpCommandLine);
  BYTE* param2 = BuildParameter(&param2Size, PARAMETER_ANSISTRING, "CmdLine", cmdLine);
  size_t param3Size;
  BYTE* param3 = BuildParameter(&param3Size, PARAMETER_UINT32, "Flags", dwCreationFlags);
  size_t fnParamSize;
  BYTE* fnParam = BuildParameter(fnParamSize, PARAMETER_ANSISTRING, "Func", "CreateProcessW");
  size_t dllParamSize;
  BYTE* dllParam = BuildParameter(dllParamSize, PARAMETER_ANSISTRING, "DllName", "kernel32.dll");

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
  free(appName); // allocated string
  free(cmdLine); // allocated string
  free(fnParam);
  free(dllParam);

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

  //params:
  //- TargetPath
  //- CmdLine
  //- flags
  //TODO: something about token
  size_t param1Size;
  BYTE* param1 = BuildParameter(&param1Size, PARAMETER_ANSISTRING, "TargetPath", lpApplicationName);
  size_t param2Size;
  BYTE* param2 = BuildParameter(&param2Size, PARAMETER_ANSISTRING, "CmdLine", lpCommandLine);
  size_t param3Size;
  BYTE* param3 = BuildParameter(&param3Size, PARAMETER_UINT32, "Flags", dwCreationFlags);
  size_t fnParamSize;
  BYTE* fnParam = BuildParameter(fnParamSize, PARAMETER_ANSISTRING, "Func", "CreateProcessAsUserA");
  size_t dllParamSize;
  BYTE* dllParam = BuildParameter(dllParamSize, PARAMETER_ANSISTRING, "DllName", "advapi32.dll");

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

  //params:
  //- TargetPath
  //- CmdLine
  //- flags
  //TODO: something about token
  size_t param1Size;
  char* appName = WideToAnsi(lpApplicationName);
  BYTE* param1 = BuildParameter(&param1Size, PARAMETER_ANSISTRING, "TargetPath", appName);
  size_t param2Size;
  char* cmdLine = WideToAnsi(lpCommandLine);
  BYTE* param2 = BuildParameter(&param2Size, PARAMETER_ANSISTRING, "CmdLine", cmdLine);
  size_t param3Size;
  BYTE* param3 = BuildParameter(&param3Size, PARAMETER_UINT32, "Flags", dwCreationFlags);
  size_t fnParamSize;
  BYTE* fnParam = BuildParameter(fnParamSize, PARAMETER_ANSISTRING, "Func", "CreateProcessAsUserW");
  size_t dllParamSize;
  BYTE* dllParam = BuildParameter(dllParamSize, PARAMETER_ANSISTRING, "DllName", "advapi32.dll");

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
  free(appName); // allocated string
  free(cmdLine); // allocated string
  free(fnParam);
  free(dllParam);

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

  //params:
  //- TargetPath
  //- CmdLine
  //- flags
  //TODO: something about token
  //
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
        
  return ((NTCREATEUSERPROCESS)HookList[HOOK_NT_CREATE_USER_PROCESS].originalFunc)(ProcessHandle, ThreadHandle,
    ProcessDesiredAccess, ThreadDesiredAccess, ProcessObjectAttributes, ThreadObjectAttributes, ProcessFlags, ThreadFlags, ProcessParameters, CreateInfo, AttributeList);
}
