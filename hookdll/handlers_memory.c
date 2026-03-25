#include <windows.h>
#include "hook.h"

//*==============================[ Memory Protection ]====================================

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
  BYTE* fnParam = BuildParameter(&fnParamSize, PARAMETER_ANSISTRING, "Func", "VirtualProtect");
  size_t dllParamSize;
  BYTE* dllParam = BuildParameter(&dllParamSize, PARAMETER_ANSISTRING, "DllName", "kernel32.dll");

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
  BYTE* fnParam = BuildParameter(&fnParamSize, PARAMETER_ANSISTRING, "Func", "VirtualProtectEx");
  size_t dllParamSize;
  BYTE* dllParam = BuildParameter(&dllParamSize, PARAMETER_ANSISTRING, "DllName", "kernel32.dll");

  // create header and total packet
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
  return ((NTPROTECTVM)HookList[HOOK_NT_PROTECT_VM].originalFunc)(ProcessHandle, BaseAddress, RegionSize, NewProtection, OldProtection);
}
//*==============================[ Memory Allocation ]====================================

LPVOID VirtualAlloc_Handler(LPVOID lpAddress, SIZE_T dwSize, DWORD  flAllocationType, DWORD  flProtect) {
  if (!HasExecutable(flProtect) && flAllocationType&PAGE_GUARD == 0) {
    return ((VIRTUALALLOC)HookList[HOOK_VIRTUAL_ALLOC].originalFunc)(lpAddress, dwSize, flAllocationType, flProtect);
  }

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
  BYTE* fnParam = BuildParameter(&fnParamSize, PARAMETER_ANSISTRING, "Func", "VirtualAlloc");
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
  BYTE* fnParam = BuildParameter(&fnParamSize, PARAMETER_ANSISTRING, "Func", "VirtualAlloc2");
  size_t dllParamSize;
  BYTE* dllParam = BuildParameter(&dllParamSize, PARAMETER_ANSISTRING, "DllName", "kernel32.dll");

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
  BYTE* fnParam = BuildParameter(&fnParamSize, PARAMETER_ANSISTRING, "Func", "VirtualAllocEx");
  size_t dllParamSize;
  BYTE* dllParam = BuildParameter(&dllParamSize, PARAMETER_ANSISTRING, "DllName", "kernel32.dll");

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

NTSTATUS NtAllocateVM_Handler(
    HANDLE    ProcessHandle,
    PVOID     *BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T   RegionSize,
    ULONG     AllocationType,
    ULONG     Protect) {

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
  BYTE* fnParam = BuildParameter(&fnParamSize, PARAMETER_ANSISTRING, "Func", "NtAllocateVirtualMemory");
  size_t dllParamSize;
  BYTE* dllParam = BuildParameter(&dllParamSize, PARAMETER_ANSISTRING, "DllName", "ntdll.dll");

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
  BYTE* fnParam = BuildParameter(&fnParamSize, PARAMETER_ANSISTRING, "Func", "NtAllocateVirtualMemoryEx");
  size_t dllParamSize;
  BYTE* dllParam = BuildParameter(&dllParamSize, PARAMETER_ANSISTRING, "DllName", "ntdll.dll");

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
  return ((NTALLOCVMEX)HookList[HOOK_NT_ALLOC_VM_EX].originalFunc)(ProcessHandle, BaseAddress, RegionSize, AllocationType, Protect, ExtendedParameters, ExtendedParameterCount);
}

//*=============================[ Remote Reads/Writes ]=============================

BOOL ReadProcessMemory_Handler(
    HANDLE  hProcess,
    LPCVOID lpBaseAddress,
    LPVOID  lpBuffer,
    SIZE_T  nSize,
    SIZE_T  *lpNumberOfBytesRead) {
    // create parameters
    size_t param1Size;
    BYTE* param1 = BuildParameter(&param1Size, PARAMETER_UINT32, "TargetPid", GetProcessId(hProcess));
    size_t param2Size;
    BYTE* param2 = BuildParameter(&param2Size, PARAMETER_POINTER, "Address", lpBaseAddress);
    size_t param3Size;
    BYTE* param3 = BuildParameter(&param3Size, PARAMETER_UINT64, "Size", nSize);
    size_t fnParamSize;
    BYTE* fnParam = BuildParameter(&fnParamSize, PARAMETER_ANSISTRING, "Func", "ReadProcessMemory");
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
    return ((READPROCESSMEMORY)HookList[HOOK_READ_PROCESS_MEMORY].originalFunc)(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead);
}

BOOL WriteProcessMemory_Handler(
    HANDLE  hProcess,
    LPVOID  lpBaseAddress,
    LPCVOID lpBuffer,
    SIZE_T  nSize,
    SIZE_T  *lpNumberOfBytesWritten) {
    // create parameters
    size_t param1Size;
    BYTE* param1 = BuildParameter(&param1Size, PARAMETER_UINT32, "TargetPid", GetProcessId(hProcess));
    size_t param2Size;
    BYTE* param2 = BuildParameter(&param2Size, PARAMETER_POINTER, "Address", lpBaseAddress);
    size_t param3Size;
    BYTE* param3 = BuildParameter(&param3Size, PARAMETER_UINT64, "Size", nSize);
    size_t fnParamSize;
    BYTE* fnParam = BuildParameter(&fnParamSize, PARAMETER_ANSISTRING, "Func", "WriteProcessMemory");
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
    return ((WRITEPROCESSMEMORY)HookList[HOOK_WRITE_PROCESS_MEMORY].originalFunc)(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten);
}

NTSTATUS NtReadVirtualMemory_Handler(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T NumberOfBytesToRead,
    PSIZE_T NumberOfBytesRead) {
    // create parameters
    size_t param1Size;
    BYTE* param1 = BuildParameter(&param1Size, PARAMETER_UINT32, "TargetPid", GetProcessId(ProcessHandle));
    size_t param2Size;
    BYTE* param2 = BuildParameter(&param2Size, PARAMETER_POINTER, "Address", BaseAddress);
    size_t param3Size;
    BYTE* param3 = BuildParameter(&param3Size, PARAMETER_UINT64, "Size", NumberOfBytesRead);
    size_t fnParamSize;
    BYTE* fnParam = BuildParameter(&fnParamSize, PARAMETER_ANSISTRING, "Func", "NtReadVirtualMemory");
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
    return ((NTREADVIRTUALMEMORY)HookList[HOOK_NT_READ_VIRTUAL_MEMORY].originalFunc)(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToRead, NumberOfBytesRead);
}

NTSTATUS NtReadVirtualMemoryEx_Handler(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T NumberOfBytesToRead,
    PSIZE_T NumberOfBytesRead,
    ULONG Flags) {
    // create parameters
    size_t param1Size;
    BYTE* param1 = BuildParameter(&param1Size, PARAMETER_UINT32, "TargetPid", GetProcessId(ProcessHandle));
    size_t param2Size;
    BYTE* param2 = BuildParameter(&param2Size, PARAMETER_POINTER, "Address", BaseAddress);
    size_t param3Size;
    BYTE* param3 = BuildParameter(&param3Size, PARAMETER_UINT64, "Size", NumberOfBytesRead);
    size_t fnParamSize;
    BYTE* fnParam = BuildParameter(&fnParamSize, PARAMETER_ANSISTRING, "Func", "NtReadVirtualMemoryEx");
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
    return ((NTREADVIRTUALMEMORYEX)HookList[HOOK_NT_READ_VIRTUAL_MEMORY_EX].originalFunc)(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToRead, NumberOfBytesRead, Flags);

}

NTSTATUS NtWriteVirtualMemory_Handler(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T NumberOfBytesToWrite,
    PSIZE_T NumberOfBytesWritten) {
    // create parameters
    size_t param1Size;
    BYTE* param1 = BuildParameter(&param1Size, PARAMETER_UINT32, "TargetPid", GetProcessId(ProcessHandle));
    size_t param2Size;
    BYTE* param2 = BuildParameter(&param2Size, PARAMETER_POINTER, "Address", BaseAddress);
    size_t param3Size;
    BYTE* param3 = BuildParameter(&param3Size, PARAMETER_UINT64, "Size", NumberOfBytesWritten);
    size_t fnParamSize;
    BYTE* fnParam = BuildParameter(&fnParamSize, PARAMETER_ANSISTRING, "Func", "NtWriteVirtualMemory");
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
    return ((NTREADVIRTUALMEMORY)HookList[HOOK_NT_READ_VIRTUAL_MEMORY].originalFunc)(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToWrite, NumberOfBytesWritten);

}

//*=================================[ File Mapping ]======================================

HANDLE CreateFileMappingA_Handler(
    HANDLE                hFile,
    LPSECURITY_ATTRIBUTES lpFileMappingAttributes,
    DWORD                 flProtect,
    DWORD                 dwMaximumSizeHigh,
    DWORD                 dwMaximumSizeLow,
    LPCSTR                lpName) {

    BYTE* param1;
    size_t param1Size;
    char targetPath[MAX_PATH];
    DWORD result = GetFinalPathNameByHandleA(hFile, &targetPath, MAX_PATH, 0);
    if (result == 0) {
        param1 = BuildParameter(&param1Size, PARAMETER_ANSISTRING, "TargetPath", "(unknown)");
    } else {
        param1 = BuildParameter(&param1Size, PARAMETER_ANSISTRING, "TargetPath", targetPath);
    }
    size_t param2Size;
    BYTE* param2 = BuildParameter(&param2Size, PARAMETER_UINT32, "Protection", flProtect);
    size_t fnParamSize;
    BYTE* fnParam = BuildParameter(&fnParamSize, PARAMETER_ANSISTRING, "Func", "CreateFileMappingA");
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
    return ((CREATEFILEMAPPINGA)HookList[HOOK_CREATE_FILE_MAPPING_A].originalFunc)(hFile, lpFileMappingAttributes, flProtect, dwMaximumSizeHigh, dwMaximumSizeLow, lpName);
}

HANDLE CreateFileMappingW_Handler(
    HANDLE                hFile,
    LPSECURITY_ATTRIBUTES lpFileMappingAttributes,
    DWORD                 flProtect,
    DWORD                 dwMaximumSizeHigh,
    DWORD                 dwMaximumSizeLow,
    LPCWSTR               lpName) {

    BYTE* param1;
    size_t param1Size;
    char targetPath[MAX_PATH];
    DWORD result = GetFinalPathNameByHandleA(hFile, &targetPath, MAX_PATH, 0);
    if (result == 0) {
        param1 = BuildParameter(&param1Size, PARAMETER_ANSISTRING, "TargetPath", "(unknown)");
    } else {
        param1 = BuildParameter(&param1Size, PARAMETER_ANSISTRING, "TargetPath", targetPath);
    }
    size_t param2Size;
    BYTE* param2 = BuildParameter(&param2Size, PARAMETER_UINT32, "Protection", flProtect);
    size_t fnParamSize;
    BYTE* fnParam = BuildParameter(&fnParamSize, PARAMETER_ANSISTRING, "Func", "CreateFileMappingW");
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
    return ((CREATEFILEMAPPINGW)HookList[HOOK_CREATE_FILE_MAPPING_W].originalFunc)(hFile, lpFileMappingAttributes, flProtect, dwMaximumSizeHigh, dwMaximumSizeLow, lpName);
}


HANDLE CreateFileMapping2_Handler(
  HANDLE                 File,
  SECURITY_ATTRIBUTES    *SecurityAttributes,
  ULONG                  DesiredAccess,
  ULONG                  PageProtection,
  ULONG                  AllocationAttributes,
  ULONG64                MaximumSize,
  PCWSTR                 Name,
  MEM_EXTENDED_PARAMETER *ExtendedParameters,
  ULONG                  ParameterCount) {

    BYTE* param1;
    size_t param1Size;
    char targetPath[MAX_PATH];
    DWORD result = GetFinalPathNameByHandleA(File, &targetPath, MAX_PATH, 0);
    if (result == 0) {
        param1 = BuildParameter(&param1Size, PARAMETER_ANSISTRING, "TargetPath", "(unknown)");
    } else {
        param1 = BuildParameter(&param1Size, PARAMETER_ANSISTRING, "TargetPath", targetPath);
    }
    size_t param2Size;
    BYTE* param2 = BuildParameter(&param2Size, PARAMETER_UINT32, "Protection", PageProtection);
    size_t param3Size;
    BYTE* param3 = BuildParameter(&param3Size, PARAMETER_UINT32, "AllocType", AllocationAttributes);
    size_t fnParamSize;
    BYTE* fnParam = BuildParameter(&fnParamSize, PARAMETER_ANSISTRING, "Func", "CreateFileMapping2");
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
    return ((CREATEFILEMAPPING2)HookList[HOOK_CREATE_FILE_MAPPING_2].originalFunc)(File, SecurityAttributes, DesiredAccess, 
        PageProtection, AllocationAttributes, MaximumSize, Name, ExtendedParameters, ParameterCount);
}


HANDLE CreateFileMappingNumaW_Handler(
    HANDLE                hFile,
    LPSECURITY_ATTRIBUTES lpFileMappingAttributes,
    DWORD                 flProtect,
    DWORD                 dwMaximumSizeHigh,
    DWORD                 dwMaximumSizeLow,
    LPCWSTR               lpName,
    DWORD                 nndPreferred) {

    BYTE* param1;
    size_t param1Size;
    char targetPath[MAX_PATH];
    DWORD result = GetFinalPathNameByHandleA(hFile, &targetPath, MAX_PATH, 0);
    if (result == 0) {
        param1 = BuildParameter(&param1Size, PARAMETER_ANSISTRING, "TargetPath", "(unknown)");
    } else {
        param1 = BuildParameter(&param1Size, PARAMETER_ANSISTRING, "TargetPath", targetPath);
    }
    size_t param2Size;
    BYTE* param2 = BuildParameter(&param2Size, PARAMETER_UINT32, "Protection", flProtect);
    size_t fnParamSize;
    BYTE* fnParam = BuildParameter(&fnParamSize, PARAMETER_ANSISTRING, "Func", "CreateFileMappingNumaW");
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
    return ((CREATEFILEMAPPINGNUMAW)HookList[HOOK_CREATE_FILE_MAPPING_NUMAW].originalFunc)(File, lpFileMappingAttributes, flProtect,
        dwMaximumSizeHigh, dwMaximumSizeLow, lpName, nndPreferred); 
}

HANDLE CreateFileMappingNumaA_Handler(
    HANDLE                hFile,
    LPSECURITY_ATTRIBUTES lpFileMappingAttributes,
    DWORD                 flProtect,
    DWORD                 dwMaximumSizeHigh,
    DWORD                 dwMaximumSizeLow,
    LPCSTR                lpName,
    DWORD                 nndPreferred) {

    BYTE* param1;
    size_t param1Size;
    char targetPath[MAX_PATH];
    DWORD result = GetFinalPathNameByHandleA(hFile, &targetPath, MAX_PATH, 0);
    if (result == 0) {
        param1 = BuildParameter(&param1Size, PARAMETER_ANSISTRING, "TargetPath", "(unknown)");
    } else {
        param1 = BuildParameter(&param1Size, PARAMETER_ANSISTRING, "TargetPath", targetPath);
    }
    size_t param2Size;
    BYTE* param3 = BuildParameter(&param3Size, PARAMETER_UINT32, "AllocType", AllocationAttributes);
    size_t fnParamSize;
    BYTE* fnParam = BuildParameter(&fnParamSize, PARAMETER_ANSISTRING, "Func", "CreateFileMappingNumaA");
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
    return ((CREATEFILEMAPPINGNUMAA)HookList[HOOK_CREATE_FILE_MAPPING_NUMAA].originalFunc)(File, lpFileMappingAttributes, flProtect,
        dwMaximumSizeHigh, dwMaximumSizeLow, lpName, nndPreferred); 
}


NTSTATUS NtCreateSection_Handler(
    PHANDLE SectionHandle,
    ACCESS_MASK DesiredAccess,
    PCOBJECT_ATTRIBUTES ObjectAttributes,
    PLARGE_INTEGER MaximumSize,
    ULONG SectionPageProtection,
    ULONG AllocationAttributes,
    HANDLE FileHandle) {

    BYTE* param1;
    size_t param1Size;
    char targetPath[MAX_PATH];
    DWORD result = GetFinalPathNameByHandleA(FileHandle, &targetPath, MAX_PATH, 0);
    if (result == 0) {
        param1 = BuildParameter(&param1Size, PARAMETER_ANSISTRING, "TargetPath", "(unknown)");
    } else {
        param1 = BuildParameter(&param1Size, PARAMETER_ANSISTRING, "TargetPath", targetPath);
    }
    size_t param2Size;
    BYTE* param2 = BuildParameter(&param2Size, PARAMETER_UINT32, "Protection", SectionPageProtection);
    size_t param3Size;
    BYTE* param3 = BuildParameter(&param3Size, PARAMETER_UINT32, "AllocType", AllocationAttributes);
    size_t fnParamSize;
    BYTE* fnParam = BuildParameter(&fnParamSize, PARAMETER_ANSISTRING, "Func", "NtCreateSection");
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
    memcpy(packet + sizeof(header) + param1Size + param2Size, param3, param3Size);
    memcpy(packet + sizeof(header) + param1Size + param2Size + param3Size, fnParam, fnParamSize);
    memcpy(packet + sizeof(header) + param1Size + param2Size + param3Size + fnParamSize, dllParam, dllParamSize);

    free(param1);
    free(param2);
    free(param3);
    free(fnParam);
    free(dllParam);

    EnqueuePacket(g_StandardQueue, packet, packetSize);
    return ((NTCREATESECTION)HookList[HOOK_NT_CREATE_SECTION].originalFunc)(SectionHandle, DesiredAccess,
        ObjectAttributes, MaximumSize, SectionPageProtection, AllocationAttributes, FileHandle);
}

NTSTATUS NtCreateSectionEx_Handler(
    PHANDLE SectionHandle,
    ACCESS_MASK DesiredAccess,
    PCOBJECT_ATTRIBUTES ObjectAttributes,
    PLARGE_INTEGER MaximumSize,
    ULONG SectionPageProtection,
    ULONG AllocationAttributes,
    HANDLE FileHandle
    PMEM_EXTENDED_PARAMETER ExtendedParameters,
    ULONG ExtendedParameterCount) {

    BYTE* param1;
    size_t param1Size;
    char targetPath[MAX_PATH];
    DWORD result = GetFinalPathNameByHandleA(FileHandle, &targetPath, MAX_PATH, 0);
    if (result == 0) {
        param1 = BuildParameter(&param1Size, PARAMETER_ANSISTRING, "TargetPath", "(unknown)");
    } else {
        param1 = BuildParameter(&param1Size, PARAMETER_ANSISTRING, "TargetPath", targetPath);
    }
    size_t param2Size;
    BYTE* param2 = BuildParameter(&param2Size, PARAMETER_UINT32, "Protection", SectionPageProtection);
    size_t param3Size;
    BYTE* param3 = BuildParameter(&param3Size, PARAMETER_UINT32, "AllocType", AllocationAttributes);
    size_t fnParamSize;
    BYTE* fnParam = BuildParameter(&fnParamSize, PARAMETER_ANSISTRING, "Func", "NtCreateSectionEx");
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
    memcpy(packet + sizeof(header) + param1Size + param2Size, param3, param3Size);
    memcpy(packet + sizeof(header) + param1Size + param2Size + param3Size, fnParam, fnParamSize);
    memcpy(packet + sizeof(header) + param1Size + param2Size + param3Size + fnParamSize, dllParam, dllParamSize);

    free(param1);
    free(param2);
    free(param3);
    free(fnParam);
    free(dllParam);

    EnqueuePacket(g_StandardQueue, packet, packetSize);
    return ((NTCREATESECTIONEX)HookList[HOOK_NT_CREATE_SECTION_EX].originalFunc)(SectionHandle, DesiredAccess,
        ObjectAttributes, MaximumSize, SectionPageProtection, AllocationAttributes, FileHandle, ExtendedParameters, ExtendedParameterCount);
}

