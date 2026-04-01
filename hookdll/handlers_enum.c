#include <windows.h>
#include <winternl.h>
#include "hook.h"

//?=======================================================================================+
//?  These are the functions API hooks point to, which get triggered when a hooked API    |
//?   is called. Hook handlers forward information of the event to the agent via          |
//?   named pipes. Packets include API, dll, caller, and parameters with additional       |
//?   info about the call (args or context). Each handler follows the same blueprint.     |
//?                                                                                       |
//?  Handlers start by optionally checking if the call is interesting, and if it          |
//?   deemed uninteresting, the call will pass through immediately without sending        |
//?   a packet. After the filtering, the telemetry packet gets built, and placed in the   |
//?   the packet queue. Finally the handlers pass the call through and return to caller.  |
//?=======================================================================================+

//* This file contains the hook handlers for enumeration APIs


FARPROC GetProcAddress_Handler(HMODULE hModule, LPCSTR lpProcName) {
	size_t param1Size;
	BYTE* param1 = BuildParameter(&param1Size, PARAMETER_ANSISTRING, "Function", lpProcName);
	size_t fnParamSize;
	BYTE* fnParam = BuildParameter(&fnParamSize, PARAMETER_ANSISTRING, "Func", "GetProcAddress");
	size_t dllParamSize;
	BYTE* dllParam = BuildParameter(&dllParamSize, PARAMETER_ANSISTRING, "DllName", "kernel32.dll");

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
	BYTE* param1 = BuildParameter(&param1Size, PARAMETER_ANSISTRING, "Module", lpModuleName);
	size_t fnParamSize;
	BYTE* fnParam = BuildParameter(&fnParamSize, PARAMETER_ANSISTRING, "Func", "GetModuleHandleA");
	size_t dllParamSize;
	BYTE* dllParam = BuildParameter(&dllParamSize, PARAMETER_ANSISTRING, "DllName", "kernel32.dll");

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
	BYTE* param1 = BuildParameter(&param1Size, PARAMETER_ANSISTRING, "Module", modName);
	size_t fnParamSize;
	BYTE* fnParam = BuildParameter(&fnParamSize, PARAMETER_ANSISTRING, "Func", "GetModuleHandleW");
	size_t dllParamSize;
	BYTE* dllParam = BuildParameter(&dllParamSize, PARAMETER_ANSISTRING, "DllName", "kernel32.dll");

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
	BYTE* param1 = BuildParameter(&param1Size, PARAMETER_ANSISTRING, "Module", lpModuleName);
	size_t param2Size;
	BYTE* param2 = BuildParameter(&param2Size, PARAMETER_UINT32, "Flags", dwFlags);
	size_t fnParamSize;
	BYTE* fnParam = BuildParameter(&fnParamSize, PARAMETER_ANSISTRING, "Func", "GetModuleHandleExA");
	size_t dllParamSize;
	BYTE* dllParam = BuildParameter(&dllParamSize, PARAMETER_ANSISTRING, "DllName", "kernel32.dll");

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

BOOL GetModuleHandleExW_Handler(DWORD dwFlags, LPCWSTR lpModuleName, HMODULE* phModule) {
	size_t param1Size;
	char* modName = WideToAnsi(lpModuleName);
	BYTE* param1 = BuildParameter(&param1Size, PARAMETER_ANSISTRING, "Module", modName);
	size_t param2Size;
	BYTE* param2 = BuildParameter(&param2Size, PARAMETER_UINT32, "Flags", dwFlags);
	size_t fnParamSize;
	BYTE* fnParam = BuildParameter(&fnParamSize, PARAMETER_ANSISTRING, "Func", "GetModuleHandleExW");
	size_t dllParamSize;
	BYTE* dllParam = BuildParameter(&dllParamSize, PARAMETER_ANSISTRING, "DllName", "kernel32.dll");

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
	BYTE* fnParam = BuildParameter(&fnParamSize, PARAMETER_ANSISTRING, "Func", "IsDebuggerPresent");
	size_t dllParamSize;
	BYTE* dllParam = BuildParameter(&dllParamSize, PARAMETER_ANSISTRING, "DllName", "kernel32.dll");

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

HWND FindWindowA_Handler(LPCSTR lpClassName, LPCSTR lpWindowName) {
	size_t param1Size;
	BYTE* param1 = BuildParameter(&param1Size, PARAMETER_ANSISTRING, "WindowName", lpWindowName);
	size_t fnParamSize;
	BYTE* fnParam = BuildParameter(&fnParamSize, PARAMETER_ANSISTRING, "Func", "FindWindowA");
	size_t dllParamSize;
	BYTE* dllParam = BuildParameter(&dllParamSize, PARAMETER_ANSISTRING, "DllName", "kernel32.dll");

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
	return ((FINDWINDOWA)HookList[HOOK_FIND_WINDOW_A].originalFunc)(lpClassName, lpWindowName);
}

HWND FindWindowW_Handler(LPCWSTR lpClassName, LPCWSTR lpWindowName) {
	size_t param1Size;
	char* wndName = WideToAnsi(lpWindowName);
	BYTE* param1 = BuildParameter(&param1Size, PARAMETER_ANSISTRING, "WindowName", lpWindowName);
	size_t fnParamSize;
	BYTE* fnParam = BuildParameter(&fnParamSize, PARAMETER_ANSISTRING, "Func", "FindWindowW");
	size_t dllParamSize;
	BYTE* dllParam = BuildParameter(&dllParamSize, PARAMETER_ANSISTRING, "DllName", "kernel32.dll");

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
	free(wndName); // allocated string

	EnqueuePacket(g_StandardQueue, packet, packetSize);
	return ((FINDWINDOWW)HookList[HOOK_FIND_WINDOW_W].originalFunc)(lpClassName, lpWindowName);
}

HWND FindWindowExA_Handler(HWND hWndParent, HWND hWndChildAfter, LPCSTR lpszClass, LPCSTR lpszWindow) {
	size_t param1Size;
	BYTE* param1 = BuildParameter(&param1Size, PARAMETER_ANSISTRING, "WindowName", lpszWindow);
	size_t fnParamSize;
	BYTE* fnParam = BuildParameter(&fnParamSize, PARAMETER_ANSISTRING, "Func", "FindWindowExA");
	size_t dllParamSize;
	BYTE* dllParam = BuildParameter(&dllParamSize, PARAMETER_ANSISTRING, "DllName", "kernel32.dll");

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
	return ((FINDWINDOWEXA)HookList[HOOK_FIND_WINDOW_EX_A].originalFunc)(hWndParent, hWndChildAfter, lpszClass, lpszWindow);
}

HWND FindWindowExW_Handler(HWND hWndParent, HWND hWndChildAfter, LPCWSTR lpszClass, LPCWSTR lpszWindow) {
	size_t param1Size;
	char* wndName = WideToAnsi(lpszWindow);
	BYTE* param1 = BuildParameter(&param1Size, PARAMETER_ANSISTRING, "WindowName", wndName);
	size_t fnParamSize;
	BYTE* fnParam = BuildParameter(&fnParamSize, PARAMETER_ANSISTRING, "Func", "FindWindowExW");
	size_t dllParamSize;
	BYTE* dllParam = BuildParameter(&dllParamSize, PARAMETER_ANSISTRING, "DllName", "kernel32.dll");

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
	free(wndName); // allocated string

	EnqueuePacket(g_StandardQueue, packet, packetSize);
	return ((FINDWINDOWEXW)HookList[HOOK_FIND_WINDOW_EX_W].originalFunc)(hWndParent, hWndChildAfter, lpszClass, lpszWindow);
}

NTSTATUS NtUserFindWindowEx_Handler(HWND hwndParent, HWND hwndChild, PCUNICODE_STRING ClassName, PCUNICODE_STRING WindowName, ULONG Type) {
	size_t param1Size;
	char* wndName = UnicodeStringToAnsi(WindowName);
	BYTE* param1 = BuildParameter(&param1Size, PARAMETER_ANSISTRING, "WindowName", wndName);
	size_t param2Size;
	BYTE* param2 = BuildParameter(&param2Size, PARAMETER_UINT32, "Type", Type);
	size_t fnParamSize;
	BYTE* fnParam = BuildParameter(&fnParamSize, PARAMETER_ANSISTRING, "Func", "NtUserFindWindowEx");
	size_t dllParamSize;
	BYTE* dllParam = BuildParameter(&dllParamSize, PARAMETER_ANSISTRING, "DllName", "ntdll.dll");

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
	free(wndName); // allocated string

	EnqueuePacket(g_StandardQueue, packet, packetSize);
	return ((NTUSERFINDWINDOWEX)HookList[HOOK_NT_USER_FIND_WINDOW_EX].originalFunc)(hwndParent, hwndChild, ClassName, WindowName, Type);
}

BOOL Thread32First_Handler(HANDLE hSnapshot, LPTHREADENTRY32 lpte) {
	size_t fnParamSize;
	BYTE* fnParam = BuildParameter(&fnParamSize, PARAMETER_ANSISTRING, "Func", "Thread32First");
	size_t dllParamSize;
	BYTE* dllParam = BuildParameter(&dllParamSize, PARAMETER_ANSISTRING, "DllName", "kernel32.dll");

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
	return ((THREAD32FIRST)HookList[HOOK_THREAD_32_FIRST].originalFunc)(hSnapshot, lpte);
}

BOOL Thread32Next_Handler(HANDLE hSnapshot, LPTHREADENTRY32 lpte) {
	size_t fnParamSize;
	BYTE* fnParam = BuildParameter(&fnParamSize, PARAMETER_ANSISTRING, "Func", "Thread32Next");
	size_t dllParamSize;
	BYTE* dllParam = BuildParameter(&dllParamSize, PARAMETER_ANSISTRING, "DllName", "kernel32.dll");

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
	return ((THREAD32NEXT)HookList[HOOK_THREAD_32_NEXT].originalFunc)(hSnapshot, lpte);
}

BOOL Process32First_Handler(HANDLE hSnapshot, LPPROCESSENTRY32 lppe) {
	size_t fnParamSize;
	BYTE* fnParam = BuildParameter(&fnParamSize, PARAMETER_ANSISTRING, "Func", "Process32First");
	size_t dllParamSize;
	BYTE* dllParam = BuildParameter(&dllParamSize, PARAMETER_ANSISTRING, "DllName", "kernel32.dll");

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
	return ((PROCESS32FIRST)HookList[HOOK_PROCESS_32_FIRST].originalFunc)(hSnapshot, lppe);
}

BOOL Process32Next_Handler(HANDLE hSnapshot, LPPROCESSENTRY32 lppe) {
	size_t fnParamSize;
	BYTE* fnParam = BuildParameter(&fnParamSize, PARAMETER_ANSISTRING, "Func", "Process32Next");
	size_t dllParamSize;
	BYTE* dllParam = BuildParameter(&dllParamSize, PARAMETER_ANSISTRING, "DllName", "kernel32.dll");

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
	return ((PROCESS32NEXT)HookList[HOOK_PROCESS_32_NEXT].originalFunc)(hSnapshot, lppe);
}

BOOL Process32FirstW_Handler(HANDLE hSnapshot, LPPROCESSENTRY32W lppe) {
	size_t fnParamSize;
	BYTE* fnParam = BuildParameter(&fnParamSize, PARAMETER_ANSISTRING, "Func", "Process32FirstW");
	size_t dllParamSize;
	BYTE* dllParam = BuildParameter(&dllParamSize, PARAMETER_ANSISTRING, "DllName", "kernel32.dll");

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
	return ((PROCESS32FIRSTW)HookList[HOOK_PROCESS_32_FIRST_W].originalFunc)(hSnapshot, lppe);
}

BOOL Process32NextW_Handler(HANDLE hSnapshot, LPPROCESSENTRY32W lppe) {
	size_t fnParamSize;
	BYTE* fnParam = BuildParameter(&fnParamSize, PARAMETER_ANSISTRING, "Func", "Process32NextW");
	size_t dllParamSize;
	BYTE* dllParam = BuildParameter(&dllParamSize, PARAMETER_ANSISTRING, "DllName", "kernel32.dll");

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
	return ((PROCESS32NEXTW)HookList[HOOK_PROCESS_32_NEXT_W].originalFunc)(hSnapshot, lppe);
}

BOOL Module32First_Handler(HANDLE hSnapshot, LPMODULEENTRY32 lpme) {
	size_t fnParamSize;
	BYTE* fnParam = BuildParameter(&fnParamSize, PARAMETER_ANSISTRING, "Func", "Module32First");
	size_t dllParamSize;
	BYTE* dllParam = BuildParameter(&dllParamSize, PARAMETER_ANSISTRING, "DllName", "kernel32.dll");

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
	return ((MODULE32FIRST)HookList[HOOK_MODULE_32_FIRST].originalFunc)(hSnapshot, lpme);
}

BOOL Module32Next_Handler(HANDLE hSnapshot, LPMODULEENTRY32 lpme) {
	size_t fnParamSize;
	BYTE* fnParam = BuildParameter(&fnParamSize, PARAMETER_ANSISTRING, "Func", "Module32Next");
	size_t dllParamSize;
	BYTE* dllParam = BuildParameter(&dllParamSize, PARAMETER_ANSISTRING, "DllName", "kernel32.dll");

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
	return ((MODULE32NEXT)HookList[HOOK_MODULE_32_NEXT].originalFunc)(hSnapshot, lpme);
}

BOOL Module32FirstW_Handler(HANDLE hSnapshot, LPMODULEENTRY32W lpme) {
	size_t fnParamSize;
	BYTE* fnParam = BuildParameter(&fnParamSize, PARAMETER_ANSISTRING, "Func", "Module32FirstW");
	size_t dllParamSize;
	BYTE* dllParam = BuildParameter(&dllParamSize, PARAMETER_ANSISTRING, "DllName", "kernel32.dll");

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
	return ((MODULE32FIRSTW)HookList[HOOK_MODULE_32_FIRST_W].originalFunc)(hSnapshot, lpme);
}

BOOL Module32NextW_Handler(HANDLE hSnapshot, LPMODULEENTRY32W lpme) {
	size_t fnParamSize;
	BYTE* fnParam = BuildParameter(&fnParamSize, PARAMETER_ANSISTRING, "Func", "Module32NextW");
	size_t dllParamSize;
	BYTE* dllParam = BuildParameter(&dllParamSize, PARAMETER_ANSISTRING, "DllName", "kernel32.dll");

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
	return ((MODULE32NEXTW)HookList[HOOK_MODULE_32_NEXT_W].originalFunc)(hSnapshot, lpme);
}

HANDLE CreateTh32Snapshot_Handler(DWORD dwFlags, DWORD th32ProcessId) {
	size_t param1Size;
	BYTE* param1 = BuildParameter(&param1Size, PARAMETER_UINT32, "Flags", dwFlags);
	size_t param2Size;
	BYTE* param2 = BuildParameter(&param2Size, PARAMETER_UINT32, "TargetPid", th32ProcessId);
	size_t fnParamSize;
	BYTE* fnParam = BuildParameter(&fnParamSize, PARAMETER_ANSISTRING, "Func", "CreateToolhelp32Snapshot");
	size_t dllParamSize;
	BYTE* dllParam = BuildParameter(&dllParamSize, PARAMETER_ANSISTRING, "DllName", "kernel32.dll");

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

NTSTATUS NtQuerySystemInformation_Handler(
	SYSTEM_INFORMATION_CLASS SystemInfoClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength) {

	size_t param1Size;
	BYTE* param1 = BuildParameter(&param1Size, PARAMETER_UINT32, "InfoClass", SystemInfoClass);
	size_t fnParamSize;
	BYTE* fnParam = BuildParameter(&fnParamSize, PARAMETER_ANSISTRING, "Func", "NtQuerySystemInformation");
	size_t dllParamSize;
	BYTE* dllParam = BuildParameter(&dllParamSize, PARAMETER_ANSISTRING, "DllName", "ntdll.dll");

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
	return ((NTQUERYSYSTEMINFO)HookList[HOOK_NT_QUERY_SYSTEM_INFO].originalFunc)(SystemInfoClass, SystemInformation, SystemInformationLength, ReturnLength);
}

NTSTATUS NtQuerySystemInformationEx_Handler(
	SYSTEM_INFORMATION_CLASS SystemInfoClass,
	PVOID InputBuffer, ULONG InputBufferLength,
	PVOID SystemInformation, ULONG SystemInformationLength,
	PULONG ReturnLength) {

	size_t param1Size;
	BYTE* param1 = BuildParameter(&param1Size, PARAMETER_UINT32, "InfoClass", SystemInfoClass);
	size_t fnParamSize;
	BYTE* fnParam = BuildParameter(&fnParamSize, PARAMETER_ANSISTRING, "Func", "NtQuerySystemInformationEx");
	size_t dllParamSize;
	BYTE* dllParam = BuildParameter(&dllParamSize, PARAMETER_ANSISTRING, "DllName", "ntdll.dll");

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
	return ((NTQUERYSYSTEMINFOEX)HookList[HOOK_NT_QUERY_SYSTEM_INFO_EX].originalFunc)(SystemInfoClass, InputBuffer, InputBufferLength, SystemInformation, SystemInformationLength, ReturnLength);
}

NTSTATUS NtQueryInformationProcess_Handler(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength) {
	
	size_t param1Size;
	BYTE* param1 = BuildParameter(&param1Size, PARAMETER_UINT32, "InfoClass", ProcessInformationClass);
	size_t fnParamSize;
	BYTE* fnParam = BuildParameter(&fnParamSize, PARAMETER_ANSISTRING, "Func", "NtQueryInformationProcess");
	size_t dllParamSize;
	BYTE* dllParam = BuildParameter(&dllParamSize, PARAMETER_ANSISTRING, "DllName", "ntdll.dll");

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
	return ((NTQUERYINFOPROCESS)HookList[HOOK_NT_QUERY_INFO_PROCESS].originalFunc)(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength);
}

NtQueryInformationProcess_Handler(
    HANDLE ThreadHandle,
    THREADINFOCLASS ThreadInformationClass,
    PVOID ThreadInformation,
    ULONG ThreadInformationLength,
    PULONG ReturnLength) {
	
	size_t param1Size;
	BYTE* param1 = BuildParameter(&param1Size, PARAMETER_UINT32, "InfoClass", ThreadInformationClass);
	size_t fnParamSize;
	BYTE* fnParam = BuildParameter(&fnParamSize, PARAMETER_ANSISTRING, "Func", "NtQueryInformationThread");
	size_t dllParamSize;
	BYTE* dllParam = BuildParameter(&dllParamSize, PARAMETER_ANSISTRING, "DllName", "ntdll.dll");

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
	return ((NTQUERYINFOTHREAD)HookList[HOOK_NT_QUERY_INFO_THREAD].originalFunc)(ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength, ReturnLength);
}