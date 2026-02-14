#include <windows.h>
#include <winternl.h>
#include <stdio.h>
#include "hook.h"

//TODO: read from a config file, currently kind of a ghetto system for enabling hooks...
//? To enable or disable hooks, add them here and the dll to TrackedModules
//? The function will also need a handler function in handlers.c and also
//?  you need to create a typedef so the function can be called from pointer in the handler,
//?  also you need to add an enum for it in correct spot in hook.h HOOK_INDEX enum.
//? Notice, if you disable a hook by commenting it out in this list, you will also
//?  need to comment out the enum in HOOK_INDEX, or it will mess up every hook after
HookEntry HookList[] = {
    { "MessageBoxA", "user32.dll", NULL, NULL,              (FARPROC)MessageBoxA_Handler, {0} },
    { "VirtualProtect", "kernelbase.dll", NULL, NULL,       (FARPROC)VirtualProtect_Handler, {0} },
    { "VirtualProtectEx", "kernelbase.dll", NULL, NULL,     (FARPROC)VirtualProtectEx_Handler, {0} },
    { "NtProtectVirtualMemory", "ntdll.dll", NULL, NULL,    (FARPROC)NtProtectVM_Handler, {0} },
    { "VirtualAlloc", "kernel32.dll", NULL, NULL,           (FARPROC)VirtualAlloc_Handler, {0} },
    { "VirtualAlloc2", "kernelbase.dll", NULL, NULL,        (FARPROC)VirtualAlloc2_Handler, {0} },
    { "VirtualAllocEx", "kernel32.dll", NULL, NULL,         (FARPROC)VirtualAllocEx_Handler, {0} },
    { "NtAllocateVirtualMemory", "ntdll.dll", NULL, NULL,   (FARPROC)NtAllocateVM_Handler, {0} },
    { "NtAllocateVirtualMemoryEx", "ntdll.dll", NULL, NULL, (FARPROC)NtAllocateVMEx_Handler, {0} },
    { "OpenProcess", "kernel32.dll", NULL, NULL,            (FARPROC)OpenProcess_Handler, {0} },
    { "NtOpenProcess", "ntdll.dll", NULL, NULL,             (FARPROC)NtOpenProcess_Handler, {0} },
    { "OpenThread", "kernel32.dll", NULL, NULL,             (FARPROC)OpenThread_Handler, {0} },
    { "NtOpenThread", "ntdll.dll", NULL, NULL,              (FARPROC)NtOpenThread_Handler, {0} },
    { "CreateProcessA", "kernel32.dll", NULL, NULL,         (FARPROC)CreateProcessA_Handler, {0} },
    { "CreateProcessW", "kernel32.dll", NULL, NULL,         (FARPROC)CreateProcessW_Handler, {0} },
    { "CreateProcessAsUserA", "kernel32.dll", NULL, NULL,   (FARPROC)CreateProcessAsUserA_Handler, {0} },
    { "CreateProcessAsUserW", "kernel32.dll", NULL, NULL,   (FARPROC)CreateProcessAsUserW_Handler, {0} },
    { "NtCreateProcess", "ntdll.dll", NULL, NULL,           (FARPROC)NtCreateProcess_Handler, {0} },
    { "NtCreateProcessEx", "ntdll.dll", NULL, NULL,         (FARPROC)NtCreateProcessEx_Handler, {0} },
    { "NtCreateUserProcess", "ntdll.dll", NULL, NULL,       (FARPROC)NtCreateUserProcess_Handler, {0} },
    { "CreateThread", "kernel32.dll", NULL, NULL,           (FARPROC)CreateThread_Handler, {0} },
    { "CreateRemoteThread", "kernel32.dll", NULL, NULL,     (FARPROC)CreateRemoteThread_Handler, {0} },
    { "CreateRemoteThreadEx", "kernel32.dll", NULL, NULL,   (FARPROC)CreateRemoteThreadEx_Handler, {0} },
    { "NtCreateThread", "ntdll.dll", NULL, NULL,            (FARPROC)NtCreateThread_Handler, {0} },
    { "NtCreateThreadEx", "ntdll.dll", NULL, NULL,          (FARPROC)NtCreateThreadEx_Handler, {0} },
    { "CreateFiber", "kernel32.dll", NULL, NULL,            (FARPROC)CreateFiber_Handler, {0} },
    { "LoadLibraryA", "kernel32.dll", NULL, NULL,           (FARPROC)LoadLibraryA_Handler, {0} },
    { "LoadLibraryW", "kernel32.dll", NULL, NULL,           (FARPROC)LoadLibraryW_Handler, {0} },
    { "LoadLibraryExW", "kernel32.dll", NULL, NULL,         (FARPROC)LoadLibraryExA_Handler, {0} },
    { "LoadLibraryExW", "kernel32.dll", NULL, NULL,         (FARPROC)LoadLibraryExW_Handler, {0} },
    { "LdrLoadDll", "ntdll.dll", NULL, NULL,                (FARPROC)LdrLoadDll_Handler, {0} },
    { "GetModuleHandleA", "kernel32.dll", NULL, NULL,       (FARPROC)GetModuleHandleA_Handler, {0} },
    { "GetModuleHandleW", "kernel32.dll", NULL, NULL,       (FARPROC)GetModuleHandleW_Handler, {0} },
    { "GetModuleHandleExA", "kernel32.dll", NULL, NULL,                (FARPROC)GetModuleHandleExA_Handler, {0} },
    { "GetModuleHandleExW", "kernel32.dll", NULL, NULL,                (FARPROC)GetModuleHandleExW_Handler, {0} },
    { "GetProcAddress", "kernel32.dll", NULL, NULL,                    (FARPROC)GetProcAddress_Handler, {0} },
    { "SetDefaultDllDirectories", "kernel32.dll", NULL, NULL,          (FARPROC)SetDefaultDllDirectories_Handler, {0} },
    { "GetThreadContext", "kernel32.dll", NULL, NULL,                  (FARPROC)GetThreadContext_Handler, {0} },
    { "NtGetContextThread", "ntdll.dll", NULL, NULL,                   (FARPROC)NtGetContextThread_Handler, {0} },
    { "SetThreadContext", "kernel32.dll", NULL, NULL,                  (FARPROC)SetThreadContext_Handler, {0} },
    { "NtSetContextThread", "ntdll.dll", NULL, NULL,                   (FARPROC)NtSetContextThread_Handler, {0} },
    { "SuspendThread", "kernel32.dll", NULL, NULL,                     (FARPROC)SuspendThread_Handler, {0} },
    { "ResumeThread", "kernel32.dll", NULL, NULL,                      (FARPROC)ResumeThread_Handler, {0} },
    { "NtSuspendThread", "ntdll.dll", NULL, NULL,                      (FARPROC)NtSuspendThread_Handler, {0} },
    { "NtResumeThread", "ntdll.dll", NULL, NULL,                       (FARPROC)NtResumeThread_Handler, {0} },
    { "TerminateThread", "kernel32.dll", NULL, NULL,                   (FARPROC)TerminateThread_Handler, {0} },
    { "NtTerminateThread", "ntdll.dll", NULL, NULL,                    (FARPROC)NtTerminateThread_Handler, {0} },
    { "TerminateProcess", "kernel32.dll", NULL, NULL,                  (FARPROC)TerminateProcess_Handler, {0} },
    { "NtTerminateProcess", "ntdll.dll", NULL, NULL,                   (FARPROC)NtTerminateProcess_Handler, {0} },
    { "NtSuspendProcess", "ntdll.dll", NULL, NULL,                     (FARPROC)NtSuspendProcess_Handler, {0} },
    { "NtResumeProcess", "ntdll.dll", NULL, NULL,                      (FARPROC)NtResumeProcess_Handler, {0} },
    { "QueueUserAPC", "kernel32.dll", NULL, NULL,                      (FARPROC)QueueUserAPC_Handler, {0} },
    { "QueueUserAPC2", "kernel32.dll", NULL, NULL,                     (FARPROC)QueueUserAPC2_Handler, {0} },
    { "NtQueueApcThread", "ntdll.dll", NULL, NULL,                     (FARPROC)NtQueueApcThread_Handler, {0} },
    { "NtQueueApcThreadEx", "ntdll.dll", NULL, NULL,                   (FARPROC)NtQueueApcThreadEx_Handler, {0} },
    { "NtQueueApcThreadEx2", "ntdll.dll", NULL, NULL,                  (FARPROC)NtQueueApcThreadEx2_Handler, {0} },
    { "AdjustTokenPrivileges", "advapi32.dll", NULL, NULL,             (FARPROC)AdjustTokenPrivileges_Handler, {0} },
    { "WaitForSingleObject", "kernel32.dll", NULL, NULL,               (FARPROC)WaitForSingleObject_Handler, {0} },
    { "WaitForSingleObjectEx", "kernel32.dll", NULL, NULL,             (FARPROC)WaitForSingleObjectEx_Handler, {0} },
    { "WaitForMultipleObjects", "kernel32.dll", NULL, NULL,            (FARPROC)WaitForMultipleObjects_Handler, {0} },
    { "WaitForMultipleObjectsEx", "kernel32.dll", NULL, NULL,          (FARPROC)WaitForMultipleObjectsEx_Handler, {0} },
    { "MsgWaitForMultipleObjects", "user32.dll", NULL, NULL,           (FARPROC)MsgWaitForMultipleObjects_Handler, {0} },
    { "MsgWaitForMultipleObjectsEx", "user32.dll", NULL, NULL,         (FARPROC)MsgWaitForMultipleObjectsEx_Handler, {0} },
    { "MsgWaitForMultipleObjectsEx", "user32.dll", NULL, NULL,         (FARPROC)MsgWaitForMultipleObjectsEx_Handler, {0} },
    { "SignalObjectAndWait", "kernel32.dll", NULL, NULL,               (FARPROC)SignalObjectAndWait_Handler, {0} },
    { "SleepEx", "kernel32.dll", NULL, NULL,                           (FARPROC)SleepEx_Handler, {0} },
    { "WaitOnAddress", "api-ms-win-core-synch-l1-2-0.dll", NULL, NULL, (FARPROC)WaitOnAddress_Handler, {0} },
    { "SetWindowsHookExA", "user32.dll", NULL, NULL,                   (FARPROC)SetWindowsHookExA_Handler, {0} },
    { "SetWindowsHookExW", "user32.dll", NULL, NULL,                   (FARPROC)SetWindowsHookExW_Handler, {0} },
    { "SetWinEventHook", "user32.dll", NULL, NULL,                     (FARPROC)SetWinEventHook_Handler, {0} },
    { "ShellExecuteA", "shell32.dll", NULL, NULL,                      (FARPROC)ShellExecuteA_Handler, {0} },
    { "ShellExecuteW", "shell32.dll", NULL, NULL,                      (FARPROC)ShellExecuteW_Handler, {0} },
    { "ShellExecuteExW", "shell32.dll", NULL, NULL,                    (FARPROC)ShellExecuteExW_Handler, {0} },
    { "ShellExecuteExA", "shell32.dll", NULL, NULL,                    (FARPROC)ShellExecuteExA_Handler, {0} },
    { "OpenThreadToken", "advapi32.dll", NULL, NULL,                   (FARPROC)OpenThreadToken_Handler, {0} },
    { "NtOpenThreadToken", "ntdll.dll", NULL, NULL,                    (FARPROC)NtOpenThreadToken_Handler, {0} },
    { "NtOpenThreadTokenEx", "ntdll.dll", NULL, NULL,                  (FARPROC)NtOpenThreadTokenEx_Handler, {0} },
    { "OpenProcessToken", "advapi32.dll", NULL, NULL,                  (FARPROC)OpenProcessToken_Handler, {0} },
    { "NtOpenProcessToken", "ntdll.dll", NULL, NULL,                   (FARPROC)NtOpenProcessToken_Handler, {0} },
    { "NtOpenProcessTokenEx", "ntdll.dll", NULL, NULL,                 (FARPROC)NtOpenProcessTokenEx_Handler, {0} },
    { "DuplicateToken", "advapi32.dll", NULL, NULL,                    (FARPROC)DuplicateToken_Handler, {0} },
    { "DuplicateTokenEx", "advapi32.dll", NULL, NULL,                  (FARPROC)DuplicateTokenEx_Handler, {0} },
    { "NtDuplicateToken", "ntdll.dll", NULL, NULL,                     (FARPROC)NtDuplicateToken_Handler, {0} },
    { "DuplicateHandle", "kernel32.dll", NULL, NULL,                   (FARPROC)DuplicateHandle_Handler, {0} },
    { "NtDuplicateObject", "ntdll.dll", NULL, NULL,                    (FARPROC)NtDuplicateObject_Handler, {0} },
    { "CreateToolhelp32Snapshot", "kernel32.dll", NULL, NULL,          (FARPROC)CreateTh32Snapshot_Handler, {0} },
    { "FindWindowA", "user32.dll", NULL, NULL,                         (FARPROC)FindWindowA_Handler, {0} },
    { "FindWindowW", "user32.dll", NULL, NULL,                         (FARPROC)FindWindowW_Handler, {0} },
    { "FindWindowExA", "user32.dll", NULL, NULL,                       (FARPROC)FindWindowExA_Handler, {0} },
    { "FindWindowExW", "user32.dll", NULL, NULL,                       (FARPROC)FindWindowExW_Handler, {0} },
    { "NtUserFindWindowEx", "ntdll.dll", NULL, NULL,                   (FARPROC)NtUserFindWindowEx_Handler, {0} },
    { "AddVectoredExceptionHandler", "kernel32.dll", NULL, NULL,       (FARPROC)AddVEH_Handler, {0} },
    { "RtlAddVectoredExceptionHandler", "ntdll.dll", NULL, NULL,       (FARPROC)RtlAddVEH_Handler, {0} },
    { "NtQuerySystemInformation", "ntdll.dll", NULL, NULL,             (FARPROC)NtQuerySystemInformation_Handler, {0} },
    { "NtQuerySystemInformationEx", "ntdll.dll", NULL, NULL,           (FARPROC)NtQuerySystemInformationEx_Handler, {0} },
    { "NtQueryInformationThread", "ntdll.dll", NULL, NULL,             (FARPROC)NtQueryInformationThread_Handler, {0} },
    { "NtQueryInformationProcess", "ntdll.dll", NULL, NULL,            (FARPROC)NtQueryInformationProcess_Handler, {0} },
    { "CreateFileMappingA", "kernel32.dll", NULL, NULL,                (FARPROC)CreateFileMappingA_Handler, {0} },
    { "CreateFileMappingW", "kernel32.dll", NULL, NULL,                (FARPROC)CreateFileMappingW_Handler, {0} },
    { "CreateFileMapping2", "kernel32.dll", NULL, NULL,                (FARPROC)CreateFileMapping2_Handler, {0} },
    { "CreateFileMappingNumaA", "kernel32.dll", NULL, NULL,            (FARPROC)CreateFileMappingNumaA_Handler, {0} },
    { "CreateFileMappingNumaW", "kernel32.dll", NULL, NULL,            (FARPROC)CreateFileMappingNumaW_Handler, {0} },
    { "NtCreateSection", "ntdll.dll", NULL, NULL,                      (FARPROC)NtCreateSection_Handler, {0} },
    { "NtCreateSectionEx", "ntdll.dll", NULL, NULL,                    (FARPROC)NtCreateSectionEx_Handler, {0} },
    { "ReadProcessMemory", "kernel32.dll", NULL, NULL,                 (FARPROC)ReadProcessMemory_Handler, {0} },
    { "NtReadVirtualMemory", "ntdll.dll", NULL, NULL,                  (FARPROC)NtReadVirtualMemory_Handler, {0} },
    { "NtReadVirtualMemoryEx", "ntdll.dll", NULL, NULL,                (FARPROC)NtReadVirtualMemoryEx_Handler, {0} },
    { "WriteProcessMemory", "kernel32.dll", NULL, NULL,                (FARPROC)WriteProcessMemory_Handler, {0} },
    { "NtWriteVirtualMemory", "ntdll.dll", NULL, NULL,                 (FARPROC)NtWriteVirtualMemory_Handler, {0} },
    { "GetThreadDescription", "kernel32.dll", NULL, NULL,              (FARPROC)GetThreadDescription_Handler, {0} },
    { "SetThreadDescription", "kernel32.dll", NULL, NULL,              (FARPROC)SetThreadDescription_Handler, {0} },
    { "SetThreadExecutionState", "kernel32.dll", NULL, NULL,           (FARPROC)SetThreadExecutionState_Handler, {0} },
    { "NtSetThreadExecutionState", "ntdll.dll", NULL, NULL,            (FARPROC)NtSetThreadExecutionState_Handler, {0} },
    { "Thread32First", "kernel32.dll", NULL, NULL,                     (FARPROC)Thread32First_Handler, {0} },
    { "Thread32Next", "kernel32.dll", NULL, NULL,                      (FARPROC)Thread32Next_Handler, {0} },
    { "Process32First", "kernel32.dll", NULL, NULL,                    (FARPROC)Process32First_Handler, {0} },
    { "Process32Next", "kernel32.dll", NULL, NULL,                     (FARPROC)Process32Next_Handler, {0} },
    { "Process32FirstW", "kernel32.dll", NULL, NULL,                   (FARPROC)Process32FirstW_Handler, {0} },
    { "Process32NextW", "kernel32.dll", NULL, NULL,                    (FARPROC)Process32NextW_Handler, {0} },
    { "Module32First", "kernel32.dll", NULL, NULL,                     (FARPROC)Module32First_Handler, {0} },
    { "Module32Next", "kernel32.dll", NULL, NULL,                      (FARPROC)Module32Next_Handler, {0} },
    { "Module32FirstW", "kernel32.dll", NULL, NULL,                    (FARPROC)Module32FirstW_Handler, {0} },
    { "Module32NextW", "kernel32.dll", NULL, NULL,                     (FARPROC)Module32NextW_Handler, {0} },
    { "IsDebuggerPresent", "kernel32.dll", NULL, NULL,                 (FARPROC)IsDebuggerPresent_Handler, {0} },
};

Module TrackedModules[] = {
    { "kernel32.dll",                         NULL, {0} },
    { "kernelbase.dll",                       NULL, {0} },
    { "ntdll.dll",                            NULL, {0} },
    { "user32.dll",                           NULL, {0} },
    { "shell32.dll",                          NULL, {0} },
    { "advapi32.dll",                           NULL, {0} },
    { "api-ms-win-core-synch-l1-2-0.dll",     NULL, {0} },
};

const size_t HookListSize = sizeof(HookList) / sizeof(HookEntry); 
const size_t NumTrackedModules = sizeof(TrackedModules) / sizeof(Module); 

void InitializeModuleList() {
    for (size_t i = 0; i < NumTrackedModules; i++) {
        TrackedModules[i].base = GetModuleHandle(TrackedModules[i].name);
        unsigned int hashLen = 0;
        HashTextSection(TrackedModules[i].base, TrackedModules[i].textHash, &hashLen);
    }
}

// fills function addresses and takes hash
int InitializeHookList() {
    fprintf(stderr, "start of InitializeHookList, NumTrackedModules: %d\n", NumTrackedModules);
    // pre-fill base addresses of each tracked module onto a list

    for (size_t i = 0; i < HookListSize; i++) {
        // fill moduleBase from previously loaded list of module addresses
        for (size_t j = 0; j < NumTrackedModules; j++) {
            if (strcmp(HookList[i].moduleName, TrackedModules[j].name) == 0) {
                HookList[i].moduleBase = TrackedModules[j].base;
            }
        }
        HookList[i].originalFunc = GetProcAddress(HookList[i].moduleBase, HookList[i].funcName);
        fprintf(stderr, "function %s\n\tmodulebase: %p\n\taddress: %p\n", HookList[i].funcName, HookList[i].moduleBase, HookList[i].originalFunc);
        FillFunctionHash(HookList[i].funcHash, HookList[i].originalFunc, FUNC_HASH_LENGTH);
    }
    return 0;
}

int InitializeIatHookByName(LPVOID moduleBase, LPCSTR funcToHook, FARPROC handler) {
    //* Parse PE header to find Import Address Table and change function address to point to handler
    PIMAGE_DOS_HEADER dosHeaders = (PIMAGE_DOS_HEADER)moduleBase;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((ULONG_PTR)moduleBase + dosHeaders->e_lfanew);
    if (ntHeaders->Signature != PE_SIGNATURE) {
        return -1;
    }

	PIMAGE_IMPORT_DESCRIPTOR importDescriptor = NULL;
	IMAGE_DATA_DIRECTORY importsDirectory = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(importsDirectory.VirtualAddress + (DWORD_PTR)moduleBase);
	LPCSTR libraryName = NULL;
	PIMAGE_IMPORT_BY_NAME functionName = NULL; 
    
    while (importDescriptor->Name != 0) {
        // is it the correct module's IAT?
		libraryName = (LPCSTR)((DWORD_PTR)importDescriptor->Name + (DWORD_PTR)moduleBase);
        if (strcmp(libraryName, "") == 0) {
            break;
        }
        
        PIMAGE_THUNK_DATA originalFirstThunk = NULL, firstThunk = NULL;
        originalFirstThunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)moduleBase + importDescriptor->OriginalFirstThunk);
        firstThunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)moduleBase + importDescriptor->FirstThunk);
        
        while (originalFirstThunk->u1.AddressOfData != 0) {
            //? do you need to check if originalFirstThunk or firstThunk is NULL?
            functionName = (PIMAGE_IMPORT_BY_NAME)((DWORD_PTR)moduleBase + originalFirstThunk->u1.AddressOfData);

            // skip null function entry
            if (firstThunk->u1.Function == 0) {
                originalFirstThunk++;
                firstThunk++;
                continue;
            }
           
            // replace address if its the one we want to hook
            if (strcmp(functionName->Name, funcToHook) == 0) {
                DWORD oldProtect;
                VirtualProtect((LPVOID)(&firstThunk->u1.Function), 8, PAGE_READWRITE, &oldProtect);
                firstThunk->u1.Function = (DWORD_PTR)handler;
                return 0;
            }
            originalFirstThunk++;
            firstThunk++;
        }
        importDescriptor++;
    }
    return 1;
}

//! currently very inefficient. will optimize it later, temporarily doing seperate parsing for each function 
int InitializeIatHooksByHookList() {
    int failed = 0;
    for (size_t i = 0; i < HookListSize; i++) {
        //? the iat is in main module, because youre going through modules imported by main module!
        int result = InitializeIatHookByName((LPVOID)GetModuleHandle(NULL), HookList[i].funcName, HookList[i].handler);
        if (result != 0) {
            // return value 1 is to be expected if the tracked program does not import this function
            fprintf(stderr, "failed to hook %s (return value %d)\n", HookList[i].funcName, result);
            failed++;
        }
    }
    return failed;
}

//TODO: uninstall iat hooks