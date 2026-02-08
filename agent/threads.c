#include <windows.h>
#include <winternl.h>
#include <ntstatus.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <stdio.h>
//#include "utils.h"

typedef NTSTATUS (NTAPI *QUERYTHREADINFO)(HANDLE, THREADINFOCLASS, PVOID, ULONG, PULONG);

// This function will enumerate all accessible threads of a process (or 0 for all),
// query its start routine address and then check if it points to a module's text section.
// Additionally you may check if the start routine address points to a LoadLibrary* function.
// Caller is responsible for freeing the resulting array of length oddCount.
THREAD_ENTRY* ScanProcessThreads(DWORD pid, size_t* oddCount) {
    (*oddCount) = 0;
    THREAD_ENTRY* oddThreads = NULL;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        printf("Failed to get snapshot of threads, error: %d\n", GetLastError());
        return NULL;
    }

    THREADENTRY32 te;
    te.dwSize = sizeof(te);
    if (!Thread32First(snapshot, &te)) {
        printf("Failed to enumerate first thread, error: %d", GetLastError());
        CloseHandle(snapshot);
        return NULL;
    }
    // NtQueryInformationThread is not in headers so I manually declare and use it 
    HMODULE ntBase = GetModuleHandle("ntdll.dll");
    if (ntBase == INVALID_HANDLE_VALUE) {
        printf("Failed to get handle to ntdll.dll, error: %d\n", GetLastError());
        CloseHandle(snapshot);
        return NULL;
    }
    FARPROC NtQueryInformationThread = GetProcAddress(ntBase, "NtQueryInformationThread");
    if (NtQueryInformationThread == NULL) {
        printf("Failed to get address of NtQueryInformationThread, error: %d\n", GetLastError());
        CloseHandle(snapshot);
        return NULL;
    }
    
    do {
        if (te.dwSize >= FIELD_OFFSET(THREADENTRY32, th32OwnerProcessID) + sizeof(te.th32OwnerProcessID)
        && (pid == te.th32OwnerProcessID || pid == 0)) {
            HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, te.th32ThreadID);
            if (hThread == INVALID_HANDLE_VALUE) {
                printf("Failed to open handle to thread %d, error: %d\n", te.th32ThreadID, GetLastError());
                continue;
            }
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_READ, FALSE, te.th32OwnerProcessID);
            if (hProcess == NULL) {
                printf("[!] Failed to open process, error: %d\n", GetLastError());
                continue;
            }

            THREAD_ENTRY entry = {0};
            if (AnalyzeThread(hProcess, hThread, NtQueryInformationThread, &entry) > 0) {
                AddThreadEntry(oddThreads, oddCount, te.th32ThreadID, te.th32OwnerProcessID,
                    entry.rip, entry.startAddress, entry.reason);
            }
            CloseHandle(hThread);
            CloseHandle(hProcess);
        }
    } while (Thread32Next(snapshot, &te));
    CloseHandle(snapshot);
    return oddThreads;
}

// Return address is a bitmask, with flags explaining what makes the thread suspicious.
// If the thread is deemed normal, return value is 0.

// Analyze a given thread, to see if it seems malicious.
// Return value is negative if the call failed, and returns the complement of error code.
// If the function call was successful, return value is bitmask explaining why it's suspicious.
// If the thread was deemed benign, the return value is 0. 
DWORD AnalyzeThread(HANDLE hProcess, HANDLE hThread, FARPROC NtQueryInformationThread, THREAD_ENTRY* output) {
    LPVOID startAddress;
    if (NtQueryInformationThread == NULL) return -ERROR_INVALID_PARAMETER;
    NTSTATUS status = ((QUERYTHREADINFO)NtQueryInformationThread)(hThread,
    ThreadQuerySetWin32StartAddress, &startAddress, sizeof(LPVOID), NULL);
    if (status != STATUS_SUCCESS) {
        printf("Failed to query thread info, error: %d\n", GetLastError());
        return -GetLastError();
    }
    CONTEXT ctx = {0};
    BOOL ok = GetThreadContext(hThread, &ctx);
    if (!ok) {
        printf("Failed to query thread context, error: %d\n", GetLastError());
        return -GetLastError();
    }
    output->rip = ctx.Rip;
    output->startAddress = startAddress;

    DWORD reason = 0;
    if (!DoesAddressPointToModule(hProcess, startAddress)) {
        reason |= THREAD_ENTRY_OUTSIDE_MODULE;
    }
    if (!DoesAddressPointToModule(hProcess, ctx.Rip)) {
        reason |= THREAD_IP_OUTSIDE_MODULE;
    }
    if (GetAddressMemoryType(hProcess, startAddress) != MEM_IMAGE) {
        reason |= THREAD_ENTRY_UNBACKED_MEM;
    }
    if (GetAddressMemoryType(hProcess, ctx.Rip) != MEM_IMAGE) {
        reason |= THREAD_IP_UNBACKED_MEM;
    }
    output->reason = reason;
    return reason;
}

MEMORY_REGION* GetRemoteProcessModuleTexts(HANDLE hProcess, size_t* modCount) {
    MEMORY_REGION* moduleTexts = NULL;
    DWORD numModules;
    DWORD bytesNeeded;
    (*modCount) = 0;

    // Get amount of modules loaded by the process
    if (EnumProcessModules(hProcess, NULL, 0, &bytesNeeded)) {
        numModules = bytesNeeded / sizeof(HMODULE);
    } else {
        printf("[!] Failed to get module count, error: %d\n", GetLastError());
        return NULL;
    }

    HMODULE* hModules = (HMODULE*)malloc(bytesNeeded);
    if (hModules == NULL) {
        printf("[!] Failed to allocate array of module handles, size: %d\n", bytesNeeded);
        return NULL;
    }
    // get the handles of all loaded modules
    if (!EnumProcessModules(hProcess, hModules, bytesNeeded, &bytesNeeded)) {
        printf("[!] Failed to enumerate remote process modules, error: %d\n", GetLastError());
        free(hModules);
        return NULL;
    }

    for (DWORD i = 0; i < numModules; i++) {
        char baseName[MAX_PATH];
        if (GetModuleBaseNameA(hProcess, hModules[i], baseName, MAX_PATH) == 0) {
            printf("[!] Failed to get module name, error: %d\n", GetLastError());
            continue;
        }
        //printf("[i] Found %s\n", baseName);

        MODULEINFO modInfo;
        if (!GetModuleInformation(hProcess, hModules[i], &modInfo, sizeof(modInfo))) {
            printf("[!] Failed to get module information, error: %d\n", GetLastError());
            continue;
        }
        // find section headers to get addresses
        LPVOID baseAddress = modInfo.lpBaseOfDll;
        if (baseAddress == NULL) {
            printf("NULL address\n");
            continue;
        }
        IMAGE_DOS_HEADER dosHeader;
        if (!ReadProcessMemory(hProcess, baseAddress, &dosHeader, sizeof(dosHeader), NULL)) {
            printf("[!] Failed to read DOS header of remote process, error: %d\n", GetLastError());
            continue;
        }

        LPVOID ntHeaderAddress = baseAddress + dosHeader.e_lfanew;
        IMAGE_NT_HEADERS ntHeader;
        if (!ReadProcessMemory(hProcess, ntHeaderAddress, &ntHeader, sizeof(ntHeader), NULL)) {
            printf("[!] Failed to read NT header of remote process, error: %d\n", GetLastError());
            continue;
        }

        LPVOID sectionHeadersAddress = ntHeaderAddress + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + ntHeader.FileHeader.SizeOfOptionalHeader;
        DWORD numRegions = ntHeader.FileHeader.NumberOfSections;

        PIMAGE_SECTION_HEADER sectionHeaders = (PIMAGE_SECTION_HEADER)malloc(sizeof(IMAGE_SECTION_HEADER) * numRegions);
        if (sectionHeaders == NULL) {
            printf("[!] Failed to allocate memory for section headers\n");
            continue;
        }

        if (!ReadProcessMemory(hProcess, sectionHeadersAddress, sectionHeaders, sizeof(IMAGE_SECTION_HEADER) * numRegions, NULL)) {
            printf("[!] Failed to read sections headers of remote process, error: %d\n", GetLastError());
            continue;
        }

        //printf("[debug] starting section loop...\n");
        // loop through sections
        for (DWORD j = 0; j < numRegions; j++) {
            if (stricmp((char*)sectionHeaders[j].Name, ".text") != 0) {
                continue;
            }
            //printf("[debug] found .text\n");
            moduleTexts = (MEMORY_REGION*)realloc(moduleTexts, ((*modCount) + 1) * sizeof(MEMORY_REGION));
            if (moduleTexts == NULL) {
                printf("\n[!] Failed to realloc (%dB)\n", ((*modCount)+1)*sizeof(MEMORY_REGION));
                return FALSE;
            }
            moduleTexts[(*modCount)].address = (LPVOID)((DWORD_PTR)baseAddress + sectionHeaders[j].VirtualAddress);
            moduleTexts[(*modCount)].size = sectionHeaders[j].Misc.VirtualSize;
            (*modCount)++;
            break;
        }
        free(sectionHeaders);
    }
    free(hModules);
    return moduleTexts;
}

// This will check if an address points to 
BOOL DoesAddressPointToModule(HANDLE hProcess, LPVOID address) {
    MEMORY_REGION* moduleTexts = NULL;
    size_t modCount;

    moduleTexts = GetRemoteProcessModuleTexts(hProcess, &modCount);
    if (moduleTexts == NULL) {
        printf("\n[!] Failed to get list of module texts for process.\n");
        return FALSE;
    }

    // check if address is within a text section
    for (int i = 0; i < modCount; i++) {
        if (address >= moduleTexts[i].address && address < moduleTexts[i].address + moduleTexts[i].size) {
            free(moduleTexts);
            return TRUE;
        }
    }
    free(moduleTexts);
    return FALSE;
}

void AddThreadEntry(THREAD_ENTRY* threads, size_t* count, DWORD tid, DWORD pid, LPVOID rip, LPVOID address, DWORD reason) {
    THREAD_ENTRY* tmp = NULL;
    tmp = (THREAD_ENTRY*)realloc(threads, ((*count)+1)*sizeof(THREAD_ENTRY));
    if (tmp == NULL) {
        printf("Failed to realloc thread list to size of %dB\n", ((*count)+1)*sizeof(THREAD_ENTRY));
        return;
    }
    threads = tmp;
    threads[(*count)].tid = tid;
    threads[(*count)].pid = pid;
    threads[(*count)].rip = rip;
    threads[(*count)].startAddress = address;
    threads[(*count)].reason = reason;
    (*count)++;
}