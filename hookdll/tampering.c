#include <windows.h>
#include <openssl/evp.h>
#include <stdio.h>
#include "hook.h"

//?=================================================================================+
//?   This file implements functionality to detect tampering in the host process.   |
//?   These get called in the counter loop, running checks periodically (main.c)    |
//?=================================================================================+


// Send a heartbeat signal to the provided pipe.
void heartbeat(HANDLE hPipe) {
    HEARTBEAT heartbeat;
    strcpy(heartbeat.Heartbeat, "heartbeat");
    heartbeat.pid = GetCurrentProcessId();
    DWORD dwBytesWritten;
    if (!WriteFile(hPipe, &heartbeat, sizeof(heartbeat), &dwBytesWritten, NULL)) {
        printf("\n[!] Failed to send heartbeat, error code: 0x%X\n", GetLastError());
    } else {
        //SetEvent(hHbEvent);
        printf("[+] Sent heartbeat\n");
    }
}

// Get the SHA256 hash of a provided module's .text section.
void HashTextSection(HMODULE moduleBase, unsigned char* output, unsigned int* hashLen) {
    fprintf(stderr, "modulebase: 0x%p\n", moduleBase);
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)moduleBase;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        printf("\n[!] Invalid DOS Header!\n");
        return;
    }
    
    // get PE header offset
    DWORD peHeader = dosHeader->e_lfanew;

    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((PBYTE)moduleBase + peHeader);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        printf("\n[!] Invalid NT Header!\n");
        return;
    }

    // the section table comes after optional header
    PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);

    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        if (strcmp((char*)sectionHeader[i].Name, ".text") == 0) {
            fprintf(stderr, "found .text section\n");
            ULONG_PTR textAddress = (ULONG_PTR)moduleBase + sectionHeader[i].VirtualAddress;
            DWORD textSize = sectionHeader[i].SizeOfRawData;
            fprintf(stderr, "\taddress: 0x%p\n\tsize: %d\n", textAddress, textSize);
            if (textSize > MAX_TEXT_SECTION_SIZE) textSize = MAX_TEXT_SECTION_SIZE;

            //printf("[+] Found .text section!\n\t\\==={ Address: 0x%X\n\t \\=={ Size: %d\n\t  \\={ RVA: 0x%X\n", textAddress, textSize, sectionHeader[i].VirtualAddress);
            EVP_MD_CTX *ctx = EVP_MD_CTX_new();
            if (!ctx) {
                fprintf(stderr, "EVP_MD_CTX_new() failed\n");
                return;
            }
//            unsigned char hash[EVP_MAX_MD_SIZE];
            *hashLen = 0;

            //fprintf(stderr, "before EVP_DigestInit_ex()\n");
            // Initialize the context for SHA256
            if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
                printf("[.text] Error initializing digest\n");
                EVP_MD_CTX_free(ctx);
                return;
            }

            //fprintf(stderr, "before EVP_DigestUpdate()\n");
            // Update the hash with the .text section data
            if (EVP_DigestUpdate(ctx, (LPCVOID)textAddress, textSize) != 1) {
                printf("[.text] Error updating digest\n");
                EVP_MD_CTX_free(ctx);
                return;
            }

            //fprintf(stderr, "before EVP_DigestFinal_ex()\n");
            // Finalize the hash and get the result
            if (EVP_DigestFinal_ex(ctx, output, hashLen) != 1) {
                printf("Error finalizing digest\n");
                EVP_MD_CTX_free(ctx);
                return;
            }

            EVP_MD_CTX_free(ctx);  // Free the context

            // printing for debug testing version
            printf("[i] Hash of .text section: ");
            for (int i = 0; i < *hashLen; i++) {
                printf("%02X ", output[i]);
            }
            printf("\n");
            return;
        }
    }
    printf("\n[!] Couldn't find .text section!\n");
}

// Check the integrity of a provided module's .text section.
// This wrapper function compares originally saved hash to fresh hash.
BOOL CheckTextSectionIntegrity(unsigned char* originalHash, HMODULE moduleBase) {
    unsigned int hashLen;
    unsigned char currentHash[EVP_MAX_MD_SIZE];
    HashTextSection(moduleBase, currentHash, &hashLen);
    return memcmp(originalHash, currentHash, hashLen) == 0; 
}

/*
void PerformIntegrityChecks(HMODULE ownBase, HMODULE ntBase, HMODULE k32Base) {
    BOOL ownMatch = CheckTextSectionIntegrity(OwnTextHash, ownBase);
    BOOL ntMatch = CheckTextSectionIntegrity(originalNtTextHash, ntBase);
    BOOL k32Match = CheckTextSectionIntegrity(originalKernel32TextHash, k32Base);
    
    //* send scan results to agent
    TELEMETRY ownCheck;
    TELEMETRY ntCheck;
    TELEMETRY k32Check;
    
    GetTextTelemetryPacket(&ownCheck, DLL_NAME, ownMatch);
    GetTextTelemetryPacket(&ntCheck, "ntdll.dll", ntMatch);
    GetTextTelemetryPacket(&k32Check, "kernel32.dll", k32Match);

    DWORD dwBytesWritten;
    WriteFile(hTelemetry, &ownCheck, sizeof(ownCheck), &dwBytesWritten, NULL);
    WriteFile(hTelemetry, &ntCheck, sizeof(ntCheck), &dwBytesWritten, NULL);
    WriteFile(hTelemetry, &k32Check, sizeof(k32Check), &dwBytesWritten, NULL);
    //* performer further checks to find out if a specific hook was tampered with
    //TODO: hash check all functions in specified module?
    if (!ntMatch || !k32Match) {
        int mismatchCount = 0;
        int* mismatches = CheckHookIntegrity(&mismatchCount); //? Seperate thread?
        
        //* send hook integrity results to agent
        TELEMETRY hookIntegrity;
        GetHookIntegrityTelemetryPacket(&hookIntegrity, mismatches, mismatchCount);
        WriteFile(hTelemetry, &hookIntegrity, sizeof(hookIntegrity), &dwBytesWritten, NULL);
        free(mismatches);
    }
}*/


// Check the memory integrity of every function in the HookList.
// This works by iterating each function and comparing saved hash to fresh hash.
// Returns an ansi string array of the found mismatches, which must be freed by caller.
char** CheckHookHashIntegrity(size_t* mismatchCount) {
    char** mismatches = NULL; // pointers to names
    size_t count = 0;
    size_t capacity = 0;

    for (size_t i = 0; i < HookListSize; i++) {
        unsigned char funcHash[EVP_MAX_MD_SIZE];
        if (HookList[i].originalFunc == NULL) {
            continue;
        }
        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        if (!ctx) {
            continue;
        }
        if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
            EVP_MD_CTX_free(ctx);
            continue;
        }
        if (EVP_DigestUpdate(ctx, (LPCVOID)HookList[i].originalFunc, FUNC_HASH_LENGTH) != 1) {
            EVP_MD_CTX_free(ctx);
            continue;
        }
        unsigned int hashLen;
        if (EVP_DigestFinal_ex(ctx, funcHash, &hashLen) != 1) {
            EVP_MD_CTX_free(ctx);
            continue;
        }
        if (memcmp(HookList[i].funcHash, funcHash, hashLen) != 0) {
            if (count >= capacity) {
                // start with 4, after that when you need more space, double it
                size_t newCapacity = (capacity == 0) ? 4 : capacity * 2;
                char** new_arr = realloc(mismatches, newCapacity * sizeof(char*));
                if (!new_arr) {
                    fprintf(stderr, "Memory allocation failed\n");
                    *mismatchCount = count;
                    return mismatches;
                }
                mismatches = new_arr;
                capacity = newCapacity;
            }
            mismatches[count] = HookList[i].funcName;
            count++;
        }
    }
    *mismatchCount = count;
    return mismatches;
}


// This function will check integrity of IAT entries, and in case of mismatches it will send
// the results to the agent process. If the IAT entry is a hook, the address to be compared against
// is the hook handler address. Otherwise the IAT address is compared against the EAT address of said function. 
IAT_MISMATCH* CheckIatIntegrity(LPVOID moduleBase, size_t* mismatchCount) {
    fprintf(stderr, "[i] Checking IAT integrity...\n");

    // parse PE header to find the import descriptor, in order to parse IAT
    // this function handles most of the pe parsing boilerplate code here.
    PIMAGE_IMPORT_DESCRIPTOR importDescriptor = GetIatImportDescriptor(moduleBase);
    if (importDescriptor == NULL) {
        //TODO: log fail
        return NULL;
    }

    size_t count = 0;
    size_t arrayCapacity = 0;
    IAT_MISMATCH* mismatches = NULL;
    // parse each iat entry
    while (importDescriptor->Name != 0) {
		LPCSTR libraryName = (LPCSTR)((DWORD_PTR)importDescriptor->Name + (DWORD_PTR)moduleBase);
        if (strcmp(libraryName, "") == 0) {
            break;
        }
        
        PIMAGE_THUNK_DATA originalFirstThunk = NULL, firstThunk = NULL;
        originalFirstThunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)moduleBase + importDescriptor->OriginalFirstThunk);
        firstThunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)moduleBase + importDescriptor->FirstThunk);
        
        while (originalFirstThunk->u1.AddressOfData != 0) {
            //? do you need to check if originalFirstThunk or firstThunk is NULL?
            PIMAGE_IMPORT_BY_NAME functionName = (PIMAGE_IMPORT_BY_NAME)((DWORD_PTR)moduleBase + originalFirstThunk->u1.AddressOfData);

            // skip null function entry
            if (firstThunk->u1.Function == 0) {
                originalFirstThunk++;
                firstThunk++;
                continue;
            }
            // skip ordinal imports, and maybe also proxied imports(?) that was the idea
            // kind of a weird check but i was getting false positives on api-ms-... functions,
            // which all had a weird low address, so this fixed it. wasnt able to find another solution.
            // you could maybe check for forward exports checking if IMAGE_IMPORT_BY_NAME is NULL or
            // originalFirstThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG 
            // "Check if export address points inside export directory (a forwarder string)"
            if ((SIZE_T)functionName & 0xff00000000000000) {
                originalFirstThunk++;
                firstThunk++;
                continue;
            }
            /*if (IMAGE_SNAP_BY_ORDINAL(originalFirstThunk->u1.Ordinal)) {

            }*/

           
            // check if its a function that weve hooked or not
            HookEntry* hook = FindHookEntry(functionName->Name);
            if (hook == NULL) { // not found
                //* check IAT address against EAT
                HMODULE base      = GetModuleHandle(libraryName);
                LPVOID eatAddress = GetProcAddress(base, functionName->Name);
                if ((LPVOID)firstThunk->u1.Function != eatAddress) {
                    //? EAT - IAT mismatch! Iat hook detected
                    // make sure mismatches array is large enough
                    if (count >= arrayCapacity) {
                        // start with 4, double as needed
                        size_t newCapacity = arrayCapacity == 0 ? 4 : arrayCapacity * 2;
                        IAT_MISMATCH* newArray = realloc(mismatches, newCapacity * sizeof(IAT_MISMATCH));
                        if (newArray == NULL) {
                            //TODO: log error
                            continue;
                        }
                        mismatches = newArray;
                        arrayCapacity = newCapacity;
                    }

                    //* add entry
                    mismatches[count].address = (LPVOID)firstThunk->u1.Function;
                    strncpy(mismatches[count].funcName, functionName->Name, sizeof(mismatches[count].funcName)-1);
                    mismatches[count].funcName[sizeof(mismatches[count].funcName)-1] = '\0';
                    count++;
                }
            } else if ((LPVOID)firstThunk->u1.Function != hook->handler) {
                //? This IAT entry is one of our hooks, and it is a mismatch
                
                // make sure mismatches array is large enough
                if (count >= arrayCapacity) {
                    // start with 4, double as needed
                    size_t newCapacity = arrayCapacity == 0 ? 4 : arrayCapacity * 2;
                    IAT_MISMATCH* newArray = realloc(mismatches, newCapacity * sizeof(IAT_MISMATCH));
                    if (newArray == NULL) {
                        //TODO: log error
                        continue;
                    }
                    mismatches = newArray;
                    arrayCapacity = newCapacity;
                }
                
                //* add entry
                mismatches[count].address = (LPVOID)firstThunk->u1.Function;
                strncpy(mismatches[count].funcName, functionName->Name, sizeof(mismatches[count].funcName)-1);
                mismatches[count].funcName[sizeof(mismatches[count].funcName)-1] = '\0';
                count++;
            }

            originalFirstThunk++;
            firstThunk++;
        }
        importDescriptor++;
    }
    *mismatchCount = count;
    return mismatches;
}
