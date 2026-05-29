#ifndef UTILS_H
#define UTILS_H

#define STATUS_ACCESS_DENIED 0xC0000022
#define PE_SIGNATURE 0x4550
#define SHA256_DIGEST_LENGTH 32
#define MAX_API_ARGS 10 
#define HEARTBEAT_INTERVAL 20000
#define INTEGRITY_CHECK_INTERVAL 30000
#define COUNTER_LOOP_SLEEP_INTERVAL 10000
#define HOOK_CHECK_INTERVAL      60000
#define IAT_CHECK_INTERVAL      60000
#define FUNC_HASH_LENGTH 256 // how many bytes to hash from start of function
#define EVP_MAX_MD_SIZE 64

#define HEARTBEAT_PIPE_NAME "\\\\.\\pipe\\vgrd_hb"
#define TELEMETRY_PIPE_NAME "\\\\.\\pipe\\vgrd_tm"
#define COMMANDS_PIPE_NAME "\\\\.\\pipe\\vgrd_cmd"

#include <openssl/evp.h>
#include <windows.h>
#include <winternl.h>
#include <ntdef.h>
#include <winbase.h>

extern HANDLE hHeartbeat;
extern HANDLE hTelemetry;
extern HANDLE hCommands;

PIMAGE_IMPORT_DESCRIPTOR GetIatImportDescriptor(LPVOID);

//int* CheckHookIntegrity(int*);
BOOL CheckTextSectionIntegrity(unsigned char*, HMODULE);
void HashTextSection(HMODULE, unsigned char*, unsigned int*);
//void PerformIntegrityChecks(HMODULE, HMODULE, HMODULE);
void CheckIatIntegrity(LPVOID);

HANDLE InitializeComms();           // ipc.c
void WaiterThread(); // ipc.c

// utils.cpp
#ifdef __cplusplus
extern "C" {
#endif
void InitializeHookMap();
HookEntry* FindHookEntry(LPCSTR);
#ifdef __cplusplus
}

#endif


#endif
