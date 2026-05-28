#include <windows.h>
#include <stdio.h>
#include "hook.h"

HANDLE hTelemetry = NULL;
HANDLE hHeartbeat = NULL;
HANDLE hCommands = NULL;

// This routine handles sending heartbeat, checking text section integrities and checking IAT integrity
int CounterLoop() {
    //fprintf(stderr, "inside counterloop\n");
    DWORD lastHeartbeat = 0;
    DWORD lastIntegrityCheck = 0;
    DWORD lastHookCheck = 0;
    DWORD lastFuncCheck = 0;

    while(1) {
        DWORD now = GetTickCount(); //milliseconds
        
        if (now - lastHeartbeat >= HEARTBEAT_INTERVAL) {
            heartbeat(hHeartbeat);
        }

        if (now - lastIntegrityCheck >= INTEGRITY_CHECK_INTERVAL) {
            //fprintf(stderr, "inside integrity check\n");
            for (size_t i = 0; i < NumTrackedModules; i++) {
                BOOL match = CheckTextSectionIntegrity(TrackedModules[i].textHash, (HMODULE)TrackedModules[i].base);
                //fprintf(stderr, "after CheckTextSectionIntegrity\n");

                if (!match) continue;
                //* create and send telemetry packet
                size_t paramSize;
                BYTE* moduleParam = BuildParameter(&paramSize, PARAMETER_ANSISTRING, "Module", TrackedModules[i].name);
                TELEMETRY_HEADER header = GetTelemetryHeader(TM_TYPE_TEXT_INTEGRITY);

                // construct packet
                size_t packetSize = paramSize + sizeof(header);
                BYTE* packet = (BYTE*)malloc(packetSize);

                memcpy(packet, &header, sizeof(header));
                memcpy(packet + sizeof(header), moduleParam, paramSize);
                free(moduleParam);

                EnqueuePacket(g_StandardQueue, packet, packetSize);
            }            
            //TODO: hash check all functions in specified module
        }

        if (now - lastFuncCheck >= FUNC_CHECK_INTERVAL) {
            size_t mismatchCount;
            char** mismatches = CheckHookHashIntegrity(&mismatchCount);
            if (mismatchCount > 0) {
                // create parameter
                size_t paramSize;
                BYTE* param = BuildArrayParameter(&paramSize, PARAMETER_ASTR_ARRAY, "Mismatches", mismatches, mismatchCount);
                TELEMETRY_HEADER header = GetTelemetryHeader(TM_TYPE_FUNC_INTEGRITY, paramSize);
            
                // construct packet
                size_t packetSize = paramSize + sizeof(header);
                BYTE* packet = (BYTE*)malloc(packetSize);
                memcpy(packet, &header, sizeof(header));
                memcpy(packet + sizeof(header), param, paramSize);

                EnqueuePacket(g_StandardQueue, packet, packetSize);
                free(mismatches);
                free(param);
            }
        }

        if (now - lastHookCheck >= IAT_CHECK_INTERVAL) {
            // check main modules IAT
            fprintf(stderr, "creating IAT check thread\n");
            HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)CheckIatIntegrity, GetModuleHandle(NULL), 0, NULL);
            if (hThread == NULL) {
                fprintf(stderr, "failed to create thread: %d\n", GetLastError());
            }
        }
        Sleep(COUNTER_LOOP_SLEEP_INTERVAL);
    }
}

BOOL WINAPI DllMain(HINSTANCE hInst, DWORD fdwReason, LPVOID lpReserved) {
    switch(fdwReason) {
    case DLL_PROCESS_ATTACH:
        //* Setup comms with agent
        HANDLE hCmdWaiter = InitializeComms();
        if (hTelemetry == NULL || hHeartbeat == NULL) {
            fprintf(stderr, "InitializeComms failed\n");
            return FALSE;
        }
        
        //* setup hooks
        InitializeModuleList();
        fprintf(stderr, "initialize module list done\n");
        int r = InitializeHookList();
        fprintf(stderr, "r1 = %d\n", r);

        // put the actual iat hooking in place
        r = InitializeIatHooksByHookList();
        fprintf(stderr, "r2 = %d\n", r);


        HANDLE hLoop = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)CounterLoop, NULL, 0, NULL);

        //TODO: one thread for listening to commands
        break;
    case DLL_PROCESS_DETACH:
        //TODO: remove IAT hooks
        break;
    }
}

