#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <evntrace.h>
#include <evntcons.h>
#include <tdh.h>
#include <winnt.h>
#include "etw.h"

//?===============================================================================+
//?  This file implements functionality for consuming ETW events in real-time.    |
//?===============================================================================+

// Microsoft-Windows-Kernel-File {EDD08927-9CC4-4E65-B970-C2560FB5C289}
GUID FileProviderGuid = { 0xEDD08927, 0x9CC4, 0x4E65, { 0xB9, 0x70, 0xC2, 0x56, 0x0F, 0xB5, 0xC2, 0x89 } };

// Microsoft-Windows-Kernel-Registry {70EB4F03-C1DE-4F73-A051-33D13D5413BD}
GUID RegistryProviderGuid = { 0x70EB4F03, 0xC1DE, 0x4F73, { 0xA0, 0x51, 0x33, 0xD1, 0x3D, 0x54, 0x13, 0xBD } };

// Microsoft-Windows-Kernel-Process {22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}
GUID ProcessProviderGuid = {0x22FB2CD6, 0x0E7B, 0x422B, { 0xA0, 0xC7, 0x2F, 0xAD, 0x1F, 0xD0, 0xE7, 0x16 }};

// Microsoft-Windows-Threat-Intelligence {F4E1897C-BB5D-5668-F1D8-040F4D8DD344}
GUID ThreatIntelGuid = {0xF4E1897C, 0xBB5D, 0x5668, { 0xF1, 0xD8, 0x04, 0x0F, 0x4D, 0x8D, 0xD3, 0x44 }}; 

// Microsoft-Windows-Kernel-Network {7DD42A49-5329-4832-8DFD-43D979153A88}
GUID NetworkProviderGuid = {0x7DD42A49, 0x5329, 0x4832, { 0x8D, 0xFD, 0x43, 0xD9, 0x79, 0x15, 0x3A, 0x88 }};


// This function is called when a new event is received.
VOID WINAPI EventCallback(PEVENT_RECORD event) {
    if (!trackAny && !IsTracked(event->EventHeader.ProcessId)) {
        return;
    }

    size_t packetSize;
    BYTE* packet = CreateEtwEventPacket(event, &packetSize);
    if (DEBUG_BUILD) PrintEventBasic(event);

    BOOL isCritical = IsCriticalEvent(event);
    TELEMETRY_QUEUE* queue = NULL;
    if (isCritical) queue = &g_CriticalQueue; else queue = &g_StandardQueue;
    ERROR_CODE result = EnqueuePacket(queue, packet, packetSize); 
    if (result != SUCCESS) {
        LogError("Failed to enqueue packet", result);
        if (isCritical) SendPacketDirectly(hEtw, packet, packetSize);
    }
}

// Parses any ETW event and creates a (v4) telemetry packet based on it.
// Relies on GetInternalProviderId(...) to translate the provider GUID.
BYTE* CreateEtwEventPacket(PEVENT_RECORD event, size_t* outSize) {
    // Start by parsing attached data and creating parameters from it,
    // because the total parameter size is needed to create telemetry header
    size_t totalParamSize = 0;
    BYTE* paramsBuf = NULL;
    if (event->UserDataLength > 0 && event->EventHeader.Flags != EVENT_HEADER_FLAG_STRING_ONLY) {
        PTRACE_EVENT_INFO info = NULL;
        ULONG infoSize = 0;
        //TODO: these properties could be cached to avoid the tdh calls below
        TdhGetEventInformation(event, 0, NULL, info, &infoSize);
        info = (PTRACE_EVENT_INFO)malloc(infoSize);
        DWORD r = TdhGetEventInformation(event, 0, NULL, info, &infoSize);
        if (r != ERROR_SUCCESS) {
            // Most events are useless without additional info,
            // for example a file event serves no purpose without path, etc.
            printf("TdhGetEventInformation failed. r=%d, error: %d\n", r, GetLastError());
            free(info);
            return NULL;
        }
        // initial guess for params buffer size
        size_t paramsBufCapacity = info->TopLevelPropertyCount * 64;
        paramsBuf = (BYTE*)malloc(paramsBufCapacity);
        //* Iterate event properties and create parameters
        for (ULONG i = 0; i < info->TopLevelPropertyCount; i++) {
            size_t paramSize;
            BYTE* param = BuildEventParameter(event, i, info, &paramSize);
            if (param == NULL) continue;
        
            // grow buffer if needed
            if (totalParamSize + paramSize > paramsBufCapacity) {
                paramsBufCapacity = (totalParamSize + paramSize) * 2;
                BYTE* buf = (BYTE*)realloc(paramsBuf, paramsBufCapacity);
                if (buf == NULL) {
                    free(param);
                    //TODO: log error
                    char msg[100];
                    sprintf(msg, "Failed to realloc params buffer on event %d (size %dB)\n",
                        event->EventHeader.EventDescriptor.Id, paramsBufCapacity);
                    LogError(msg, ERROR_REALLOC);
                    break;
                }
                paramsBuf = buf;
            }
            // add param to params buffer
            memcpy(paramsBuf + totalParamSize, param, paramSize);
            totalParamSize += paramSize;
            free(param);
        }
        free(info);
    }
    //* Create telemetry header for packet    
    FILETIME ft;
    ft.dwLowDateTime = event->EventHeader.TimeStamp.LowPart;
    ft.dwHighDateTime = event->EventHeader.TimeStamp.HighPart;
    time_t stamp = FiletimeToUnixMillis(ft);
    uint8_t source = GetInternalProviderId(event);
    TELEMETRY_HEADER header = GetTelemetryHeader(source, totalParamSize, totalParamSize, stamp);
    header.eventId = event->EventHeader.EventDescriptor.Id;

    //* Construct full telemetry packet
    size_t packetSize = sizeof(header) + totalParamSize;
    BYTE* packet = (BYTE*)malloc(packetSize);

    memcpy(packet, &header, sizeof(header));
    if (totalParamSize > 0) memcpy(packet + sizeof(header), paramsBuf, totalParamSize);
    free(paramsBuf);

    *outSize = packetSize;
    return packet;
}

// Parse an ETW event's parameter (a single one) and build a parameter buffer based on it.
BYTE* BuildEventParameter(PEVENT_RECORD event, ULONG index, PTRACE_EVENT_INFO info, size_t* outSize) {
    EVENT_PROPERTY_INFO propInfo = info->EventPropertyInfoArray[index];

    PROPERTY_DATA_DESCRIPTOR propDesc;
    RtlZeroMemory(&propDesc, sizeof(propDesc));
    propDesc.PropertyName = (ULONGLONG)((PBYTE)info + propInfo.NameOffset);
    propDesc.ArrayIndex = ULONG_MAX;


    // First, get the size of the property
    ULONG propertySize = 0;
    DWORD status = TdhGetPropertySize(event, 0, NULL, 1, &propDesc, &propertySize);
    if (status != ERROR_SUCCESS) {
        printf("Failed to get size of property %lu\n", index);
        return FALSE;
    }

    // Allocate buffer for the property data, which will then get parsed
    BYTE* buffer = (BYTE*)malloc(propertySize);
    if (!buffer) return FALSE;
  
    // Now actually get the property value
    status = TdhGetProperty(event, 0, NULL, 1, &propDesc, propertySize, buffer);
    if (status != ERROR_SUCCESS) {
        printf("Failed to get property %lu\n", index);
        free(buffer);
        return FALSE;
    }
	
	BYTE* parameter = NULL;
	char* name = WideToAnsi((WCHAR*)propDesc.PropertyName);

	// Construct parameter from the property value
    switch (propInfo.nonStructType.InType) {
		// this one is actually a regular utf16 string,
		// not a UNICODE_STRING... microsoft devs are just pricks
		case TDH_INTYPE_UNICODESTRING: {
			char* ansiValue = WideToAnsi((WCHAR*)buffer);
			if (ansiValue == NULL) {
				free(name);
				free(buffer);
				return FALSE;
			} 
			parameter = BuildParameter(outSize, PARAMETER_ANSISTRING, name, ansiValue);
			break;
        }
		case TDH_INTYPE_ANSISTRING: 
			parameter = BuildParameter(outSize, PARAMETER_ANSISTRING, name, (char*)buffer);
			break;
			
		case TDH_INTYPE_POINTER:
			parameter = BuildParameter(outSize, PARAMETER_POINTER, name, *(void**)buffer);
			break;

		case TDH_INTYPE_UINT32: 
			parameter = BuildParameter(outSize, PARAMETER_UINT32, name, *(DWORD*)buffer);
			break;

		 //case TDH_INTYPE_UINT16: 

		case TDH_INTYPE_BOOLEAN: 
			parameter = BuildParameter(outSize, PARAMETER_BOOLEAN, name, *(BOOL*)buffer);
			break;
	}
	free(buffer);
	free(name);
	return parameter;
}