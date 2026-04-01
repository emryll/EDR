#include <windows.h>
#include "hook.h"

//?================================================================================+
//?  This file contains implementations of telemetry packet construction for IPC.  | 
//?                                                                                |
//?  A (v4) packet is created by creating parameters and a telemetry header,       |
//?   then constructing a packet out of those, starting with the header.           |
//?                                                                                |
//?  Use GetTelemetryHeader(...) to create the header, BuildParameter(...) for     |
//?   scalar parameters, and BuildArrayParameter(...) for array parameters.        |
//?================================================================================+

//* This is the outer function for creating an array parameter buffer.
// @totalSize   (out) The length of the full parameter buffer.
// @type        The type of the parameter.
// @name        The name of the parameter.
// @arr         The value array to construct parameter out of.
// @arrSize     Length of arr; the amount of elements.
// @return      The parameter buffer
BYTE* BuildArrayParameter(size_t* totalSize, DWORD type, const char* name, void* arr, size_t arrSize) {
	BYTE* buf;
	size_t valSize;
	switch (type) {
		case PARAMETER_ASTR_ARRAY:
			buf = GetAnsiArray((const char**)arr, arrSize, &valSize);
            break;
		case PARAMETER_UINT32_ARRAY:
			buf = GetUint32Array((DWORD*)arr, arrSize, &valSize);
            break;
		case PARAMETER_UINT64_ARRAY:
			buf = GetUint64Array((UINT64*)arr, arrSize, &valSize);
            break;
		case PARAMETER_POINTER_ARRAY:
			buf = GetUint64Array((UINT64*)arr, arrSize, &valSize);
            break;
		case PARAMETER_BOOLEAN_ARRAY:
			buf = GetBooleanArray((BOOL*)arr, arrSize, &valSize);
            break;
		case PARAMETER_BYTES:
			buf = (BYTE*)arr;
			valSize = arrSize;
            break;
        default:
            return NULL;
	}
	
	size_t headSize;
	BYTE* header = CreateParameterHeader(name, valSize, type, &headSize);
	if (header == NULL) return NULL;
	
	*totalSize = headSize + valSize;
	BYTE* parameter = (BYTE*)malloc(*totalSize);
	
	memcpy(parameter, header, headSize);
	memcpy(parameter + headSize, buf, valSize);
	free(header);
	free(buf);
	
	return parameter;
}

//* This is the outer function for creating a scalar parameter buffer.
//? BYTE* param = BuildParameter(&paramSize, PARAMETER_ANSISTRING, "MyName", str)
// Note: this function takes in 4 parameters, the last one being the value,
//  variadic args were used as a workaround for a generic value receiver.
//  void pointer could be used but this way is nicer for the caller...
// @totalSize   (out) The length of the full parameter buffer.
// @type        The type of the parameter.
// @name        The name of the parameter.
// @variadic    The value to be used. (must match type)
// @return      The parameter buffer
BYTE* BuildParameter(size_t* totalSize, DWORD type, const char* name, ...) {
    va_list args;
    va_start(args, name);

    // Determine value pointer and size based on type
    BYTE valueBuf[8];
    const void* value = valueBuf;
    DWORD valueSize = 0;

    switch (type) {
        case PARAMETER_UINT32: {
            DWORD tmp = (DWORD)va_arg(args, unsigned int);
            memcpy(valueBuf, &tmp, sizeof(DWORD));
            valueSize = sizeof(DWORD);
            break;
        }
        case PARAMETER_UINT64: {
            UINT64 tmp = va_arg(args, UINT64);
            memcpy(valueBuf, &tmp, sizeof(UINT64));
            valueSize = sizeof(UINT64);
            break;
        }
        case PARAMETER_POINTER: {
            void* tmp = va_arg(args, void*);
            memcpy(valueBuf, &tmp, sizeof(void*));
            valueSize = sizeof(void*);
            break;
        }
        case PARAMETER_BOOLEAN: {
            BOOL tmp = (BOOL)va_arg(args, BOOL);
            memcpy(valueBuf, &tmp, sizeof(BOOL));
            valueSize = sizeof(BOOL);
            break;
        }
        case PARAMETER_ANSISTRING: {
            value = va_arg(args, const char*);
            valueSize = (DWORD)(strlen((const char*)value) + 1);
            break;
        }
        default:
            va_end(args);
            return NULL;
    }
    va_end(args);

    size_t headerLen = 0;
    BYTE* header = CreateParameterHeader((char*)name, 0, type, &headerLen);
    if (!header) return NULL;

    // Layout: [header bytes (includes null terminator)] [raw value]
    *totalSize = headerLen + valueSize;
    BYTE* buf = (BYTE*)malloc(*totalSize);
    if (!buf) { free(header); return NULL; }

    memcpy(buf, header, headerLen);
    memcpy(buf + headerLen, value, valueSize);

    free(header);
    return buf;
}

//* Create string-based header for v4 parameter.
// @name     The name of the parameter
// @size     The length of array value. Pass 0 if value is scalar
// @type     The type of value. PARAMETER_TYPE enum
// @dataSize (out) Size of the resulting buffer
// @return   Raw buffer containing parameter header. NULL if failed.
BYTE* CreateParameterHeader(const char* name, DWORD size, DWORD type, size_t* dataSize) {
    if (size > 50000) return NULL;
    // data size will also work as a counter for how much memory to allocate
    (*dataSize) = strlen(name) + 2; // +2 is for the symbol and the null-terminator at the end.

    size_t sizeStrLen;
    if (size > 0) {    
        // get the amount of characters it takes to represent size
        sizeStrLen = snprintf(NULL, 0, "%d", size);
        (*dataSize) += 1; // for the "/"
    } else {
        sizeStrLen = 0;
    }
    (*dataSize) += sizeStrLen;

    char symbol;
    // prefixed type similar to hungarian notation
    switch (type) {
        case PARAMETER_ANSISTRING:
            symbol = 's'; break;
        case PARAMETER_ASTR_ARRAY:
            symbol = 'S'; break;
        case PARAMETER_UINT32:
            symbol = 'd'; break;
        case PARAMETER_UINT32_ARRAY:
            symbol = 'D'; break;
        case PARAMETER_UINT64:
            symbol = 'q'; break;
        case PARAMETER_UINT64_ARRAY:
            symbol = 'Q'; break;
        case PARAMETER_POINTER:
            symbol = 'p'; break;
        case PARAMETER_POINTER_ARRAY:
            symbol = 'P'; break;
        case PARAMETER_BOOLEAN:
            symbol = 'b'; break;
        case PARAMETER_BOOLEAN_ARRAY:
            symbol = 'B'; break;
        case PARAMETER_BYTES: 
            symbol = 'x'; break;
        default: return NULL;
    }
    
    BYTE* packet = (BYTE*)malloc((*dataSize));
    if (packet == NULL) return NULL;

    if (sizeStrLen == 0) {
        snprintf((char*)packet, (*dataSize), "%c%s", symbol, name);
    } else {
        snprintf((char*)packet, (*dataSize), "%c%s/%d", symbol, name, size);
    }
    return packet;
}

// Returns a C string array as a buffer of consecutive dynamic size strings
BYTE* GetAnsiArray(const char** arr, size_t arrSize, size_t* bufSize) {
    *bufSize = 0;
	for (size_t i = 0; i < arrSize; i++) {
		*bufSize += strlen(arr[i]) + 1;
	}
	BYTE* buf = (BYTE*)malloc(*bufSize);
    if (buf == NULL) return NULL;
	
	size_t offset = 0;
	for (size_t i = 0; i < arrSize; i++) {
		size_t len = strlen(arr[i]) + 1;
		memcpy(buf + offset, arr[i], len);
		offset += len;
	}
	return buf;
}

// Returns a raw buffer containing provided uint32 array
BYTE* GetUint32Array(DWORD* arr, size_t arrSize, size_t* bufSize) {
    *bufSize = arrSize * sizeof(DWORD);
	BYTE* buf = (BYTE*)malloc(*bufSize);
    if (buf == NULL) return NULL;
	memcpy(buf, arr, *bufSize);
	return buf;
}

// Returns a raw buffer containing provided uint64 array
BYTE* GetUint64Array(UINT64* arr, size_t arrSize, size_t* bufSize) {
    *bufSize = arrSize * sizeof(UINT64);
	BYTE* buf = (BYTE*)malloc(*bufSize);
    if (buf == NULL) return NULL;
	memcpy(buf, arr, *bufSize);
	return buf;
}

// Returns a raw buffer containing provided boolean array
BYTE* GetBooleanArray(BOOL* arr, size_t arrSize, size_t* bufSize) {
    *bufSize = arrSize * sizeof(BOOL);
	BYTE* buf = (BYTE*)malloc(*bufSize);
    if (buf == NULL) return NULL;
	memcpy(buf, arr, *bufSize);
	return buf;
}
