#ifndef QUEUE_H
#define QUEUE_H

#include <windows.h>

#define SUCCESS 0
#define ERROR_INVALID_QUEUE -1
#define ERROR_FULL_QUEUE -2
#define ERROR_EMPTY_QUEUE -3
#define ERROR_FAILED_WRITE -4 
#define ERROR_PARTIAL_WRITE -5

#define DEFAULT_STANDARD_QUEUE_SIZE 1024 // max num entries in queue
#define DEFAULT_CRITICAL_QUEUE_SIZE 512 // max num entries in queue

typedef struct {
	LPVOID packet; // pointer to telemetry packet
	size_t size;   // size of telemetry packet
} QUEUE_ENTRY;

typedef struct {
	volatile ULONG64 head;  // producer offset (writes)
	volatile ULONG64 tail;  // consumer offset (reads)
	const size_t capacity;  // max elements in queue
	QUEUE_ENTRY* queue;     // queue array
} TELEMETRY_QUEUE;

extern TELEMETRY_QUEUE g_StandardQueue;
extern TELEMETRY_QUEUE g_CriticalQueue;

void InitQueue(TELEMETRY_QUEUE*, const size_t);
void DestroyQueue(TELEMETRY_QUEUE*);

int EnqueuePacket(TELEMETRY_QUEUE*, LPVOID, size_t);
int DequeuePacket(TELEMETRY_QUEUE*, HANDLE);

#endif
