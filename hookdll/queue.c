#include <windows.h>
#include "queue.h"

//?=====================================================================+
//?  This file contains the implementation of a telemetry packet queue. |
//?  A queue is needed, because API hooks must be as fast and cheap     |
//?   as possible. File I/O (sending to pipe) creates a large cost,     |
//?   which is unacceptable in frequent APIs like VirtualAlloc.         |
//?  Instead the hook handlers will build the packet and queue it       |
//?   to be sent by a worker thread, whose job is sending packets.      |
//?---------------------------------------------------------------------|
//?  The packet queue is implemented as a simple ring buffer queue,     |
//?   with one for critical events, and another for standard events.    |
//?  The reason for two queues, is because if the queue is full, some   |
//?   events may need to be thrown away, but this is not acceptable     |
//?   for critical (i.e. suspicious) events, like queueing an APC.      |
//?---------------------------------------------------------------------|
//?  Note: this queue is created for multiple producers, with a single  |
//?   consumer. It is not safe to be used with multiple consumers!      |
//?=====================================================================+

// This function will take a single queue and initialize it for use.
void InitQueue(TELEMETRY_QUEUE* queue, const size_t size) {
	queue->tail  = 0;
	queue->head  = 0;
	queue->count = 0;
	queue->size  = size;
	queue->queue = malloc(queue->size * sizeof(QUEUE_ENTRY));
    queue->event = CreateEventA(NULL, TRUE, FALSE, NULL)
}

// This function will uninitialize a single queue. Should only ever be called at cleanup.
void DestroyQueue(TELEMETRY_QUEUE* queue) {
    queue->size = 0;
    queue->count = 0;
    free(queue->queue);
    CloseHandle(queue->event);
}

// Are there any packets in queue? Return value of true indicates there are no packets in queue.
BOOL QueueIsEmpty(TELEMETRY_QUEUE* queue) {
    return queue->head == queue->tail;
}

//? The term producer refers to something that creates new entries in the queue.
//? The term consumer refers to something that processes entries from the queue.

// Function for a producer (hook) to place a packet into the provided queue.
// @param  packet   A pointer to the packet buffer.
// @param  size    The size of the provided packet buffer.
// Boolean return value indicates if operation was successful, with true indicating success.
int EnqueuePacket(TELEMETRY_QUEUE* queue, LPVOID packet, size_t size) {
	if (queue == NULL || queue->queue == NULL || queue->event == NULL) {
        return ERROR_INVALID_QUEUE;
    }

    int attempts = 3;
    for (int i = 0; i < attempts; i++) {
        ULONG64 head = queue->head;
        ULONG64 tail = queue->tail;
        //* Check if queue is empty
        if (head - tail >= queue->capacity) {
            return ERROR_FULL_QUEUE;
        }
        //* Atomically check that queue state has not changed, and claim slot if has not.
        if (InterlockedCompareExchange64(&queue->head, head + 1, head) == head) {
            ULONG64 index = head % queue->capacity;
            queue->queue[index].packet = packet;
            queue->queue[index].size   = size;
            SetEvent(queue->event);
            return SUCCESS;
        }
    }
    return ERROR_FAILED_WRITE;
}

// Function for a consumer to process the next packet in a
// given packet queue, sending the packet through given named pipe.
// This function is not safe with multiple consumers. Only one worker should be used.
// @param  queue    Pointer to initialized packet queue to dequeue from.
// @param  hPipe    Named pipe to which the packet will be sent. 
// @param  retries  How many times to attempt sending packet, before returning error
// @return          Return value is 0 if successful, otherwise returns error code.
int DequeuePacket(TELEMETRY_QUEUE* queue, HANDLE hPipe, int retries) {
    //* validate queue state
    if (queue == NULL || queue->queue == NULL) {
        return ERROR_INVALID_QUEUE;
    }
    if (queue->head == queue->tail) return ERROR_EMPTY_QUEUE;

    //* get next packet
    ULONG64 tail = InterlockedIncrement64(&queue->tail) -1;
	ULONG64 index = tail % queue->capacity;
    LPVOID packet = queue->queue[index].packet;
    size_t size = queue->queue[index].size;

    //TODO: FREE PACKET!!!!!!!!!!!!!!!!
    //* attempt to send packet
    DWORD bytesWritten;
    for (int i = 0; i <= retries; i++) {
        BOOL success = WriteFile(hPipe, packet, size, &bytesWritten, NULL);
        if (success && bytesWritten == size) return SUCCESS;
    }
    return ERROR_FAILED_WRITE;
}

// This is the consumer routine for a worker thread.
// It will send packets to the agents telemetry pipe, as the packets come.
void QueueWorker(HANDLE hPipe) {
    HANDLE events[2] = { g_CriticalQueue.event, g_StandardQueue.event }
    while (1) {
        WaitForMultipleObjects(2, events, FALSE, INFINITE);
        //* Process priority packet queue first
        ResetEvent(g_CriticalQueue.event);
        while (!QueueIsEmpty(&g_CriticalQueue)) {
            int result = DequeuePacket(&g_CriticalQueue, hPipe, 2);
            if (result == ERROR_FAILED_WRITE) {
                //TODO: log error
            }
        }

        //* Process standard packet queue 
        ResetEvent(g_StandardQueue.event);
        while (!QueueIsEmpty(&g_StandardQueue)) {
            int result = DequeuePacket(&g_StandardQueue, hPipe, 0);
            if (result == ERROR_FAILED_WRITE) {
                //TODO: log error
            }
        }
    }
}

//CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)QueueWorker, &hTelemetry, 0, &tid);