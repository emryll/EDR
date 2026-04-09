#include <windows.h>
#include <stdio.h>
#include "etw.h"

//?========================================================================+
//?  This file implements a ring buffer queue for telemetry events.        |
//?  It is a single producer - single consumer queue with batched sending. |
//?------------------------------------------------------------------------|
//?     This queue is not safe to use concurrently!!                       | 
//?========================================================================+

//? Currently this is just a simple queue, but in the future this
//? will be reworked to include batched sending, and be reworked
//? from a packet queue to an event queue, including the parsing.

// This function will take a single queue and initialize it for use.
// This will not create a worker thread to process queue items.
int InitQueue(TELEMETRY_QUEUE* queue, const size_t size) {
	queue->tail  = 0;
	queue->head  = 0;
	queue->capacity = size;
	queue->queue = malloc(queue->capacity * sizeof(QUEUE_ENTRY));
    queue->event = CreateEventA(NULL, TRUE, FALSE, NULL);
    if (queue->queue == NULL || queue->event == NULL) return ERROR_INVALID_QUEUE;
    return SUCCESS;
}

// This function will uninitialize a single queue. Should only ever be called at cleanup.
void DestroyQueue(TELEMETRY_QUEUE* queue) {
    queue->capacity = 0;
    free(queue->queue);
    CloseHandle(queue->event);
}

//? The term producer refers to something that creates new entries in the queue.
//? The term consumer refers to something that processes entries from the queue.

BOOL QueueIsEmpty(TELEMETRY_QUEUE* queue) {
    return queue->head == queue->tail;
}

BOOL QueueIsFull(TELEMETRY_QUEUE* queue) {
    return (queue->head - queue->tail) >= queue->capacity;
}

// Function for a producer (etw consumer) to place a packet into the provided queue.
// This function is not safe to use concurrently! Designed for one consumer and producer.
// @param  packet   A pointer to the packet buffer.
// @param  size     The size of the provided packet buffer.
// @return          Return value is 0 if successful, otherwise value is the error code.
int EnqueuePacket(TELEMETRY_QUEUE* queue, BYTE* packet, size_t size) {
    if (queue == NULL || queue->queue == NULL
        || queue->capacity == 0) return ERROR_INVALID_QUEUE;
    if (QueueIsFull(queue)) return ERROR_FULL_QUEUE;

    ULONG64 index = queue->head % queue->capacity;
    queue->queue[index].packet = packet;
    queue->queue[index].size   = size;
    SetEvent(queue->event);
    queue->head++;

    return SUCCESS;
}

// Function for a consumer to process the next packet in a 
// given packet queue, sending the packet through to given named pipe.
// This function is NOT SAFE WITH MULTIPLE CONSUMERS. Only one worker should be used.
// @param  queue    Pointer to initialized packet queue to dequeue from.
// @param  hPipe    Named pipe to which the packet will be sent.
// @param  retries  How many times to attempt sending packet, before returning error.
// @return          Return value is 0 if successful, otherwise value is the error code.
int DequeuePacket(TELEMETRY_QUEUE* queue, HANDLE hPipe, int retries) {
    if (queue == NULL || queue->queue == NULL
        || queue->capacity == 0) return ERROR_INVALID_QUEUE;
    if (QueueIsEmpty(queue)) return ERROR_EMPTY_QUEUE;

    ULONG64 index = queue->tail % queue->capacity;
    LPVOID packet = queue->queue[index].packet;
    size_t size = queue->queue[index].size;

    for (int i = 0; i < retries; i++) {
        DWORD bytesWritten;
        BOOL success = WriteFile(hPipe, packet, size, &bytesWritten, NULL);
        if (success && bytesWritten == size) {
            queue->tail++;
            return SUCCESS;
        }
    }
    return ERROR_FAILED_WRITE;
}

// This is a worker routine for a queue consumer
void QueueWorker(HANDLE hPipe) {
    HANDLE events[2] = {g_StandardQueue.event, g_CriticalQueue.event};
    while(1) {
        WaitForMultipleObjects(2, events, FALSE, INFINITE);
        //? This is where batched sending would be implemented
        ResetEvent(g_CriticalQueue.event);
        while (!QueueIsEmpty(g_CriticalQueue)) {
            int result = DequeuePacket(g_CriticalQueue, hEtw, 3);
            if (result != 0) {
                printf("[ERROR] Failed to dequeue packet: %s", GetError(result));
                //TODO: log error and packet to disk
            }
        }
        ResetEvent(g_StandardQueue.event);
        while (!QueueIsEmpty(g_StandardQueue)) {
            int result = DequeuePacket(g_StandardQueue, hEtw, 3);
            if (result != 0) {
                printf("[ERROR] Failed to dequeue packet: %s", GetError(result));
                //TODO: log error and packet to disk
            }
        }
    }
}