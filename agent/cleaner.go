package main

import (
	"context"
	"path/filepath"
	"sync"
	"time"
)

//?====================================================================================+
//?  This file contains the implementation for telemetry storage lifecycle management. |
//?  Only time-based storage management is implemented here, size caps are             |
//?   implemented directly when the threshold is passed; inside AddToHistory.          |
//?====================================================================================+

//* cleanup old events periodically, using a worker pool
// remove events only if newest timestamp is older than threshold.
// ( i.e. TimeStamps[len(TimeStamps) - 1] < threshold )

type CleanupMission struct {
	Type uint32 // event type constant
	Pid  int
}

// Scheduler of telemetry storage cleanups, Destroyer of Worlds~
func Sir_HumphreyDaundelyon_ChiefJanitor_MasterOfMops(wg *sync.WaitGroup, ctx context.Context) {
	defer wg.Done()
	cleanup := time.NewTicker(time.Duration(TM_CLEANUP_INTERVAL) * time.Second)
	tasks := make(chan CleanupMission)

	const numHumbleWorkers = NUM_ENSLAVED_JANITORS
	for w := 0; w < numHumbleWorkers; w++ {
		wg.Add(1)
		go Humble_AdamFollywolle_III_NoviceSweeper(wg, tasks, ctx)
	}

	for {
		select {
		case <-ctx.Done(): // termination signal
			close(tasks)
			return
		case <-cleanup.C:
			go func() {
				for pid := range processes {
					tasks <- CleanupMission{Type: TM_TYPE_API_CALL, Pid: pid}
					tasks <- CleanupMission{Type: TM_TYPE_FILE_EVENT, Pid: pid}
					tasks <- CleanupMission{Type: TM_TYPE_REG_EVENT, Pid: pid}
				}
			}()
		}
	}
}

// Humble worker under the mighty sir Humphrey Daundelyon, executing thine demands~
func Humble_AdamFollywolle_III_NoviceSweeper(wg *sync.WaitGroup, tasks chan CleanupMission, ctx context.Context) {
	defer wg.Done()
	for {
		select {
		case <-ctx.Done(): // termination signal
			return
		case mission := <-tasks:
			if _, exists := processes[mission.Pid]; !exists {
				continue
			}
			switch mission.Type {
			case TM_TYPE_API_CALL:
				processes[mission.Pid].ApiEvents.Cleanup()
			case TM_TYPE_FILE_EVENT:
				processes[mission.Pid].FileEvents.Cleanup()
			case TM_TYPE_REG_EVENT:
				processes[mission.Pid].RegEvents.Cleanup()
			}
		}
	}
}

// Remove all events older than TM_CLEANUP_INTERVAL.
// Duplicates can remain, if there is a recent call.
func (t *ApiTelemetryIndex) Cleanup() {
	threshold := time.Now().Unix() - TM_CLEANUP_INTERVAL
	type expired struct{ api, id string }
	var events []expired

	t.mu.RLock()
	// first collect expired events.
	// this is separated to avoid holding write lock.
	for api, apiEvents := range t.Events {
		for id, event := range apiEvents {
			if event.TimeStamps[len(event.TimeStamps)-1] < threshold {
				events = append(events, expired{api: api, id: id})
			}
		}
	}
	t.mu.RUnlock()

	t.mu.Lock()
	defer t.mu.Unlock()
	// remove the expired events
	for _, event := range events {
		newest := t.Events[event.api][event.id].TimeStamps[len(t.Events[event.api][event.id].TimeStamps)-1]
		if newest < threshold {
			delete(t.Events[event.api], event.id)
		}
	}
}

// Remove all events older than TM_CLEANUP_INTERVAL.
// Duplicates can remain, if there is a recent call.
func (t *FileTelemetryIndex) Cleanup() {
	threshold := time.Now().Unix() - TM_CLEANUP_INTERVAL
	var expired []*FileEvent

	t.mu.RLock()
	for _, m := range t.FileActionTree {
		for _, event := range m {
			if event.TimeStamps[len(event.TimeStamps)-1] < threshold {
				expired = append(expired, event)
			}
		}
	}
	t.mu.RUnlock()

	t.mu.Lock()
	defer t.mu.Unlock()
	for _, event := range expired {
		// check that no new entries were added between locks
		if event.TimeStamps[len(event.TimeStamps)-1] >= threshold {
			continue
		}
		var (
			id   = event.GetUniqueIdentifier()
			dir  = filepath.Dir(event.Path)
			base = filepath.Base(event.Path)
		)

		delete(t.FileActionTree[event.Action], id)
		delete(t.FilePathTree[dir][base][event.Action], id)
		if len(t.FilePathTree[dir][base][event.Action]) == 0 {
			delete(t.FilePathTree[dir][base], event.Action)
		}
		if len(t.FilePathTree[dir][base]) == 0 {
			delete(t.FilePathTree[dir], base)
		}
		if len(t.FilePathTree[dir]) == 0 {
			delete(t.FilePathTree, dir)
		}
	}
}

// Remove all events older than TM_CLEANUP_INTERVAL.
// Duplicates can remain, if there is a recent call.
func (t *RegTelemetryIndex) Cleanup() {
	threshold := time.Now().Unix() - TM_CLEANUP_INTERVAL
	var expired []*RegistryEvent

	t.mu.RLock()
	for _, path := range t.RegPathTree {
		for _, event := range path {
			if event.TimeStamps[len(event.TimeStamps)-1] < threshold {
				expired = append(expired, event)
			}
		}
	}
	t.mu.RUnlock()

	t.mu.Lock()
	defer t.mu.Unlock()
	for _, event := range expired {
		// check that no new entries were added between locks
		if event.TimeStamps[len(event.TimeStamps)-1] >= threshold {
			continue
		}

		id := event.GetUniqueIdentifier()
		delete(t.RegActionTree[event.Action], id)
		delete(t.RegPathTree[event.Path], id)
		if len(t.RegPathTree[event.Path]) == 0 {
			delete(t.RegPathTree, event.Path)
		}
	}
}
