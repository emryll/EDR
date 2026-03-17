package main

import (
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

//?==========================================================================+
//?  This file contains the (go) code in charge of handle scans. The actual  |
//?   handle enumeration functionality is implemented in C (handles.c).      |
//?  Note: in version 0.1.0-alpha, there will only be single component       |
//?   rules for handle scans. Handle components can additionally be used     |
//?   in regular behavioral patterns, but they are quite inefficient.        |
//?==========================================================================+

//*=================================[ Handle Table Cache ]=================================

var HandleTable *HandleCache

// Since currently handles are retrieved
// via global handle table lookup,
// which is expensive; caching is used.
// You should only use the mutex if you
// directly access cache, never for methods.
type HandleCache struct {
	mu        sync.RWMutex
	Cache     map[uint32]map[string]map[uint32]*HandleEntry // pid -> object type -> handle
	TimeStamp int64                                         // last updated
}

// Initialize cache, refilling it. Mutex is handled internally. Concurrency safe method.
func (c *HandleCache) Init() {
	var handleCount C.size_t
	cHandleEntries := C.GetGlobalHandleTable(&handleCount)
	handleTable := unsafe.Slice((*HandleEntry)(unsafe.Pointer(cHandleEntries)), int(handleCount))

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.Cache == nil {
		c.Cache = make(map[uint32]map[string]map[uint32]*HandleEntry)
	}
	for _, handle := range handleTable {
		if c.Cache[handle.Pid] == nil {
			c.Cache[handle.Pid] = make(map[string]map[uint32]*HandleEntry)
		}
		objectType := handle.GetTypeName()
		if c.Cache[handle.Pid][objectType] == nil {
			c.Cache[handle.Pid][objectType] = make(map[uint32]*HandleEntry)
		}

		if entry, exists := c.Cache[handle.Pid][objectType][handle.Handle]; exists {
			entry.LastSeen = time.Now().UnixMilli()
		} else {
			//*Note: you need go version >=1.22 or this wont work!
			//* the iteration value will point to same address. To fix: handle := handle
			c.Cache[handle.Pid][objectType][handle.Handle] = &handle
		}
	}
	C.FreeHandleTable(cHandleEntries, handleCount)
}

// Is handle table cache ready for use. Mutex is handled internally
func (c *HandleCache) Valid() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.Cache == nil {
		return false
	}
	return c.TimeStamp >= (time.Now().Unix() - HANDLE_CACHE_EXPIRATION)
}

// Add new handle entry into cache, or update existing
func (c *HandleCache) Add(handle *HandleEntry) {
	if handle.FirstSeen == 0 {
		handle.FirstSeen = time.Now().UnixMilli()
	}
	if handle.LastSeen == 0 {
		handle.LastSeen = handle.FirstSeen
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.Cache[handle.Pid] == nil {
		c.Cache[handle.Pid] = make(map[string]map[uint32]*HandleEntry)
	}
	objectType := handle.GetTypeName()
	if c.Cache[handle.Pid][objectType] == nil {
		c.Cache[handle.Pid][objectType] = make(map[uint32]*HandleEntry)
	}

	//* Add handle, or update existing
	if entry, exists := c.Cache[handle.Pid][objectType][handle.Handle]; exists {
		entry.LastSeen = time.Now().UnixMilli()
	} else {
		c.Cache[handle.Pid][objectType][handle.Handle] = handle
	}
}

// Remove all handle entries held by given process
func (c *HandleCache) Remove(pid uint32) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	delete(c.Cache, pid)
}

//*====================================[ Handle Scanning ]=========================================

type cHandleEntry struct {
	FirstSeen  int64
	LastSeen   int64
	Params     unsafe.Pointer
	ParamsSize uint64
	Handle     uint32
	Access     uint32
	Type       uint32
	Pid        uint32
}

type HandleEntry struct {
	FirstSeen  int64
	LastSeen   int64
	Handle     uint32
	Access     uint32
	Type       uint32
	Pid        uint32
	Parameters map[string]Parameter
}

//TODO: helpers to lookup if a process has a certain type of handle,
//TODO:  as described by a handle component. It should also lookup a handle opening api
/*
// This is the outer function for performing a global handle scan.
func GlobalHandleScan() {
	if !HandleTable.Valid() {
		HandleTable.Init()
	}

	//TODO: implement worker pool
	//TODO: implement caching of handle table

	for _, handle := range handleTable {
		for _, pattern := range HandleRuleCatalog[handle.GetTypeName()] {
			match := handle.CheckPattern(pattern)
			if match {
				if _, exists := processes[int(handle.Pid)].PatternMatches[pattern.GetName()]; exists {
					continue
				}
				processes[int(handle.Pid)].IncrementScore(pattern.Score)
				processes[int(handle.Pid)].PatternMatches[pattern.GetName()] = pattern.GetStdResult(pattern.Bonus)
			}
		}
	}
}
*/
//TODO: implement single handle lookup for patterns

// Get global handle table. Note that this is heavy; in the ballpark of 1000ms
func GetGlobalHandleTable() []HandleEntry {
	var handleCount C.size_t
	cHandleEntries := C.GetGlobalHandleTable(&handleCount)
	cSlice := unsafe.Slice((*cHandleEntry)(unsafe.Pointer(cHandleEntries)), int(handleCount))

	handleTable := make([]HandleEntry, 0, int(handleCount))
	for _, v := range cSlice {
		handleTable = append(handleTable, v.GoEntry())
	}
	C.FreeHandleTable(cHandleEntries, handleCount)
	return handleTable
}

// This unfortunately currently parses the entire global handle table, therefore should be avoided
func (c HandleComponent) GetResult(p *Process) *ComponentResult {
	var result ComponentResult
	//* Check universal override
	if c.UniversalOverride != nil && !c.UniversalOverride.Check(p) {
		return &ComponentResult{Exists: false, Required: c.IsRequired()}
	}

	// Initialize handle table for lookup
	if !HandleTable.Valid() {
		HandleTable.Init()
	}
	HandleTable.mu.RLock()
	defer HandleTable.mu.RUnlock()

	// All corresponding handles can be found directly in this slice
	if HandleTable.Cache[p.ProcessId][c.Type] == nil || len(HandleTable.Cache[p.ProcessId][c.Type]) == 0 {
		return &ComponentResult{Exists: false, Required: c.IsRequired()}
	}

Handles:
	//* Iterate corresponding handles
	for _, handle := range HandleTable.Cache[p.ProcessId][c.Type] {
		//* Check if conditions are passed
		for _, condition := range c.Conditions {
			if !condition.Check(p, handle) {
				continue Handles
			}
		}
		//* Add handle to result
		result.LeftEdge = append(result.LeftEdge, handle)
	}
	result.Timeless = true
	return &result
}

// Convert mirrored C HANDLE_ENTRY layout into go version
func (h cHandleEntry) GoEntry() HandleEntry {
	var entry HandleEntry
	entry.FirstSeen = h.FirstSeen
	entry.LastSeen = h.LastSeen
	entry.Handle = h.Handle
	entry.Access = h.Access
	entry.Type = h.Type
	entry.Pid = h.Pid

	if h.ParamsSize == 0 || h.Params == nil || uintptr(h.Params) == ^uintptr(0) {
		return entry
	}

	buf := C.GoBytes(unsafe.Pointer(h.Params), C.int(h.ParamsSize))
	params := ParseParameters(buf)
	entry.Parameters = make(map[string]Parameter)
	for _, param := range params {
		entry.Parameters[param.Name] = param
	}
	C.free(unsafe.Pointer(h.Params))

	return entry
}

// required to implement event interface. not used
// handle entries are a special case of events,
// as they are not stored like other events.
// use the handle table cache for storage and access.
func (handle *HandleEntry) AddToHistory(pid int) error {
	return nil
}

// required to implement event interface. not used
func (handle *HandleEntry) RemoveFromHistory(pid int) {
	return
}

// method made for implementing special case in timeline checks
func (handle *HandleEntry) IsTimeless() bool {
	return true
}

// required to implement event interface. not used
func (handle *HandleEntry) GetUniqueIdentifier() string {
	return ""
}

// Check if a handle matches a pattern. Return value True indicates a match.
func (handle *HandleEntry) CheckPattern(pattern BehaviorPattern) bool {
	for _, component := range pattern.Components {
		comp := component.(HandleComponent)
		//* check object type
		if handle.Type != comp.Type {
			return false
		}
		//* these contain the filters like handle access rights
		for _, condition := range comp.Conditions {
			if !condition.Check(nil, handle) {
				return false
			}
		}
	}
	return true
}

/*
// Returns the filepath of a process, given a handle to it

	func (handle HandleEntry) GetPathFromProcessHandle() (string, error) {
		if handle.Type != OBJECT_TYPE_PROCESS {
			return "", fmt.Errorf("failed to get path from process handle: not a process handle (%s object)", handle.GetTypeName())
		}
		targetPid, err := windows.GetProcessId(windows.Handle(handle.Handle))
		if err != nil {
			return "", fmt.Errorf("failed to get path from process handle: %v", err)
		}
		path, err := GetProcessExecutable(targetPid)
		if err != nil {
			return "", fmt.Errorf("failed to get path from process handle: %v", err)
		}
		return path, nil
	}

// Returns the path of the owning process of specified thread (handle)

	func (handle HandleEntry) GetPathFromThreadHandle() (string, error) {
		if handle.Type != OBJECT_TYPE_THREAD {
			return "", fmt.Errorf("failed to get process path from thread handle: not a thread handle (%s object)", handle.GetTypeName())
		}
		targetPid, err := GetProcessIdOfThread(handle.Handle)
		if err != nil {
			return "", fmt.Errorf("failed to get process path from thread handle: %v", err)
		}
		path, err := GetProcessExecutable(targetPid)
		if err != nil {
			return "", fmt.Errorf("failed to get process path from thread handle: %v", err)
		}
		return path, nil
	}
*/
func GetProcessIdOfThread(handle uintptr) (uint32, error) {
	var (
		modk32             = windows.NewLazySystemDLL("kernel32.dll")
		procGetPidOfThread = modk32.NewProc("GetProcessIdOfThread")
	)
	r, _, err := procGetPidOfThread.Call(handle)
	if r == 0 {
		if err != windows.ERROR_SUCCESS {
			return 0, err
		}
		return 0, windows.ERROR_INVALID_PARAMETER
	}
	return uint32(r), nil
}

func (handle HandleEntry) GetTypeName() string {
	switch int(handle.Type) {
	case OBJECT_TYPE_PROCESS:
		return "Process"
	case OBJECT_TYPE_THREAD:
		return "Thread"
	case OBJECT_TYPE_TOKEN:
		return "Token"
	case OBJECT_TYPE_DEVICE:
		return "Device"
	case OBJECT_TYPE_DESKTOP:
		return "Desktop"
	case OBJECT_TYPE_DRIVER:
		return "Driver"
	case OBJECT_TYPE_WORKER_FACTORY:
		return "TpWorkerFactory"
	case OBJECT_TYPE_SECTION:
		return "Section"
	case OBJECT_TYPE_DBGOBJECT:
		return "DebugObject"
	case OBJECT_TYPE_EVENT:
		return "Event"
	case OBJECT_TYPE_DIRECTORY:
		return "Directory"
	case OBJECT_TYPE_FILE:
		return "File"
	case OBJECT_TYPE_SEMAPHORE:
		return "Semaphore"
	case OBJECT_TYPE_KEY:
		return "Key"
	case OBJECT_TYPE_SYMLINK:
		return "SymbolicLink"
		//TODO: rest of object types
	}
	return "(unknown)"
}
