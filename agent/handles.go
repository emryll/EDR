package main

import (
	"fmt"
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

// This is the outer function for performing a global handle scan.
func GlobalHandleScan() {
	var handleCount C.size_t
	cHandleEntries := C.GetGlobalHandleTable(&handleCount)
	handleTable := unsafe.Slice((*HandleEntry)(unsafe.Pointer(cHandleEntries)), int(handleCount))

	for _, handle := range handleTable {
		for _, pattern := range HandleRuleCatalog[handle.GetTypeName()] {
			match := handle.CheckPattern(pattern)
			if match {
				processes[int(handle.Pid)].IncrementScore(pattern.Score)
				//TODO: push to pattern matches
			}
		}
	}
	C.FreeHandleTable(cHandleEntries, handleCount)
}

// Check if a handle matches a pattern. Return value True indicates a match.
func (handle HandleEntry) CheckPattern(pattern BehaviorPattern, handleTable *[]HandleEntry) bool {
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
