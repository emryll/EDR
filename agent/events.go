package main

import (
	"encoding/binary"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
)

//? This file contains the declarations and methods of Event interface.
//? Events describe telemetry data. Actual actions which have happened in a process.

type Event interface {
	GetEventType() int
	GetTimestamps() []int64
	GetParameter(name string) Parameter
	GetParameterWithOptions(options ...string) Parameter
	GetUniqueIdentifier() string // the purpose of this is to spot duplicates
	RemoveFromHistory(pid int)
	AddToHistory(pid int) error
	Print(pid uint32)
}

type History[T any] interface {
	GetTime() int64
	HistoryPtr() *[]*T
}

// describes an API call intercepted by hooks
type ApiEvent struct {
	ThreadId   uint32
	DllName    string
	FuncName   string
	TimeStamps []int64
	Parameters map[string]Parameter
}

type FileEvent struct {
	Path       string
	Action     string
	TimeStamps []int64
	Parameters map[string]Parameter
	History    []*FileEvent
}

type RegistryEvent struct {
	Path       string
	Action     string
	TimeStamps []int64
	Parameters map[string]Parameter
	History    []*RegistryEvent
}

// This also implements Event interface because its a component type, for now.
type HandleEntry struct {
	Handle uintptr
	Type   uint32
	Pid    uint32
	Access uint32
}

func (f FileEvent) GetTimestamps() []int64 {
	return f.TimeStamps
}

func (r RegistryEvent) GetTimestamps() []int64 {
	return r.TimeStamps
}

func (a ApiEvent) GetTimestamps() []int64 {
	return a.TimeStamps
}

func (h HandleEntry) GetTimestamps() []int64 {
	return []int64{0} // wont this mess up timeline checks? //TODO: should add special case
}

func (a ApiEvent) GetEventType() int {
	return TM_TYPE_API_CALL
}

func (f FileEvent) GetEventType() int {
	return TM_TYPE_FILE_EVENT
}

func (r RegistryEvent) GetEventType() int {
	return TM_TYPE_REG_EVENT
}

func (handle HandleEntry) GetEventType() int {
	return EVENT_TYPE_HANDLE
}

func (f FileEvent) GetParameter(name string) Parameter {
	if param, exists := f.Parameters[name]; exists {
		return param
	}
	if name == "FilePath" || name == "TargetPath" || name == "Path" || name == "TargetFile" {
		param := Parameter{Type: PARAMETER_ANSISTRING, Name: name, Buffer: []byte(f.Path)}
		param.Buffer = append(param.Buffer, '\000')
		return param
	}
	return Parameter{}
}

func (handle HandleEntry) GetParameter(name string) Parameter {
	switch name {
	case "Access", "DesiredAccess":
		param := Parameter{Name: name, Type: PARAMETER_UINT32}
		param.Buffer = binary.LittleEndian.AppendUint32(param.Buffer, handle.Access)
		return param
	case "Type", "ObjectType", "HandleType":
		param := Parameter{Name: name, Type: PARAMETER_UINT32}
		param.Buffer = binary.LittleEndian.AppendUint32(param.Buffer, handle.Type)
		return param
	case "Pid", "CallingPid", "Owner", "OwningPid":
		param := Parameter{Name: name, Type: PARAMETER_UINT32}
		param.Buffer = binary.LittleEndian.AppendUint32(param.Buffer, handle.Pid)
		return param
	}
	return Parameter{}
}

func (a ApiEvent) GetParameter(name string) Parameter {

}

func (r RegistryEvent) GetParameter(name string) Parameter {
	if param, exists := r.Parameters[name]; exists {
		return param
	}
	return Parameter{}
}
func (event ApiEvent) GetParameterWithOptions(options ...string) Parameter {
	for _, name := range options {
		if param, exists := event.Parameters[name]; exists {
			return param
		}
	}
	return Parameter{}
}

func (event FileEvent) GetParameterWithOptions(options ...string) Parameter {
	for _, name := range options {
		if param, exists := event.Parameters[name]; exists {
			return param
		}
	}
	return Parameter{}
}

func (event RegistryEvent) GetParameterWithOptions(options ...string) Parameter {
	for _, name := range options {
		if param, exists := event.Parameters[name]; exists {
			return param
		}
	}
	return Parameter{}
}

func (handle HandleEntry) GetParameterWithOptions(options ...string) Parameter {
	for _, name := range options {
		switch name {
		case "Access", "DesiredAccess":
			param := Parameter{Name: name, Type: PARAMETER_UINT32}
			param.Buffer = binary.LittleEndian.AppendUint32(param.Buffer, handle.Access)
			return param
		case "Type", "ObjectType", "HandleType":
			param := Parameter{Name: name, Type: PARAMETER_UINT32}
			param.Buffer = binary.LittleEndian.AppendUint32(param.Buffer, handle.Type)
			return param
		case "Pid", "CallingPid", "Owner", "OwningPid":
			param := Parameter{Name: name, Type: PARAMETER_UINT32}
			param.Buffer = binary.LittleEndian.AppendUint32(param.Buffer, handle.Pid)
			return param
		}
	}
	return Parameter{}
}

// Derive a string encoded key for the specific event.
// Events with the same identifier are considered duplicates.
func (a ApiEvent) GetUniqueIdentifier() string {
	// parameters need to be iterated in alphabetical order
	keys := make([]string, 0, len(a.Parameters))
	for k := range a.Parameters {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	// the identifier is in the following format:
	// tid + param_1 + value_1 + ... + param_n + value_n
	var b strings.Builder
	fmt.Fprintf(&b, "%d", a.ThreadId)
	for _, k := range keys {
		b.WriteString(k)
		fmt.Fprintf(&b, "%v", a.Parameters[k].GetValue())
	}
	return b.String()
}

// Derive a string encoded key for the specific event.
// Events with the same identifier are considered duplicates.
func (f FileEvent) GetUniqueIdentifier() string {
	// parameters need to be iterated in alphabetical order
	keys := make([]string, 0, len(f.Parameters))
	for k := range f.Parameters {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	// the identifier is in the following format:
	// filepath + param_1 + value_1 + ... + param_n + value_n
	var b strings.Builder
	b.WriteString(f.Path)
	for _, k := range keys {
		b.WriteString(k)
		fmt.Fprintf(&b, "%v", f.Parameters[k].GetValue())
	}
	return b.String()
}

func (r RegistryEvent) GetUniqueIdentifier() string {
	// parameters need to be iterated in alphabetical order
	keys := make([]string, 0, len(r.Parameters))
	for k := range r.Parameters {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	// the identifier is in the following format:
	// filepath + param_1 + value_1 + ... + param_n + value_n
	var b strings.Builder
	b.WriteString(r.Path)
	for _, k := range keys {
		b.WriteString(k)
		fmt.Fprintf(&b, "%v", r.Parameters[k].GetValue())
	}
	return b.String()
}

// Add an event to the corresponding process' telemetry history.
// This method should be called when event is first received and constructed.
func (a *ApiEvent) AddToHistory(pid int) error {
	if _, exists := processes[pid]; !exists {
		return fmt.Errorf("process %d is not tracked", pid)
	}

	id := a.GetUniqueIdentifier()
	processes[pid].ApiEvents.mu.Lock()
	if processes[pid].ApiEvents.Events[a.FuncName] == nil {
		processes[pid].ApiEvents.Events[a.FuncName] = make(map[string]*ApiEvent)
	}
	//* Check if such an entry already exists, add new one if needed.
	if _, exists := processes[pid].ApiEvents.Events[a.FuncName][id]; exists {
		// add timestamp to duplicate event entry
		processes[pid].ApiEvents.Events[a.FuncName][id].TimeStamps = append(
			processes[pid].ApiEvents.Events[a.FuncName][id].TimeStamps, a.TimeStamps...)
	} else {
		processes[pid].ApiEvents.Events[a.FuncName][id] = a
	}
	processes[pid].ApiEvents.mu.Unlock()
	return nil
}

// Add an event to the corresponding process' telemetry history.
// This method should be called when event is first received and constructed.
func (f *FileEvent) AddToHistory(pid int) error {
	if _, exists := processes[pid]; !exists {
		return fmt.Errorf("process %d is not tracked", pid)
	}

	var (
		id   = f.GetUniqueIdentifier()
		dir  = filepath.Dir(f.Path)
		base = filepath.Base(f.Path)
	)
	processes[pid].FileEvents.mu.Lock()
	//* First check that all of the inner maps are initialized.
	if processes[pid].FileEvents.FileActionTree[f.Action] == nil {
		processes[pid].FileEvents.FileActionTree[f.Action] = make(map[string]*FileEvent)
	}
	if processes[pid].FileEvents.FilePathTree[dir] == nil {
		processes[pid].FileEvents.FilePathTree[dir] = make(map[string]map[string]map[string]*FileEvent)
	}
	if processes[pid].FileEvents.FilePathTree[dir][base] == nil {
		processes[pid].FileEvents.FilePathTree[dir][base] = make(map[string]map[string]*FileEvent)
	}
	if processes[pid].FileEvents.FilePathTree[dir][base][f.Action] == nil {
		processes[pid].FileEvents.FilePathTree[dir][base][f.Action] = make(map[string]*FileEvent)
	}

	//* Check if such an entry already exists, add new one if needed.
	if _, exists := processes[pid].FileEvents.FileActionTree[f.Action][id]; exists {
		// add timestamp to duplicate event entry
		processes[pid].FileEvents.FileActionTree[f.Action][id].TimeStamps = append(
			processes[pid].FileEvents.FileActionTree[f.Action][id].TimeStamps, f.TimeStamps...)
	} else {
		processes[pid].FileEvents.FileActionTree[f.Action][id] = f
		processes[pid].FileEvents.FilePathTree[dir][base][f.Action][id] = f
		//TODO: also check the directory size cap while youre at it
		//TODO: queue history cleanup task if threshold is exceeded
	}
	processes[pid].FileEvents.mu.Lock()
	return nil
}

func (r *RegistryEvent) AddToHistory(pid int) error {
	if _, exists := processes[pid]; !exists {
		return fmt.Errorf("process %d is not tracked", pid)
	}
	id := r.GetUniqueIdentifier()
	processes[pid].RegEvents.mu.Lock()
	//* First check that the inner maps are initialized.
	if processes[pid].RegEvents.RegActionTree[r.Action] == nil {
		processes[pid].RegEvents.RegActionTree[r.Action] = make(map[string]*RegistryEvent)
	}
	if processes[pid].RegEvents.RegPathTree[r.Path] == nil {
		processes[pid].RegEvents.RegPathTree[r.Path] = make(map[string]*RegistryEvent)
	}

	//* Check if such an entry already exists, add new one if needed.
	if _, exists := processes[pid].RegEvents.RegPathTree[r.Path][id]; exists {
		// add timestamp to duplicate event entry
		processes[pid].RegEvents.RegPathTree[r.Path][id].TimeStamps = append(
			processes[pid].RegEvents.RegPathTree[r.Path][id].TimeStamps, r.TimeStamps...)
	} else {
		processes[pid].RegEvents.RegActionTree[r.Action][id] = r
		processes[pid].RegEvents.RegPathTree[r.Path][id] = r
		//TODO: also check the directory size cap while youre at it
		//TODO: queue history cleanup task if threshold is exceeded
	}
	processes[pid].RegEvents.mu.Unlock()
	return nil
}

func (a *ApiEvent) RemoveFromHistory(pid int) {
	processes[pid].ApiEvents.mu.Lock()
	defer processes[pid].ApiEvents.mu.Unlock()

	// Check that inner map is initialized
	if processes[pid].ApiEvents.Events[a.FuncName] == nil {
		return
	}
	delete(processes[pid].ApiEvents.Events[a.FuncName], a.GetUniqueIdentifier())
}

func (f *FileEvent) RemoveFromHistory(pid int) {
	processes[pid].FileEvents.mu.Lock()
	defer processes[pid].FileEvents.mu.Unlock()

	var (
		id   = f.GetUniqueIdentifier()
		dir  = filepath.Dir(f.Path)
		base = filepath.Base(f.Path)
	)
	// Check that inner maps are initialized
	if processes[pid].FileEvents.FileActionTree[f.Action] == nil {
		return
	}
	if processes[pid].FileEvents.FilePathTree[dir] == nil ||
		processes[pid].FileEvents.FilePathTree[dir][base] == nil ||
		processes[pid].FileEvents.FilePathTree[dir][base][f.Action] == nil {
		return
	}

	// Remove event entries and cleanup maps
	delete(processes[pid].FileEvents.FileActionTree[f.Action], id)
	delete(processes[pid].FileEvents.FilePathTree[dir][base][f.Action], id)
	if len(processes[pid].FileEvents.FilePathTree[dir][base][f.Action]) == 0 {
		delete(processes[pid].FileEvents.FilePathTree[dir][base], f.Action)
	}
	if len(processes[pid].FileEvents.FilePathTree[dir][base]) == 0 {
		delete(processes[pid].FileEvents.FilePathTree[dir], base)
	}
	if len(processes[pid].FileEvents.FilePathTree[dir]) == 0 {
		delete(processes[pid].FileEvents.FilePathTree, dir)
	}
}

func (r *RegistryEvent) RemoveFromHistory(pid int) {
	processes[pid].RegEvents.mu.Lock()
	defer processes[pid].RegEvents.mu.Unlock()

	// Check that inner maps are initialized
	if processes[pid].RegEvents.RegActionTree[r.Action] == nil ||
		processes[pid].RegEvents.RegPathTree[r.Path] == nil {
		return
	}
	id := r.GetUniqueIdentifier()
	// Remove event entries and cleanup maps
	delete(processes[pid].RegEvents.RegActionTree[r.Action], id)
	delete(processes[pid].RegEvents.RegPathTree[r.Path], id)
	if len(processes[pid].RegEvents.RegPathTree[r.Path]) == 0 {
		delete(processes[pid].RegEvents.RegPathTree, r.Path)
	}
}
