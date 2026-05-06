package main

import (
	"encoding/binary"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

//?=====================================================================================+
//?  This file contains the declarations and helper methods of the Event interface.     |
//?  In addition to the core events, the event storage structures are implemented here. |
//?  Events describe telemetry data, actual actions which have happened in a process.   |
//?=====================================================================================+

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

//* A single event structure in the current design
//* describes a *unique* event. It can describe several
//* occurances (hence timestamps list) as long as it is
//* meaningfully the same event (parameters, tid, etc.)

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
}

type RegistryEvent struct {
	Path       string
	Action     string
	TimeStamps []int64
	Parameters map[string]Parameter
}

type EtwEvent struct {
	Provider   string // name, not guid
	EventId    int    // ETW event id
	TimeStamps []int64
	Parameters map[string]Parameter
}

type ApiTelemetryIndex struct {
	mu     sync.RWMutex
	Events map[string]map[string]*ApiEvent // api -> id
}

type FileTelemetryIndex struct {
	mu sync.RWMutex
	// dir -> filename -> action -> string encoded "unique" key
	FilePathTree   map[string]map[string]map[string]map[string]*FileEvent
	FileActionTree map[string]map[string]*FileEvent // action -> key
}

type RegTelemetryIndex struct {
	mu            sync.RWMutex
	RegPathTree   map[string]map[string]*RegistryEvent // path -> id
	RegActionTree map[string]map[string]*RegistryEvent // action -> id
}

func MakeApiTelemetryStore() ApiTelemetryIndex {
	var store ApiTelemetryIndex
	store.Events = make(map[string]map[string]*ApiEvent)
	return store
}

func MakeFileTelemetryStore() FileTelemetryIndex {
	var store FileTelemetryIndex
	store.FilePathTree = make(map[string]map[string]map[string]map[string]*FileEvent)
	store.FileActionTree = make(map[string]map[string]*FileEvent)
	return store
}

func MakeRegTelemetryStore() RegTelemetryIndex {
	var store RegTelemetryIndex
	store.RegActionTree = make(map[string]map[string]*RegistryEvent)
	store.RegPathTree = make(map[string]map[string]*RegistryEvent)
	return store
}

// Get all events of a certain API call (e.g. WriteProcessMemory)
// Optionally you can define a whitelist/filter of unique identifiers
func (a *ApiTelemetryIndex) GetEvents(api string, id ...string) []*ApiEvent {
	a.mu.RLock()
	if _, exists := a.Events[api]; !exists {
		return nil
	}
	var (
		events = make([]*ApiEvent, 0, len(a.Events[api]))
		ids    = make(map[string]bool, len(id))
	)
	for _, v := range id {
		ids[v] = true
	}

	for key, event := range a.Events[api] {
		// check filter if one is set
		if len(ids) == 0 || ids[key] {
			events = append(events, event)
		}
	}
	a.mu.RUnlock()
	return events
}

// Get all registry events under a given registry path.
// Note that it is not recursive (i.e. subdirs not included).
// Optionally you can specify a specific action the event should be.
func (r *RegTelemetryIndex) GetEventsByPath(path string, action string) []*RegistryEvent {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.RegPathTree[path] == nil {
		return nil
	}

	var events []*RegistryEvent
	for _, event := range r.RegPathTree[path] {
		if action == "" || event.Action == action {
			events = append(events, event)
		}
	}
	return events
}

// Get all registry events of a specified action (e.g. create_key)
func (r *RegTelemetryIndex) GetEventsByAction(action string) []*RegistryEvent {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.RegActionTree[action] == nil {
		return nil
	}

	var events []*RegistryEvent
	for _, event := range r.RegActionTree[action] {
		events = append(events, event)
	}
	return events
}

// Get all file system events of a specified action (e.g. write)
func (f *FileTelemetryIndex) GetEventsByAction(action string) []*FileEvent {
	f.mu.RLock()
	defer f.mu.RUnlock()

	if f.FileActionTree[action] == nil {
		return nil
	}

	var events []*FileEvent
	for _, event := range f.FileActionTree[action] {
		events = append(events, event)
	}
	return events
}

// Get all file system events described by dir, path and action.
// dir is required and declares the directory that the events must be under.
// Note that the directory structure is not recursive (i.e. subdirs dont count)
// Optionally you can define a filename and/or action further filtering events.
func (f *FileTelemetryIndex) GetEventsByPath(dir string, base *string, action *string) []*FileEvent {
	f.mu.RLock()
	defer f.mu.RUnlock()

	if dir == "" || f.FilePathTree[dir] == nil || len(f.FilePathTree[dir]) == 0 {
		return nil
	}
	if base != nil {
		if f.FilePathTree[dir][*base] == nil || len(f.FilePathTree[dir][*base]) == 0 {
			return nil
		}
		return getEventsOfAction(f.FilePathTree[dir][*base], action)
	}

	var events []*FileEvent
	for _, file := range f.FilePathTree[dir] {
		events = append(events, getEventsOfAction(file, action)...)
	}
	return events
}

// Internal helper for finding file system events in PathTree.
func getEventsOfAction(actionMap map[string]map[string]*FileEvent, action *string) []*FileEvent {
	var events []*FileEvent
	for a, idMap := range actionMap {
		if action != nil && a != *action {
			continue
		}
		for _, event := range idMap {
			events = append(events, event)
		}
	}
	return events
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
	if param, exists := a.Parameters[name]; exists {
		return param
	}
	return Parameter{}
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

// Add an event to the corresponding process' telemetry history.
// This method should be called when event is first received and constructed.
func (a *ApiEvent) AddToHistory(pid int) error {
	process := psTable.GetProcess(pid)
	if process == nil {
		return fmt.Errorf("process %d is not tracked", pid)
	}

	id := a.GetUniqueIdentifier()
	process.ApiEvents.mu.Lock()
	defer process.ApiEvents.mu.Unlock()
	if process.ApiEvents.Events[a.FuncName] == nil {
		process.ApiEvents.Events[a.FuncName] = make(map[string]*ApiEvent)
	}
	//* Check if such an entry already exists, add new one if needed.
	if _, exists := process.ApiEvents.Events[a.FuncName][id]; exists {
		// add timestamp to duplicate event entry
		process.ApiEvents.Events[a.FuncName][id].TimeStamps = append(
			process.ApiEvents.Events[a.FuncName][id].TimeStamps, a.TimeStamps...)
	} else {
		process.ApiEvents.Events[a.FuncName][id] = a
	}
	return nil
}

// Add an event to the corresponding process' telemetry history.
// This method should be called when event is first received and constructed.
func (f *FileEvent) AddToHistory(pid int) error {
	process := psTable.GetProcess(pid)
	if process == nil {
		return fmt.Errorf("process %d is not tracked", pid)
	}

	var (
		id   = f.GetUniqueIdentifier()
		dir  = filepath.Dir(f.Path)
		base = filepath.Base(f.Path)
	)
	process.FileEvents.mu.Lock()
	defer process.FileEvents.mu.Lock()
	//* First check that all of the inner maps are initialized.
	if process.FileEvents.FileActionTree[f.Action] == nil {
		process.FileEvents.FileActionTree[f.Action] = make(map[string]*FileEvent)
	}
	if process.FileEvents.FilePathTree[dir] == nil {
		process.FileEvents.FilePathTree[dir] = make(map[string]map[string]map[string]*FileEvent)
	}
	if process.FileEvents.FilePathTree[dir][base] == nil {
		process.FileEvents.FilePathTree[dir][base] = make(map[string]map[string]*FileEvent)
	}
	if process.FileEvents.FilePathTree[dir][base][f.Action] == nil {
		process.FileEvents.FilePathTree[dir][base][f.Action] = make(map[string]*FileEvent)
	}

	//* Check if such an entry already exists, add new one if needed.
	if _, exists := process.FileEvents.FileActionTree[f.Action][id]; exists {
		// add timestamp to duplicate event entry
		process.FileEvents.FileActionTree[f.Action][id].TimeStamps = append(
			process.FileEvents.FileActionTree[f.Action][id].TimeStamps, f.TimeStamps...)
	} else {
		process.FileEvents.FileActionTree[f.Action][id] = f
		process.FileEvents.FilePathTree[dir][base][f.Action][id] = f
		//TODO: also check the directory size cap while youre at it
		//TODO: queue history cleanup task if threshold is exceeded
	}
	return nil
}

// Add an event to the corresponding process' telemetry history.
// This method should be called when event is first received and constructed.
func (r *RegistryEvent) AddToHistory(pid int) error {
	process := psTable.GetProcess(pid)
	if process == nil {
		return fmt.Errorf("process %d is not tracked", pid)
	}

	id := r.GetUniqueIdentifier()
	process.RegEvents.mu.Lock()
	defer process.RegEvents.mu.Unlock()
	//* First check that the inner maps are initialized.
	if process.RegEvents.RegActionTree[r.Action] == nil {
		process.RegEvents.RegActionTree[r.Action] = make(map[string]*RegistryEvent)
	}
	if process.RegEvents.RegPathTree[r.Path] == nil {
		process.RegEvents.RegPathTree[r.Path] = make(map[string]*RegistryEvent)
	}

	//* Check if such an entry already exists, add new one if needed.
	if _, exists := process.RegEvents.RegPathTree[r.Path][id]; exists {
		// add timestamp to duplicate event entry
		process.RegEvents.RegPathTree[r.Path][id].TimeStamps = append(
			process.RegEvents.RegPathTree[r.Path][id].TimeStamps, r.TimeStamps...)
	} else {
		process.RegEvents.RegActionTree[r.Action][id] = r
		process.RegEvents.RegPathTree[r.Path][id] = r
		//TODO: also check the directory size cap while youre at it
		//TODO: queue history cleanup task if threshold is exceeded
	}
	return nil
}

// Remove this api event entry from the specified process' telemetry storage.
func (a *ApiEvent) RemoveFromHistory(pid int) {
	process := psTable.GetProcess(pid)
	if process == nil {
		return
	}

	process.ApiEvents.mu.Lock()
	defer process.ApiEvents.mu.Unlock()

	// Check that inner map is initialized
	if process.ApiEvents.Events[a.FuncName] == nil {
		return
	}
	delete(process.ApiEvents.Events[a.FuncName], a.GetUniqueIdentifier())
}

// Remove this file event entry from the specified process' telemetry storage.
func (f *FileEvent) RemoveFromHistory(pid int) {
	process := psTable.GetProcess(pid)
	if process == nil {
		return
	}
	process.FileEvents.mu.Lock()
	defer process.FileEvents.mu.Unlock()

	var (
		id   = f.GetUniqueIdentifier()
		dir  = filepath.Dir(f.Path)
		base = filepath.Base(f.Path)
	)
	// Check that inner maps are initialized
	if process.FileEvents.FileActionTree[f.Action] == nil {
		return
	}
	if process.FileEvents.FilePathTree[dir] == nil ||
		process.FileEvents.FilePathTree[dir][base] == nil ||
		process.FileEvents.FilePathTree[dir][base][f.Action] == nil {
		return
	}

	// Remove event entries and cleanup maps
	delete(process.FileEvents.FileActionTree[f.Action], id)
	delete(process.FileEvents.FilePathTree[dir][base][f.Action], id)

	if len(process.FileEvents.FilePathTree[dir][base][f.Action]) == 0 {
		delete(process.FileEvents.FilePathTree[dir][base], f.Action)
	}
	if len(process.FileEvents.FilePathTree[dir][base]) == 0 {
		delete(process.FileEvents.FilePathTree[dir], base)
	}
	if len(process.FileEvents.FilePathTree[dir]) == 0 {
		delete(process.FileEvents.FilePathTree, dir)
	}
}

// Remove this registry entry from the specified process' telemetry storage.
func (r *RegistryEvent) RemoveFromHistory(pid int) {
	process := psTable.GetProcess(pid)
	if process == nil {
		return
	}
	process.RegEvents.mu.Lock()
	defer process.RegEvents.mu.Unlock()

	// Check that inner maps are initialized
	if process.RegEvents.RegActionTree[r.Action] == nil ||
		process.RegEvents.RegPathTree[r.Path] == nil {
		return
	}
	id := r.GetUniqueIdentifier()
	// Remove event entries and cleanup maps
	delete(process.RegEvents.RegActionTree[r.Action], id)
	delete(process.RegEvents.RegPathTree[r.Path], id)
	if len(process.RegEvents.RegPathTree[r.Path]) == 0 {
		delete(process.RegEvents.RegPathTree, r.Path)
	}
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

// Derive a string encoded "unique" identifier.
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

// Derive a string encoded key for the specific event.
// Two events with the same identifier are consided duplicates.
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
	return TM_TYPE_ETW_FILE
}

func (r RegistryEvent) GetEventType() int {
	return TM_TYPE_ETW_REG
}

func (handle HandleEntry) GetEventType() int {
	return TM_TYPE_HANDLE
}
