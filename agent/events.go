package main

import (
	"encoding/binary"
	"fmt"
	"sort"
	"strings"
)

//? This file contains the declarations and methods of Event interface.
//? Events describe telemetry data. Actual actions which have happened in a process.

type Event interface {
	GetEventType() int
	GetTimestamp() int64
	GetParameter(name string) Parameter
	GetParameterWithOptions(options ...string) Parameter
	GetUniqueIdentifier() string // the purpose of this is to spot duplicates
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
	TimeStamps int64
	Parameters map[string]Parameter
}

type FileEvent struct {
	Path       string
	Action     uint32
	TimeStamp  int64
	Parameters map[string]Parameter
	History    []*FileEvent
}

type RegistryEvent struct {
	Path       string
	Action     uint32
	TimeStamp  int64
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

func (f FileEvent) GetTimestamp() int64 {
	return f.TimeStamp
}

func (r RegistryEvent) GetTimestamp() int64 {
	return r.TimeStamp
}

func (a ApiEvent) GetTimestamp() int64 {
	return a.TimeStamp
}

func (h HandleEntry) GetTimestamp() int64 {
	return 0 // wont this mess up timeline checks? //TODO: should add special case
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
