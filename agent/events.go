package main

import "encoding/binary"

//? This file contains the declarations and methods of Event interface.
//? Events describe telemetry data. Actual actions which have happened in a process.

type Event interface {
	GetEventType() int
	GetTimestamp() int64
	GetParameter(name string) Parameter
	GetParameterWithOptions(options ...string) Parameter
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
	TimeStamp  int64
	Parameters map[string]Parameter
	History    []*ApiEvent // previous occurrences sorted by timestamp
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

func (a ApiEvent) HistoryPtr() *[]*ApiEvent {
	return &a.History
}

func (f FileEvent) HistoryPtr() *[]*FileEvent {
	return &f.History
}

func (r RegistryEvent) HistoryPtr() *[]*RegistryEvent {
	return &r.History
}
