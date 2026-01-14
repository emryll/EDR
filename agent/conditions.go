package main

import (
	"encoding/binary"
	"path/filepath"
	"strings"
	"unicode"
)

//?=======================================================================================+
//?  This file is responsible for the handling of conditions in behavioral patterns.	  |
//?  Mainly this includes the functionality of checking which group an event belongs to,  |
//?   and checking if a given condition is allowed for this specific event (group).		  |
//?=======================================================================================+

// Condition validation, as in "is this allowed", happens at startup, therefore performance is not so critical.

// A "set", refers to a collection of conditions, with something in common. For example a set of process conditions
//  contains conditions about a process, such as the path, pid, parent, etc.

// A "group", refers to a collection of similar types of events. For example, memory allocation events form one group,
//  while remote memory allocation events are a subgroup. These groups define which condition sets can be used.
//  For example: to use memory allocation conditions, the event must belong to the memory allocation group.

// To parse conditions of a component, you would first figure out which group it belongs to. After this,
//  you would query which sets of conditions are allowed for this group, and then just unmarshal to those.

// To check if a give condition is allowed for a component, you would first figure out which group it
//  belongs to. After this you would check which set the condition belongs to, and then seeing if this set
//  is allowed to be used by the group. This is done by the syntax checker, to notify user of invalid use.
// Technically this could also maybe be done by just reading all the valid conditions and then seeing which ones were "left-over"

// I don't like this current implementation so much, it feels a bit hacky. It will be reworked in future versions.

// Get the group this event belongs to. This is needed to implement Component interface
func (event FileComponent) GetGroup() int {
	return GROUP_FILE_EVENT
}

// Get the group this event belongs to. This is needed to implement Component interface
func (event RegComponent) GetGroup() int {
	return GROUP_REG_EVENT
}

// Get the group this event belongs to. This is needed to implement Component interface
func (event ApiComponent) GetGroup() int {
	return GetApiGroup(event.Options)
}

// shorthand name for a set of api functions. for example "mem_alloc"
// these are read from a config file on disk at startup, into a map for easy lookup.
type ApiShorthand struct {
	Name    string
	Group   string
	Options map[string]bool
}

const (
	GROUP_INVALID_API_OPTIONS = -1
	GROUP_UNKNOWN_API         = 0
	GROUP_FILE_EVENT          = 1
	GROUP_REG_EVENT           = 2
	GROUP_GENERIC_EMPTY       = 3 // no conditions defined to describe this event
	GROUP_GENERIC_THREAD      = 4 // those that only take thread handle/id as parameter
	GROUP_GENERIC_FLAGS       = 5 // uint32 flags
	GROUP_LOCAL_MEM_ALLOC
	GROUP_REMOTE_MEM_ALLOC
	GROUP_LOCAL_MEM_PROTECT
	GROUP_REMOTE_MEM_PROTECT
	GROUP_OPEN_PROCESS
	GROUP_CREATE_PROCESS
	GROUP_OPEN_THREAD
	GROUP_CREATE_LOCAL_THREAD
	GROUP_CREATE_REMOTE_THREAD
	GROUP_SET_THREAD_CONTEXT
	GROUP_QUEUE_APC

	GROUP_GET_MODULE_HANDLE
	GROUP_GET_FN_ADDRESS
	GROUP_LOAD_LIBRARY
)

func GetApiGroup(options []string) int {
	// This is for checking if conflicting apis exist.
	groups := make(map[int]bool)
	for _, option := range options {
		//* first check if it is shorthand
		if shorthand, exists := ApiShorthands[option]; exists {
			groups[shorthand.Group] = true
			continue
		}

		//* actual api
		switch option {
		case "VirtualAlloc": // should you include heapalloc, globalalloc, etc?
			groups[GROUP_LOCAL_MEM_ALLOC] = true
		case "VirtualAllocEx", "VirtualAlloc2", "NtAllocateVirtualMemory", "NtAllocateVirtualMemoryEx":
			groups[GROUP_REMOTE_MEM_ALLOC] = true
		case "VirtualProtect":
			groups[GROUP_LOCAL_MEM_PROTECT] = true
		case "VirtualProtectEx", "NtProtectVirtualMemory":
			groups[GROUP_REMOTE_MEM_PROTECT] = true
		case "OpenProcess", "NtOpenProcess":
			groups[GROUP_OPEN_PROCESS] = true
		case "CreateProcess", "NtCreateProcess": //TODO: add other options
			groups[GROUP_CREATE_PROCESS] = true

		case "GetModuleHandleA", "GetModuleHandleW", "GetModuleHandleExA", "GetModuleHandleExW":
			groups[GROUP_GET_MODULE_HANDLE] = true
		case "GetProcAddress":
			groups[GROUP_GET_FN_ADDRESS] = true
		case "LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "LoadLibraryExW", "LdrLoadDll":
			groups[GROUP_LOAD_LIBRARY] = true
		case "CreateToolhelp32Snapshot", "SetDefaultDllDirectories":
			groups[GROUP_GENERIC_FLAGS] = true
		case "GetThreadContext", "NtGetContextThread", "SuspendThread", "ResumeThread", "NtSuspendThread", "NtResumeThread":
			groups[GROUP_GENERIC_THREAD] = true
		case "SetThreadContext", "NtSetContextThread":
			groups[GROUP_SET_THREAD_CONTEXT] = true
			//TODO other enumeration APIs ?
		case "CreateThread":
			groups[GROUP_CREATE_LOCAL_THREAD] = true
		case "CreateRemoteThread", "CreateRemoteThreadEx", "NtCreateThread", "NtCreateThreadEx":
			groups[GROUP_CREATE_REMOTE_THREAD] = true
			//TODO create fiber
		case "QueueUserAPC", "QueueUserAPC2", "NtQueueApcThread", "NtQueueApcThreadEx", "NtQueueApcThreadEx2":
			groups[GROUP_QUEUE_APC] = true
			//TODO token APIs
			//TODO wait for object, etc?
			//TODO SetWindowsHookEx
			//TODO SetWinEventHook?
			//TODO ShellExecute
			//TODO OpenThread
		case "OpenThread": //TODO add other options
			groups[GROUP_OPEN_THREAD] = true
			//TODO OpenProcessToken, OpenThreadToken
		case "OpenThreadToken": //TODO add other optiosn
			//TODO target thread + flags
		case "OpenProcessToken": //TODO add other optiosn
			//TODO target process + flags

			//TODO DuplicateToken, DuplicateHandle
			//TODO token impersonation APIs
		case "IsDebuggerPresent":
			groups[GROUP_GENERIC_EMPTY] = true
		}
	}
	// All options must belong to the same group
	if len(groups) != 1 {
		if len(groups) == 0 {
			return GROUP_UNKNOWN_API
		}
		return GROUP_INVALID_API_OPTIONS
	}
	for group, _ := range groups {
		return group
	}
	return GROUP_UNKNOWN_API
}

func GetConditionSets(group int) []Condition {
	var sets []Condition
	switch group {
	case GROUP_LOCAL_MEM_ALLOC:
		var alloc AllocFilter
		sets = append(sets, alloc)

	case GROUP_REMOTE_MEM_ALLOC:
		var (
			alloc  AllocFilter
			target ProcessFilter
		)
		sets = append(sets, alloc, target)

	case GROUP_LOCAL_MEM_PROTECT:
		var protect ProtectFilter
		sets = append(sets, protect)

	case GROUP_REMOTE_MEM_PROTECT:
		var (
			protect ProtectFilter
			target  ProcessFilter
		)
		sets = append(sets, protect, target)

	case GROUP_FILE_EVENT:
		var target FileFilter
		sets = append(sets, target)
	case GROUP_THREAD_CREATE:
	case GROUP_PROCESS_CREATE:
	case GROUP_PROCESS_OPEN:
	}
	return sets
}

func GetConditionSet(condition string) Condition {
	switch condition {

	}
}

func SnakeCaseToPascalCase(str string) string {
	parts := strings.Split(str, "_")
	for i, part := range parts {
		if part == "" {
			continue
		}
		runes := []rune(part)
		runes[0] = unicode.ToUpper(runes[0])
		parts[i] = string(runes)
	}
	return strings.Join(parts, "")
}

func (u UniversalConditions) Check(p *Process) bool {
	//? to check if remote thread is running this, you need to get tid
	var wantedParentFound bool
	//? parent needs to be one of these
	if len(u.Parent) == 0 {
		wantedParentFound = true
	}
	for _, parent := range u.Parent {
		if p.ParentPath == parent || filepath.Base(p.ParentPath) == parent {
			wantedParentFound = true
			break
		}
	}
	if !wantedParentFound {
		return false
	}

	//? parent cant be any of these
	for _, parent := range u.ParentNot {
		if p.ParentPath == parent || filepath.Base(p.ParentPath) == parent {
			return false
		}
	}

	//? check process filter
	if !u.Process.Check(p, nil) {
		return false
	}

	//? session id must be one of these
	for _, id := range u.SessionId {

	}

	//? session id cant be one of these
	for _, id := range u.SessionIdNot {

	}

	for _, user := range u.User {

	}

	for _, user := range u.UserNot {

	}

	return true
}

func (f GenericFlags) Check(p *Process, event Event) bool {
	var mask uint32
	flagParam := event.GetParameter("Flags")
	if len(flagParam.Buffer) > 0 {
		mask = binary.LittleEndian.Uint32(flagParam.Buffer)
	} else if len(f.Flags) > 0 || len(f.FlagsNot) > 0 {
		return false
	}

	// has to be one of these
	var flagFound bool
	for _, flag := range f.Flags {
		if mask&flag != 0 {
			flagFound = true
			break
		}
	}
	if !flagFound && len(f.Flags) > 0 {
		return false
	}

	// must not be one of these
	for _, flag := range f.FlagsNot {
		if mask&flag != 0 {
			return false
		}
	}
	return true
}

// only works for API
func (f GenericThread) Check(p *Process, event Event) bool {
	api := event.(ApiCallData)
	//TODO what is even needed here? theres not much to it... start routine etc are handled by the system already
}

// Method to implement Condition interface. Returns true if it passed filter.
// There are two different cases, whether its part of universal conditions or not:
// If this is part of universal filters, event must be nil, and the process in question will be host.
// If this is a component, event must not be nil, and the process in question will be the one being operated on.
func (f ProcessFilter) Check(p *Process, event Event) bool {
	//? Process structure provides everything necessary
	var nameFound bool
	if len(f.Name) == 0 {
		nameFound = true
	}
	for _, name := range f.Name {
		if name == filepath.Base(p.Path) || name == p.Path {
			nameFound = true
			break
		}
	}
	if !nameFound {
		return false
	}

	for _, name := range f.NameNot {
		if name == filepath.Base(p.Path) || name == p.Path {
			return false
		}
	}

	var pathFound bool
	if len(f.Path) == 0 {
		pathFound = true
	}
	for _, dir := range f.Path {
		if dir == filepath.Dir(p.Path) || dir == p.Path {
			pathFound = true
			break
		}
	}
	if !pathFound {
		return false
	}
	for _, dir := range f.Path {
		if dir == filepath.Dir(p.Path) || dir == p.Path {
			return false
		}
	}

	// if issigned is false, either is fine
	if f.IsSigned && !p.IsSigned {
		return false
	}

	if f.IsElevated && !p.IsElevated {
		return false
	}
	return true
}

// currently only API. in the future probably also callbacks or etw
func (f ThreadCreationFilter) Check(p *Process, event Event) bool {
	var mask uint32
	flagParam := event.GetParameter("Flags")
	if len(flagParam.Buffer) > 0 {
		mask = binary.LittleEndian.Uint32(flagParam.Buffer)
	} else if len(f.Flags) > 0 || len(f.FlagsNot) > 0 {
		return false
	}
	if event.GetEventType() == EVENT_API {
		api := event.(ApiCallData)
		// special case, others use flags for suspended
		if api.FuncName == "NtCreateThread" && f.CreateSuspended {
			csParam := event.GetParameter("CreateSuspended")
			if len(csParam.Buffer) > 0 {
				// NtCreateThread doesnt have any flags
				return binary.LittleEndian.Uint32(csParam.Buffer) != 0
			}
		}
	}

	if f.CreateSuspended {
		f.Flags = append(f.Flags, THREAD_CREATE_SUSPENDED)
	}
	var flagFound bool
	for _, flag := range f.Flags {
		if mask&flag != 0 {
			flagFound = true
			break
		}
	}
	if !flagFound && len(f.Flags) > 0 {
		return false
	}
	for _, flag := range f.FlagsNot {
		if mask&flag != 0 {
			return false
		}
	}
	return true
}

func (f ProcessCreationFilter) Check(p *Process, event Event) bool {
  // flags, FlagsNot
  var mask uint32
  flagParam := event.GetParameter("Flags")
  if len(flagParam.Buffer) > 0 {
    mask = binary.LittleEndian.Uint32(flagParam.Buffer)
  } else if len(f.Flags) > 0 || len(f.FlagsNot) > 0 {
    return false
  }
  var flagFound bool
  for _, flag := range f.Flags {
    if mask&flag != 0 {
      flagFound = true
      break
    }
  }
  if !flagFound && len(f.Flags) > 0 {
    return false
  }
  for _, flag := range f.FlagsNot {
    if mask&flag != 0 {
      return false
    }
  }

  // token used
  if tokenParam := event.GetParameter("Token"); len(tokenParam.Buffer) == 0 && f.TokenUsed {
    return false
  }
  // target, targetnot; base or full path
  var target string
  targetParam := event.GetParameter("Target")
  if len(targetParam.Buffer) > 0 {
    target = ReadAnsiStringValue(targetParam.Buffer)
  } else if len(f.Target) > 0 || len(f.TargetNot) > 0 {
    return false
  }
  var targetFound bool
  for _, t := f.Target {
    if target == t || filepath.Base(target) == t {
      targetFound = true
      break
    }
  }
  if !targetFound && len(f.Target) > 0 {
    return false
  }
  for _, t := f.TargetNot {
    if target == t || filepath.Base(target) == t {
      return false
    }
  }
  return true
}

func (f GetFnFilter) Check(p *Process, event Event) bool {
  fnParam := event.GetParameter("Function")
  var target string
  if len(fnParam.Buffer) > 0 {
    target = ReadAnsiStringValue(fnParam.Buffer)
  } else if len(f.Function) > 0 || len(f.FunctionNot) > 0 {
    return false
  }
  var fnFound bool
  for _, fn := range f.Function {
    if target == fn {
      fnFound = true
      break
    }
  }
  if !fnFound && len(f.Function) > 0 {
    return false
  }
  for _, fn := range f.FunctionNot {
    if target == fn {
      return false
    }
  }
  return true
}

func (f GetModuleFilter) Check(p *Process, event Event) bool {
  modParam := event.GetParameter("Module")
  var target string
  if len(modParam.Buffer) > 0 {
    target = ReadAnsiStringValue(modParam.Buffer)
  } else if len(f.Module) > 0 || len(f.ModuleNot) > 0 {
    return false
  }
  var modFound bool
  for _, mod := range f.Module {
    if target == mod || target == filepath.Base(mod) || filepath.Base(target) == mod {
      modFound = true
      break
    }
  }
  if !modFound && len(f.Module) > 0 {
    return false
  }
  for _, mod := range f.ModuleNot {
    if target == mod || target == filepath.Base(mod) || filepath.Base(target) == mod {
      return false
    }
  }
  return true
}

// Method to implement Condition interface. Returns true if it passed filter
func (f FileFilter) Check(p *Process, event Event) bool {
	//TODO check if it is API or file event. For file event you need to look up the events
	//? only filepath is needed
	fileEvent := event.(FileEventData)
	var foundName bool
	if len(f.Name) == 0 {
		foundName = true
	}

	//TODO: update for new nested directory design

	for _, name := range f.Name {
		if name == filepath.Base(fileEvent.Path) || name == fileEvent.Path {
			foundName = true
			break
		}
	}
	if !foundName {
		return false
	}

	for _, name := range f.NameNot {
		if name == filepath.Base(fileEvent.Path) || name == fileEvent.Path {
			return false
		}
	}

	var foundPath bool
	if len(f.Path) == 0 {
		foundPath = true
	}
	for _, path := range f.Path {
		if path == filepath.Dir(fileEvent.Path) || path == fileEvent.Path {
			foundPath = true
			break
		}
	}
	if !foundPath {
		return false
	}

	for _, path := range f.PathNot {
		if path == filepath.Base(fileEvent.Path) || path == fileEvent.Path {
			return false
		}
	}

	var foundExt bool
	if len(f.Extension) == 0 {
		foundExt = true
	}
	for _, ext := range f.Extension {
		if ext == filepath.Ext(fileEvent.Path) {
			foundExt = true
			break
		}
	}
	if !foundExt {
		return false
	}

	for _, ext := range f.ExtNot {
		if ext == filepath.Base(fileEvent.Path) {
			return false
		}
	}

	//TODO: check if magic matches extension

	return true
}

// Method to implement Condition interface. Returns true if it passed filter
func (f AllocFilter) Check(p *Process, event interface{}) bool {
	//? memory allocation apis should save protection, allocation type and size
	apiCall := event.(ApiCallData)
	var (
		size         uint64
		sizeFound    bool
		allocType    uint32
		typeFound    bool
		protection   uint32
		protectFound bool
	)
	for _, arg := range apiCall.args {
		switch arg.Name {
		case "Size", "SizeOfAlloc", "AllocSize":
			size = binary.LittleEndian.Uint64(arg.RawData)
			sizeFound = true
		case "Type", "AllocType", "AllocationType":
			allocType = ReadDWORDValue(arg.RawData)
			typeFound = true
		case "Protection":
			protection = ReadDWORDValue(arg.RawData)
			protectFound = true
		}
	}

	if sizeFound && (f.sizeMin > size || f.sizeMax < size) {
		return false
	}

	if protectFound {
		var isCorrectProtection bool
		if len(f.Protection) == 0 {
			isCorrectProtection = true
		}
		for _, p := range f.Protection {
			if protect&p != 0 {
				isCorrectProtection = true
				break
			}
		}
		if !isCorrectProtection {
			return false
		}

		for _, p := range f.ProtectionNot {
			if protect&p != 0 {
				return false
			}
		}
	}

	if typeFound && f.IsImageSection && (allocType&MEM_IMAGE) != 0 {
		return false
	}
}

// Method to implement Condition interface. Returns true if it passed filter
func (f ProtectFilter) Check(p *Process, event interface{}) bool {
	//? memory protection apis should save old protection and new protection
	apiCall := event.(ApiCallData)
	var (
		oldFound   bool
		newFound   bool
		oldProtect uint32
		newProtect uint32
	)

	for _, arg := range apiCall.args {
		switch arg.Name {
		case "OldProtect":
			oldProtect = ReadDWORDValue(arg.RawData)
			oldFound = true
		case "NewProtect":
			newProtect = ReadDWORDValue(arg.RawData)
			newFound = true
		}
	}

	if oldFound {
		var found bool
		for _, p := range f.OldProtection {
			if protect&p != 0 {
				found = true
				break
			}
		}
		if !found {
			return false
		}
		//TODO: OldProtectionNot
	}

	if newFound {
		var found bool
		for _, p := range f.NewProtection {
			if protect&p != 0 {
				found = true
				break
			}
		}
		if !found {
			return false
		}
		//TODO: NewProtectionNot
	}
}

// Method to implement Condition interface. Returns true if it passed filter
func (f HandleFilter) Check(p *Process, event interface{}) bool {
	//? only desired access is needed, but likely also target pid
	apiCall := event.(ApiCallData)
	var (
		pathFound     bool
		accessFound   bool
		targetPath    string
		desiredAccess uint32
	)

	for _, arg := range apiCall.args {
		switch arg.Name {
		case "TargetPath", "Path":
			targetPath = ReadAnsiStringValue(arg.RawData)
			pathFound = true
		case "TargetPid", "Pid":
			pid := ReadDWORDValue(arg.RawData)
			path, err := GetProcessExecutable(pid)
			if err != nil {
				red.Log("\n[!] Failed to get path of process %d\n\tError: %v\n", pid, err)
			} else {
				targetPath = path
				pathFound = true
			}
		case "DesiredAccess":
			desiredAccess = ReadDWORDValue(arg.RawData)
			accessFound
		}
	}

	if pathFound {
		var found bool
		if len(f.TargetPath) == 0 {
			found = true
		}
		for _, path := range f.TargetPath {

		}
		if !found {
			return false
		}
	}

	if accessFound {

	}
}

// Method to implement Condition interface. Returns true if it passed filter
func (f PTCreationFilter) Check(p *Process, event interface{}) bool {
	//? only creation flags are needed
}
