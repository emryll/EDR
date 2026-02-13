package main

import (
	"encoding/binary"
	"path/filepath"
	"strings"
	"unicode"

	"golang.org/x/sys/windows"
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

// To check if a given condition is allowed for a component, you would first figure out which group it
//  belongs to. After this you would check which set the condition belongs to, and then seeing if this set
//  is allowed to be used by the group. This is done by the syntax checker, to notify user of invalid use.
// Technically this could also maybe be done by just reading all the valid conditions and then seeing which ones were "left-over"

// I don't like this current implementation so much, it feels a bit hacky. It will be reworked in future versions.

// shorthand name for a set of api functions. for example "mem_alloc"
// these are read from a config file on disk at startup, into a map for easy lookup.
type ApiShorthand struct {
	Name    string
	Group   string
	Options map[string]bool
}
//*=======================================[ Condition set checks ]===========================================

//TODO
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

func (f FlagsFilter) Check(p *Process, event Event) bool {
	var mask uint32
	flagParam := event.GetParameter("Flags")
	if len(flagParam.Buffer) > 0 {
		mask = binary.LittleEndian.Uint32(flagParam.Buffer)
	} else if len(f.Flags) > 0 || len(f.FlagsNot) > 0 {
		return false
	}

	if !CheckBitmaskFilter(mask, f.Flags, f.FlagsNot) {
		return false
	}
	return true
}

func (f AccessFilter) Check(p *Process, event Event) bool {
	var mask uint32
	accessParam := event.GetParameter("Access")
	if len(accessParam.Buffer) > 0 {
		mask = binary.LittleEndian.Uint32(accessParam.Buffer)
	} else if len(f.Access) > 0 || len(f.AccessNot) > 0 {
		return false
	}

	if !CheckBitmaskFilter(mask, f.Access, f.AccessNot) {
		return false
	}
	return true
}

func (f AddressFilter) Check(p *Process, event Event) bool {
	//TODO
}

func (f NameFilter) Check(p *Process, event Event) bool {
	//TODO
}

// Method to implement Condition interface. Returns true if it passed filter
func (f FileFilter) Check(p *Process, event Event) bool {
	var path string
	switch event.GetEventType() {
	case TM_TYPE_FILE_EVENT:
		fileEvent := event.(FileEvent)
		path = fileEvent.Path
	case TM_TYPE_API_CALL:
		pathParam := event.GetParameterWithOptions("FilePath", "TargetPath", "Path")
		if len(pathParam.Buffer) == 0 && (len(f.Path) > 0 || len(f.PathNot) > 0
		|| len(f.Dir) > 0 || len(f.DirNot) > 0 || len(f.Extension) > 0 || len(f.ExtNot) > 0) {
			return false
		}
		path = ReadAnsiStringValue(pathParam.Buffer)
	default:
		return true // shouldnt be used on others
	}

	if !CheckPathFilter(path, f.Path, f.PathNot, false) {
		return false
	}
	if !CheckPathFilter(path, f.Name, f.NameNot, true) {
		return false
	}
	if !CheckDirFilter(path, f.Dir, f.DirNot) {
		return false
	}

	var foundExt bool
	if len(f.Extension) == 0 {
		foundExt = true
	}
	for _, ext := range f.Extension {
		if ext == filepath.Ext(path) {
			foundExt = true
			break
		}
	}
	if !foundExt {
		return false
	}

	for _, ext := range f.ExtNot {
		if ext == filepath.Ext(path) {
			return false
		}
	}

	if f.IsSigned.IsSet() || f.HashMismatch.IsSet() {
		status, err := IsSignatureValid(path)
		if err != nil {
			red.Log("[ERROR] ")
			white.Log("Failed to inspect file signature of %s: %v\n", path, err)
		} else {
			if f.IsSigned.True() != (status == HAS_SIGNATURE) {
				return false
			}
			if f.HashMismatch.True() != (status == HASH_MISMATCH) {
				return false
			}
		}
	}

	if f.IsUserPath.IsSet() && f.IsUserPath.True() != IsUserWriteable(path) {
		return false
	}

	var magic Magic
	if f.HasScaryMagic.IsSet() || f.MagicMismatch.IsSet() {
		magic, err = FetchMagic(path)
		if err != nil {
			red.Log("[ERROR] ")
			white.Log("Failed to get magic of %s: %v\n", path, err)
		}
	}

	if f.HasScaryMagic.IsSet() && magic.NotEmpty() {
		if f.HasScaryMagic.True() != (magic.HasScaryMagic() || hasExecutableExtension(path)) {
			return false
		}
	}
	if f.MagicMismatch.IsSet() && magic.NotEmpty() && f.MagicMismatch.True() != magic.MagicMismatch(path) {
		return false
	}
	return true
}

func (f RegistryFilter) Check(p *Process, event Event) bool {
	var path string
	if regEvent, ok := event.(RegistryEvent); !ok {
		pathParam := event.GetParameterWithOptions("Path", "KeyPath", "TargetPath")
		if len(pathParam.Buffer) == 0 {
			if len(f.Path) > 0 || len(f.PathNot) > 0 || len(f.PathDir) > 0 || len(f.PathDirNot) > 0 {
				return false
			}
		} else {
			path = ReadAnsiStringValue(pathParam.Buffer)
		}
	} else {
		path = regEvent.Path
	}

	if (path != "" && !CheckPathFilter(path, f.Path, f.PathNot, false)) {
		return false
	}
	if (path != "" && !CheckDirFilter(path, f.PathDir, f.PathNot)) {
		return false
	}

	var valName string
	valParam := event.GetParameterWithOptions("ValueName", "Value")
	if len(valParam.Buffer) > 0 {
		valName = ReadAnsiStringValue(valParam.Buffer)
	} else if len(f.ValueName) > 0 || len(f.ValueNameNot) > 0 {
		return false
	}
	if valName != "" && !CheckPathFilter(valName, f.ValueName, f.ValueNameNot, false) {
		return false
	}
	return true
}

// There are two different cases: inspecting host process (p), or target process.
// In practice, inspecting the host process only happens in the universal conditions,
// for it, you must pass event as nil. In the case of inspecting a target process,
// event must not be nil, and it must have a TargetPid parameter, with the targets pid.
func (f ProcessFilter) Check(p *Process, event Event) bool {
	var (
		path 	   string
		pid 	   uint32
		err 	   error
		isSigned   bool
		isElevated bool
		integrity  int
	)
	//* Start by getting the process path
	if event != nil {
		if pidParam := event.GetParameter("TargetPid"); len(pidParam.Buffer) > 0 {
			pid = binary.LittleEndian.Uint32(pidParam.Buffer)
			path, err = GetProcessExecutable(pid)
			if err != nil {
				red.Log("[ERROR] ")
				white.Log("Failed to get process executable of process %d: %v\n", pid, err)
				if len(f.Name) > 0 || len(f.NameNot) > 0 || len(f.Path) > 0 || len(f.PathNot) > 0 ||
				len(f.Integrity) > 0 || f.IsSigned.IsSet() || f.IsElevated.IsSet() {
					return false
				}
				return true
			}
			hProcess, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION, false, pid)
			if err != nil {
				red.Log("[ERROR] ")
				white.Log("Failed to open handle to process %d: %v\n", pid, err)
				white.Log("[info] Using default values on process %d in process filter check.\n", pid)
			} else {
				elev8d := C.IsProcessElevated(uintptr(hProcess))
				if elev8d == C.int(1) {
					IsElevated = true
				}
				integr := C.GetProcessIntegrityLevel(uintptr(hProcess))
				integrity = int(integr)
			}
		} else if len(f.Name) > 0 || len(f.NameNot) > 0 || len(f.Path) > 0 || len(f.PathNot) > 0 ||
		len(f.Integrity) > 0 || f.IsSigned.IsSet() || f.IsElevated.IsSet() {
			return false
		} else {
			return true
		}
	} else {
		pid 	   = p.ProcessId
		path 	   = p.Path
		isSigned   = p.IsSigned
		isElevated = p.IsElevated
		integrity  = int(p.Integrity)
	}

	//* check path conditions
	if !CheckPathFilter(path, f.Name, f.NameNot, true) {
		return false
	}
	if !CheckPathFilter(path, f.Path, f.PathNot, false) {
		return false
	}
	if !CheckDirFilter(path, f.Dir, f.DirNot, false) {
		return false
	}

	//* check pid conditions
	var pidFound bool
	for _, id := range f.ProcessId {
		if id == pid {
			pidFound = true
			break
		}
	}
	if !pidFound && len(f.ProcessId) > 0 {
		return false
	}
	for _, id := range f.PidNot {
		if id == pid {
			return false
		}
	}

	//* check process integrity conditions
	var found bool
	for _, val := range integrity {
		if integrity == val {
			found = true
			break
		}
	}
	if !found && len(f.Integrity) > 0 {
		return false
	}

	//* check process attribute conditions
	if f.IsSigned.IsSet() && f.IsSigned.True() != isSigned {
		return false
	}

	if f.IsElevated.IsSet() && f.IsElevated.True() != isElevated {
		return false
	}
	return true
}

func (f ThreadFilter) Check(p *Process, event Event) bool {
	//TODO: is the thread remote? owner different than p(caller)
	//TODO: is the thread sleeping?
	//TODO: is the thread suspended?
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
				r := binary.LittleEndian.Uint32(csParam.Buffer)
				if r == 1 {
					mask |= windows.THREAD_CREATE_SUSPENDED
				}
			}
		}
	}

	if f.CreateSuspended { // this condition can be set with the boolean or as flag
		f.Flags = append(f.Flags, windows.THREAD_CREATE_SUSPENDED)
	}
	//TODO: check is remote
	if !CheckBitmaskFilter(mask, f.Flags, f.FlagsNot) {
		return false
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
	if !CheckBitmaskFilter(mask, f.Flags, f.FlagsNot) {
		return false
	}

  	// token used
  	tokenParam := event.GetParameter("Token") 
	if len(tokenParam.Buffer) == 0 && f.TokenUsed.True() {
    	return false
	} else if f.TokenUsed.True() != binary.LittleEndian.Uint32(tokenParam.Buffer) == 1 {
		return false
	}

  // target, targetnot; base or full path
  var path string
  targetParam := event.GetParameterWithOptions("Target", "TargetPath")
  if len(targetParam.Buffer) > 0 {
    path = ReadAnsiStringValue(targetParam.Buffer)
  } else if len(f.Target) > 0 || len(f.TargetNot) > 0 {
    return false
  }
  if !CheckPathFilter(path, f.Target, f.TargetNot) {
	return false
  }
  if !CheckDirFilter(path, f.TargetDir, f.DirNot) {
	return false
  }
  return true
}

func (f ReadWriteFilter) Check(p *Process, event Event) bool {
	sizeParam := event.GetParameter("Size")
	if len(size.Buffer) == 0 && (f.SizeMin != 0 || f.SizeMax != 0) {
		return false
	} else {
		size := binary.LittleEndian.Uint64(sizeParam.Buffer)
		if f.SizeMin != 0 && f.SizeMin > size {
			return false
		}
		if f.SizeMax != 0 && f.SizeMax < size {
			return false
		}
	} 
	return true
}

// Method to implement Condition interface. Returns true if it passed filter
func (f AllocFilter) Check(p *Process, event Event) bool {
	//? memory allocation apis should save protection, allocation type and size
	if apiCall, ok := event.(ApiCallData); !ok {
		return false
	}
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
		case "Size", "AllocSize", "SizeOfAlloc":
			size = binary.LittleEndian.Uint64(arg.RawData)
			sizeFound = true
		case "Type", "AllocType", "AllocationType":
			allocType = ReadDWORDValue(arg.RawData)
			typeFound = true
		case "Protection", "Protect":
			protection = ReadDWORDValue(arg.RawData)
			protectFound = true
		}
	}

	if sizeFound && (f.sizeMin > size || f.sizeMax < size) {
		return false
	}
	if protectFound && !CheckBitmaskFilter(protect, f.Protection, f.ProtectionNot){
		return false
	}
	if typeFound {
		if !CheckBitmaskFilter(allocType, f.AllocType, f.AllocTypeNot) {
			return false
		}
		if f.IsImageSection.IsSet() && f.IsImageSection.True() != ((allocType&MEM_IMAGE) != 0) {
			return false
		} 
	}
	return true
}

// Method to implement Condition interface. Returns true if it passed filter
func (f ProtectFilter) Check(p *Process, event Event) bool {
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

	if !CheckBitmaskFilter(oldProtect, f.OldProtection, f.OldProtectionNot) {
		return false
	}
	if !CheckBitmaskFilter(newProtect, f.NewProtection, f.NewProtectionNot) {
		return false
	}
	return true
}

// Method to implement Condition interface. Returns true if it passed filter
func (f HandleFilter) Check(p *Process, event Event) bool {
	var (
		pathFound     bool
		accessFound   bool
		targetPath    string
		desiredAccess uint32
	)
	switch event.GetEventType() {
	case TM_TYPE_API_CALL:
		apiCall := event.(ApiEvent)
		for arg, val := range apiCall.Parameters {
		switch arg {
		case "TargetPath", "Path":
			if !pathFound { // if pid was found, thats the one
				targetPath = ReadAnsiStringValue(arg.RawData)
				pathFound = true
			}
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
	case EVENT_TYPE_HANDLE:
		handle := event.(HandleEntry)
		desiredAccess = handle.Access
		accessFound = true
		if handle.Type == OBJECT_TYPE_PROCESS {
			path, err := handle.GetPathFromProcessHandle()
			if err != nil {
				red.Log("[ERROR] ")
				white.Log("%v\n", err)
			} else {
				pathFound = true
				targetPath = path
			}
		} else if handle.Type == OBJECT_TYPE_THREAD {
			path, err := handle.GetPathFromThreadHandle()
			if err != nil {
				red.Log("[ERROR] ")
				white.Log("%v\n", err)
			} else {
				pathFound = true
				targetPath = path
			}
		}

	default: // shouldnt be used on others
		return true
	}

	if !accessFound && (len(f.Access) > 0 || len(f.AccessNot) > 0) {
		return false
	}
	if !pathFound && (len(f.TargetPath) > 0 || len(f.TargetPathNot) > 0) {
		return false
	}

	// Check handle access conditions
	if !CheckBitmaskFilter(desiredAccess, f.Access, f.AccessNot) {
		return false
	}
	// Check target path conditions
	if !CheckPathFilter(targetPath, f.TargetPath, f.TargetPathNot, true) {
		return false
	}
	// Check target dir conditions
	if !CheckPathFilter(targetPath, f.TargetDir, f.TargetDirNot, true) {
		return false
	}
	return true
}

func (f GetFnFilter) Check(p *Process, event Event) bool {
	var target string
	if fnParam := event.GetParameter("Function"); len(fnParam.Buffer) > 0 {
		target = ReadAnsiStringValue(fnParam.Buffer)
	} else if len(f.Function) > 0 || len(f.FunctionNot) > 0 {
		PrintError(fmt.Errorf("Failed to check function condition set: no event parameter found with function name"))
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

func (f ModuleFilter) Check(p *Process, event Event) bool {
	var target string
	if modParam := event.GetParameterWithOptions("Module", "Library"); len(modParam.Buffer) > 0 {
		target = ReadAnsiStringValue(modParam.Buffer)
	} else if len(f.Module) > 0 || len(f.ModuleNot) > 0 {
		PrintError(fmt.Errorf("Failed to check module condition set: no event parameter with module name found"))
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

func (f HandleDupFilter) Check(p *Process, event Event) bool {
	if typeParam := event.GetParameterWithOptions("Type", "ObjectType", "HandleType"); len(typeParam.Buffer) == 0 {
		PrintError(fmt.Errorf("Failed to check handle duplication condition set: no event parameter found for object type", typeParam.Type))
		return false
	}
	var objectType string
	if typeParam.Type == PARAMETER_ANSISTRING {
		objectType = ReadAnsiStringValue(typeParam.Buffer)
	} else if typeParam.Type == PARAMETER_UINT32 {
		objectType = GetObjectTypeName(binary.LittleEndian.Uint32(typeParam.Buffer))
	} else {
		PrintError(fmt.Errorf("Failed to check handle duplication condition set: object type parameter has unexpected type (%d)", typeParam.Type))
		return false
	}
	return CheckStringFilter(objectType, f.Type, f.TypeNot)
}
/*
func (f TokenFilter) Check(p *Process, event Event) bool {
	if len(f.Present) == 0 && len(f.PresentNot) == 0 &&
		len(f.Enabled) == 0 && len(f.EnabledNot) == 0 &&
		len(f.Disabled) == 0 && len(f.DisabledNot) == 0 {
			return true
	}
	//TODO: how do you get the token handle...
	//TODO: event should pass the handle and owner event or something,
	//TODO:  so it could be duplicated here in agent process

	var count C.size_t
	cToken := C.GetTokenPrivileges(hToken, &count)
	if cToken != nil || count == 0 {
		//TODO: raise runtime error
		return false
	}
	token := unsafe.Slice((*TokenInfo)(unsafe.Pointer(cToken)), int(count))

	//TODO: check present rights
	//TODO: check enabled rights
	//TODO: check disabled rights
}*/

func (f ShellExecuteFilter) Check(p *Process, event Event) bool {
	var (
		path string
		operation string
		parameters string
		workingDir string
	)
	if pathParam := event.GetParameter("TargetFile", "TargetPath", "FilePath"); len(pathParam.Buffer) > 0 {
		path = ReadAnsiStringValue(pathParam.Buffer)
	} else if len(f.FilePath) > 0 || len(f.FilePathNot) > 0 || len(f.FileDir) > 0 || len(f.FileDirNot) > 0 {
		PrintError(fmt.Errorf("Failed to check condition set for shell execute: no event parameter found with target file"))
		return false
	}
	if !CheckPathFilter(path, f.FilePath, f.FilePathNot, true) {
		return false
	}
	if !CheckDirFilter(path, f.FileDir, f.FileDirNot) {
		return false
	}

	if opParam := event.GetParameter("Operation"); len(opParam.Buffer) > 0 {
		operation = ReadAnsiStringValue(opParam.Buffer)
	} else if len(f.Operation) > 0 || len(f.OperationNot) > 0 {
		PrintError(fmt.Errorf("Failed to check condition set for shell execute: no event parameter found with operation"))
		return false
	}
	if !CheckStringFilter(operation, f.Operation, f.OperationNot) {
		return false
	}

	if paramsParam := event.GetParameter("Parameters"); len(paramsParam.Buffer) > 0 {
		parameters = ReadAnsiStringValue(paramsParam.Buffer)
	} else if len(f.Parameters) > 0 || len(f.ParametersNot) > 0 {
		PrintError(fmt.Errorf("Failed to check condition set for shell execute: no event parameter found with file parameters"))
		return false
	} 
	if !CheckStringFilter(parameters, f.Parameters, f.ParametersNot) {
		return false
	}

	if wdirParam := event.GetParameterWithOptions("Directory", "WorkingDirectory", "CurrentDirectory"); len(wdirParam.Buffer) > 0 {
		workingDir = ReadAnsiStringValue(wdirParam.Buffer)
	} else if len(f.WorkingDir) > 0 || len(f.WorkingDirNot) > 0 {
		PrintError(fmt.Errorf("Failed to check condition set for shell execute: no event parameter found with working directory"))
		return false
	}
	if !CheckStringFilter(workingDir, f.WorkingDir, f.WorkingDirNot) {
		return false
	}
	return true
}

func (f ObjectWaitFilter) Check(p *Process, event Event) bool {
	var (
		alertable bool
		wait uint32
	)
	if alertableParam := event.GetParameter("Alertable"); len(alertableParam.Buffer) > 0 {
		if binary.LittleEndian.Uint32(alertableParam.Buffer) == 1 {
			alertable = true
		}
	} 
	if waitParam := event.GetParameterWithOptions("Wait", "Timeout", "Limit"); len(waitParam.Buffer) > 0 {
		wait = binary.LittleEndian.Uint32(waitParam.Buffer)
	} else if f.WaitMin > 0 || f.WaitMax > 0 {
		PrintError(fmt.Errorf("Failed to check ObjectWait Condition set: no wait timeout parameter found in event"))
		return false
	}
	if f.Alertable.IsSet() && f.Alertable.True() != alertable {
		return false
	}
	// checking that wait is positive, because -1 means infinite
	if (wait > 0 && wait < f.WaitMin) || (f.WaitMax > 0 && wait > f.WaitMax) {
		return false
	}
	return true
}

//*=================================[ Generic utils ]=========================================

func CheckBitmaskFilter(mask uint32, wanted []uint32, denied []uint32) bool {
	var found bool
	for _, flag := range wanted {
		if mask&flag != 0 {
			found = true
			break
		}
	}
	if !found && len(wanted) > 0 {
		return false
	} 

	for _, flag := range denied {
		if mask&flag != 0 {
			return false
		}
	}
	return true
}

// Name parameter defines if you want to also allow filename matches in addition to full path matches.
func CheckPathFilter(path string, wanted []string, denied []string, name bool) bool {
	var found bool
	for _, p := range wanted {
		if path == p {
			found = true
			break
		}
		if name && filepath.Base(path) == p {
			found = true
			break
		}
	}
	if !found && len(wanted) > 0 {
		return false
	}
	
	for _, p := range denied {
		if path == p {
			return false
		}
		if name && filepath.Base(path) == p {
			return false
		}
	}
	return true
}

func CheckDirFilter(path string, wanted []string, denied []string) bool {
	var found bool
	for _, dir := range wanted {
		if dir == filepath.Dir(path) {
			found = true
			break
		}
	}
	if !found && len(wanted) > 0 {
		return false
	}
	for _, dir := range denied {
		if dir == filepath.Dir(path) {
			return false
		}
	}
	return true
}

func CheckStringFilter(str string, wanted []string, denied []string) bool {
	var found bool
	for _, s := range wanted {
		if str == s {
			found = true
			break
		}
	}
	if !found && len(wanted) > 0 {
		return false
	}
	for _, s := range denied {
		if str == s {
			return false
		}
	}
	return true
}