package main

const (
	GROUP_INVALID_API_OPTIONS = -1
	GROUP_UNKNOWN             = 0
	GROUP_FILE_EVENT          = 1
	GROUP_REG_EVENT           = 2
	GROUP_HANDLE_EVENT        = 3
	GROUP_GENERIC_EMPTY       = 4 // no conditions defined to describe this event
	GROUP_GENERIC_THREAD      = 5 // those that only take thread handle/id as parameter
	GROUP_GENERIC_PROCESS     = 6 // those that only take process handle/id as parameter
	GROUP_GENERIC_FLAGS       = 7 // uint32 flags
	GROUP_GENERIC_ADDRESS     = 8
	GROUP_GENERIC_NAME        = 9
	GROUP_MEM_ALLOC           = 10
	GROUP_MEM_PROTECT         = 11
	GROUP_REMOTE_MEM_OP       = 12
	GROUP_OPEN_PROCESS        = 13
	GROUP_CREATE_PROCESS      = 14
	GROUP_OPEN_THREAD         = 15
	GROUP_CREATE_THREAD       = 16
	GROUP_SET_THREAD_CONTEXT  = 17
	GROUP_QUEUE_APC           = 18

	GROUP_MODULE_OP        = 19
	GROUP_GET_FN_ADDRESS   = 20
	GROUP_TH32_SNAPSHOT    = 21
	GROUP_DUPLICATE_HANDLE = 22
	GROUP_DUPLICATE_TOKEN  = 23
	GROUP_TOKEN_PRIVILEGES = 24
	GROUP_OBJECT_WAIT      = 25
	GROUP_SET_WIN_HOOK     = 26
	GROUP_SHELL_EXECUTE    = 28
)

// Get the group this event belongs to. This is needed to implement Component interface
func (event FileComponent) GetGroup() int {
	return GROUP_FILE_EVENT
}

// Get the group this event belongs to. This is needed to implement Component interface
func (event RegComponent) GetGroup() int {
	return GROUP_REG_EVENT
}

func (event EtwComponent) GetGroup() int {
	return GetEtwGroup(event.Provider, event.EventId)
}

// Get the group this event belongs to. This is needed to implement Component interface
func (event HandleComponent) GetGroup() int {
	return GROUP_HANDLE_EVENT
}

// Get the group this event belongs to. This is needed to implement Component interface
func (event ApiComponent) GetGroup() int {
	return GetApiGroup(event.Options)
}

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
		// should you include heapalloc, globalalloc, etc?
		case "VirtualAlloc", "VirtualAllocEx", "VirtualAlloc2", "NtAllocateVirtualMemory", "NtAllocateVirtualMemoryEx":
			groups[GROUP_MEM_ALLOC] = true
		case "VirtualProtect", "VirtualProtectEx", "NtProtectVirtualMemory":
			groups[GROUP_MEM_PROTECT] = true
		case "OpenProcess", "NtOpenProcess":
			groups[GROUP_OPEN_PROCESS] = true
		case "CreateProcessA", "CreateProcessW", "CreateProcessAsUserA", "CreateProcessAsUserW", "NtCreateProcess", "NtCreateProcessEx", "NtCreateUserProcess": //TODO: add other options
			groups[GROUP_CREATE_PROCESS] = true
		case "LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "LoadLibraryExW", "LdrLoadDll":
			groups[GROUP_MODULE_OP] = true
		case "GetModuleHandleA", "GetModuleHandleW", "GetModuleHandleExA", "GetModuleHandleExW":
			groups[GROUP_MODULE_OP] = true
		case "GetProcAddress":
			groups[GROUP_GET_FN_ADDRESS] = true
		case "SetDefaultDllDirectories":
			groups[GROUP_GENERIC_FLAGS] = true
		case "GetThreadContext", "NtGetContextThread", "SuspendThread", "ResumeThread", "NtSuspendThread", "NtResumeThread":
			groups[GROUP_GENERIC_THREAD] = true
		case "NtSuspendProcess":
			groups[GROUP_GENERIC_PROCESS] = true
		case "SetThreadContext", "NtSetContextThread":
			groups[GROUP_SET_THREAD_CONTEXT] = true
		case "CreateThread", "CreateRemoteThread", "CreateRemoteThreadEx", "NtCreateThread", "NtCreateThreadEx":
			groups[GROUP_CREATE_THREAD] = true
		case "CreateFiber":
			groups[GROUP_GENERIC_ADDRESS] = true
		case "QueueUserAPC", "QueueUserAPC2", "NtQueueApcThread", "NtQueueApcThreadEx", "NtQueueApcThreadEx2":
			groups[GROUP_QUEUE_APC] = true
		case "AdjustTokenPrivileges":
			groups[GROUP_TOKEN_PRIVILEGES] = true
		case "WaitForSingleObject", "WaitForSingleObjectEx", "WaitForMultipleObjects", "WaitForMultipleObjectsEx", "MsgWaitForMultipleObjects", "MsgWaitForMultipleObjectsEx", "SignalObjectAndWait", "SleepEx", "WaitOnAddress":
			groups[GROUP_OBJECT_WAIT] = true
		case "SetWindowsHookExA", "SetWindowsHookExW", "SetWinEventHook":
			groups[GROUP_SET_WIN_HOOK] = true
		case "ShellExecuteA", "ShellExecuteW", "ShellExecuteExA", "ShellExecuteExW":
			groups[GROUP_SHELL_EXECUTE] = true
		case "OpenThread", "NtOpenThread":
			groups[GROUP_OPEN_THREAD] = true
		case "OpenThreadToken", "NtOpenThreadToken", "NtOpenThreadTokenEx":
			groups[GROUP_GENERIC_THREAD] = true
		case "OpenProcessToken", "NtOpenProcessToken", "NtOpenProcessTokenEx":
			groups[GROUP_GENERIC_PROCESS] = true
		case "DuplicateToken", "DuplicateTokenEx", "NtDuplicateToken":
			groups[GROUP_DUPLICATE_TOKEN] = true
		case "DuplicateHandle", "NtDuplicateObject":
			groups[GROUP_DUPLICATE_HANDLE] = true
		case "CreateToolhelp32Snapshot":
			groups[GROUP_TH32_SNAPSHOT] = true
		case "FindWindowA", "FindWindowW", "FindWindowExA", "FindWindowExW", "NtUserFindWindowEx":
			groups[GROUP_GENERIC_NAME] = true
			//TODO other enumeration APIs ?

		case "ReadProcessMemory", "NtReadVirtualMemory", "NtReadVirtualMemoryEx":
			// processfilter, addressfilter, readwritefilter, flagsfilter(ex)
			groups[GROUP_REMOTE_MEM_OP] = true
		case "WriteProcessMemory", "NtWriteVirtualMemory":
			// processfilter, addressfilter, readwritefilter
			groups[GROUP_REMOTE_MEM_OP] = true
		case "GetThreadDescription", "SetThreadDescription":
			groups[GROUP_GENERIC_THREAD] = true
			//TODO: maybe add some filters (regex, pattern matching, etc) for the description. also comparison if wstrlen is less than actually
		case "SetThreadExecutionState", "NtSetThreadExecutionState":
			groups[GROUP_GENERIC_FLAGS] = true
		}
		if ApiInGenericEmptyGroup(option) {
			groups[GROUP_GENERIC_EMPTY] = true
		}
	}
	// All options must belong to the same group
	if len(groups) > 1 {
		return GROUP_INVALID_API_OPTIONS
	}
	// cant access first element of map directly via index
	for group, _ := range groups {
		return group
	}
	return GROUP_UNKNOWN
}

func ApiInGenericEmptyGroup(api string) bool {
	switch api {
	case "Thread32First", "Thread32Next":
		return true
	case "Process32First", "Process32Next", "Process32FirstW", "Process32NextW":
		return true
	case "Module32First", "Module32Next", "Module32FirstW", "Module32NextW":
		return true
	case "IsDebuggerPresent":
		return true
	}
	return false
}

// Returns available conditions for specified group
func GetConditionSets(group int) []Condition {
	var sets []Condition
	switch group {
	case GROUP_FILE_EVENT:
		sets = append(sets, FileFilter{})
	case GROUP_REG_EVENT:
		sets = append(sets, RegistryFilter{})
	case GROUP_HANDLE_EVENT:
		sets = append(sets, HandleFilter{})
	case GROUP_GENERIC_FLAGS:
		sets = append(sets, GenericFlags{})
	case GROUP_GENERIC_ADDRESS:
		sets = append(sets, GenericAddress{})
	case GROUP_GENERIC_THREAD:
		sets = append(sets, GenericThread{}, ProcessFilter{})
	case GROUP_GENERIC_PROCESS:
		sets = append(sets, ProcessFilter{})
	case GROUP_GENERIC_NAME:
		sets = append(sets, GenericName{})
	case GROUP_MEM_ALLOC:
		sets = append(sets, AllocFilter{}, ProcessFilter{})
	case GROUP_MEM_PROTECT:
		sets = append(sets, ProtectFilter{}, ProcessFilter{})
	case GROUP_REMOTE_MEM_OP: // read / write
		sets = append(sets, ProcessFilter{}, GenericAddress{}, ReadWriteFilter{})
	case GROUP_OPEN_PROCESS:
		sets = append(sets, GenericAccess{}, ProcessFilter{})
	case GROUP_CREATE_PROCESS:
		sets = append(sets, ProcessCreationFilter{})
	case GROUP_OPEN_THREAD:
		sets = append(sets, GenericAccess{}, GenericThread{}, ProcessFilter{})
	case GROUP_CREATE_THREAD:
		sets = append(sets, ThreadCreationFilter{}, GenericAddress{})
	case GROUP_SET_THREAD_CONTEXT:
		sets = append(sets, GenericThread{}, GenericAddress{}, ProcessFilter{})
	case GROUP_QUEUE_APC:
		sets = append(sets, GenericThread{}, GenericAddress{}, GenericFlags{}, ProcessFilter{})
	case GROUP_MODULE_OP:
		sets = append(sets, ModuleFilter{})
	case GROUP_GET_FN_ADDRESS:
		sets = append(sets, GetFnFilter{})
	case GROUP_TH32_SNAPSHOT:
		sets = append(sets, GenericFlags{}, ProcessFilter{})
	case GROUP_DUPLICATE_HANDLE:
		sets = append(sets, HandleFilter{}, HandleDupFilter{}, ProcessFilter{})
	case GROUP_DUPLICATE_TOKEN:
		break // no conditions for now
	case GROUP_TOKEN_PRIVILEGES:
		sets = append(sets, TokenFilter{})
	case GROUP_SHELL_EXECUTE:
		sets = append(sets, ShellExecuteFilter{})
	case GROUP_OBJECT_WAIT:
		sets = append(sets, ObjectWaitFilter{})
	case GROUP_SET_WIN_HOOK:
		sets = append(sets, GenericFlags{}, GenericAddress{}, GenericThread{}, ProcessFilter{}) // flags filter is for the event id
	}
	return sets
}

func GetEtwGroup(provider string, eventId Bitmask) int {
	switch provider {
	case "Microsoft-Windows-Threat-Intelligence":
		switch eventId {
		case ETW_TI_QUEUE_APC:
			return GROUP_QUEUE_APC
		case ETW_TI_SET_THREAD_CONTEXT:
			return GROUP_SET_THREAD_CONTEXT
		case ETW_TI_SUSPEND_RESUME_THREAD, ETW_TI_SUSPEND_RESUME_THREAD2:
			return GROUP_GENERIC_THREAD
		case ETW_TI_SUSPEND_RESUME_PROCESS, ETW_TI_SUSPEND_RESUME_PROCESS2, ETW_TI_SUSPEND_RESUME_PROCESS3, ETW_TI_SUSPEND_RESUME_PROCESS4:
			return GROUP_GENERIC_PROCESS
		//TODO: mem alloc/protect/write/read ?
		default:
			return GROUP_UNKNOWN
		}
	}
	return GROUP_GENERIC_EMPTY
}
