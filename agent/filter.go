package main

//?=================================================================================+
//?  This file contains all condition set definitions. The actual condition set     |
//?    checking functionality is implemented in conditions.go                       |
//?                                                                                 |
//?  It should be noted that components often use multiple condition sets;          |
//?   a single set is not necessarily expected to cover everything for a component, |
//?    in principle condition sets avoid overlap, to improve reusability.           |
//?=================================================================================+

// Conditions for an entire pattern, applying to each component.
type UniversalConditions struct {
	Parent    []string `yaml:"parent"`
	ParentNot []string `yaml:"parent_not"`
	//TODO: child
	Process *ProcessFilter `yaml:"host_process"`
	//IsRemote  	 bool
	//? ^for this one you need to implement calling thread collection into all telemetry packets (add tid field to header)
	SessionId    []uint32 `yaml:"session_id"`
	SessionIdNot []uint32 `yaml:"session_id_not"`
	User         []string `yaml:"user"`
	UserNot      []string `yaml:"user_not"`
}

// condition set for generic 32-bit values (flags)
type FlagsFilter struct {
	Flags    []Bitmask `yaml:"flags"`
	FlagsNot []Bitmask `yaml:"flags_not"`
}

// condition set for access masks.
// Effectively same as FlagsFilter but with different names
type AccessFilter struct {
	Access    []Bitmask `yaml:"access"`
	AccessNot []Bitmask `yaml:"access_not"`
}

// Generic condition set for any name string
type NameFilter struct {
	Name      []string `yaml:"name"`
	NameNot   []string `yaml:"name_not"`
	Suffix    []string `yaml:"suffix"`
	SuffixNot []string `yaml:"suffix_not"`
	Prefix    []string `yaml:"prefix"`
	PrefixNot []string `yaml:"prefix_not"`
	//TODO: add support for wildcards (*) in name
}

// Generic condition set for any memory address
type AddressFilter struct {
	MemoryType       []Bitmask `yaml:"mem_type"`
	MemoryTypeNot    []Bitmask `yaml:"mem_type_not"`
	MemoryProtect    []Bitmask `yaml:"mem_protect"`
	MemoryProtectNot []Bitmask `yaml:"mem_protect_not"`
	Unbacked         Bool      `yaml:"mem_unbacked"`
	LibraryLoad      Bool      `yaml:"load_library"`    // does address point to library load function
	InsideModuleText Bool      `yaml:"in_text_section"` // does address point outside valid module's .text
	InsideModule     []string  `yaml:"module"`          // does address point inside one of these modules
	InsideModuleNot  []string  `yaml:"module_not"`
}

// Condition set for anything involving a thread (id)
type ThreadFilter struct {
	Sleeping  Bool `yaml:"sleeping"`
	Suspended Bool `yaml:"suspended"`
	Remote    Bool `yaml:"remote"`
	// conditions for owner process are implemented in ProcessFilter
}

// Condition set for anything involving a process
type ProcessFilter struct {
	Name       []string `yaml:"name"`
	NameNot    []string `yaml:"name_not"`
	Path       []string `yaml:"path"`
	PathNot    []string `yaml:"path_not"`
	Dir        []string `yaml:"dir"`
	DirNot     []string `yaml:"dir_not"`
	ProcessId  []uint32 `yaml:"pid"`
	PidNot     []uint32 `yaml:"pid_not"`
	Integrity  []int    `yaml:"integrity"`
	IsSigned   Bool     `yaml:"is_signed"`
	IsElevated Bool     `yaml:"is_elevated"`
}

// Condition set for the creation of a thread.
type ThreadCreationFilter struct {
	Flags           []uint32 `yaml:"flags"`
	FlagsNot        []uint32 `yaml:"flags_not"`
	CreateSuspended Bool     `yaml:"create_suspended"`
	IsRemote        Bool     `yaml:"remote"`
}

// Condition set for the creation of a process.
// Parent spoofing is not covered here, because it's an in-built mechanism, not reliant on patterns
type ProcessCreationFilter struct {
	Flags     []uint32 `yaml:"flags"`
	FlagsNot  []uint32 `yaml:"flags_not"`
	Target    []string `yaml:"path"`
	TargetNot []string `yaml:"path_not"`
	TargetDir []string `yaml:"dir"`
	DirNot    []string `yaml:"dir_not"`
	TokenUsed Bool     `yaml:"token_used"` // signifies a token was specified.
}

// Condition set for any file involved in an event
type FileFilter struct {
	Path          []string `yaml:"path"`
	PathNot       []string `yaml:"path_not"`
	Dir           []string `yaml:"dir"`
	DirNot        []string `yaml:"dir_not"`
	Extension     []string `yaml:"extension"`
	ExtNot        []string `yaml:"extension_not"`
	IsSigned      Bool     `yaml:"is_signed"`
	HashMismatch  Bool     `yaml:"hash_mismatch"`
	IsUserPath    Bool     `yaml:"is_user_path"`
	HasScaryMagic Bool     `yaml:"has_scary_magic"`
	MagicMismatch Bool     `yaml:"magic_mismatch"`
}

// Condition set for registry operations
type RegistryFilter struct {
	Path         []string `yaml:"path"`
	PathNot      []string `yaml:"path_not"`
	PathDir      []string `yaml:"dir"` // recursive version of path
	PathDirNot   []string `yaml:"dir_not"`
	ValueName    []string `yaml:"value_name"`
	ValueNameNot []string `yaml:"value_name_not"`
	//TODO: others?
}

// Condition set for memory allocation
type AllocFilter struct {
	Protection    []uint32 `yaml:"protection"`
	ProtectionNot []uint32 `yaml:"protection_not"`
	AllocType     []uint32 `yaml:"alloc_type"`
	AllocTypeNot  []uint32 `yaml:"alloc_type_not"`
	IsRemoteAlloc Bool     `yaml:"remote_alloc"`
	SizeMin       int64    `yaml:"size_min"`
	SizeMax       int64    `yaml:"size_max"`
	//IsImageSection Bool     `yaml:"is_image_section"`
}

// Condition set for changing memory page protections
type ProtectFilter struct {
	OldProtection    []uint32 `yaml:"old_protect"`
	NewProtection    []uint32 `yaml:"new_protect"`
	OldProtectionNot []uint32 `yaml:"old_protect_not"`
	NewProtectionNot []uint32 `yaml:"new_protect_not"`
}

// Condition set for object handles
type HandleFilter struct {
	Access        []Bitmask `yaml:"access"`
	AccessNot     []Bitmask `yaml:"access_not"`
	TargetPath    []string  `yaml:"target_path"`     // only if thread or process
	TargetPathNot []string  `yaml:"target_path_not"` // only if thread or process
	TargetDir     []string  `yaml:"target_dir"`      // only if thread or process
	TargetDirNot  []string  `yaml:"target_dir_not"`  // only if thread or process
}

// Condition set for handle duplication
type HandleDupFilter struct {
	Type    []string `yaml:"type"`
	TypeNot []string `yaml:"type_not"`
	// access flags are a separate filter
}

// Condition set for read/write operations
type ReadWriteFilter struct {
	SizeMin uint64 `yaml:"size_min"`
	SizeMax uint64 `yaml:"size_max"`
}

// Condition set for win32 API wait operations
type ObjectWaitFilter struct {
	WaitMin   uint32 `yaml:"wait_min"`
	WaitMax   uint32 `yaml:"wait_max"`
	Alertable bool   `yaml:"alertable"`
}

// Condition set for ShellExecute APIs
type ShellExecuteFilter struct {
	Operation     []string `yaml:"operation"`
	OperationNot  []string `yaml:"operation_not"`
	FilePath      []string `yaml:"file"`
	FilePathNot   []string `yaml:"file_not"`
	FileDir       []string `yaml:"file_dir"`
	FileDirNot    []string `yaml:"file_dir_not"`
	Parameters    []string `yaml:"parameters"`
	ParametersNot []string `yaml:"parameters_not"`
	WorkingDir    []string `yaml:"working_dir"`
	WorkingDirNot []string `yaml:"working_dir_not"`
}

// Condition set for tokens (which rights are enabled/disabled)
type TokenFilter struct {
	Present     []string `yaml:"present"`
	PresentNot  []string `yaml:"not_present"`
	Enabled     []string `yaml:"enabled"`
	EnabledNot  []string `yaml:"not_enabled"`
	Disabled    []string `yaml:"disabled"`
	DisabledNot []string `yaml:"not_disabled"`
}

// Condition set specifically for GetProcAddress
type GetFnFilter struct {
	Function    []string `yaml:"function"`
	FunctionNot []string `yaml:"function_not"`
}

// Condition set for events dealing with modules (LoadLibrary, GetModuleHandle, etc.)
type ModuleFilter struct {
	Module    []string `yaml:"module"`
	ModuleNot []string `yaml:"module_not"`
}
