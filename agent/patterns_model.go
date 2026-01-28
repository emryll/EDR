package main

//*==============================================================================================+
//*   			Experimental v2 behavioral pattern design								         |
//?==============================================================================================+
//?   These behavioral patterns are like a timeline of behavior, represented in YAML.		     |
//?   This timeline consists of components, which describe an arbitrary telemetry event.         |
//?   																						     |
//?   This design is aimed to be as flexible and extensible as possible. It should be able       |
//?   to precisely describe all kinds of behavior, and allow an efficient code implementation.   |
//?	 																						     |
//?   Patterns include a description of the behavior, a score describing how malicious           |
//?   it is, and optionally a timerange and additional conditions, which must match for all.     |
//?	 																						     |
//?   Components can define a list of possible options. You could for example describe a file    |
//?   creation event in any path from a (white)list, or any API function from a list of options. |
//?   Conditional filters, as described above also generally have a negative counterpart.        |
//?	 																						     |
//?   Components can be required, or a "bonus" component, and they can either be tied to a 	     |
//?   timeline, or not. In addition, you can set different kinds of conditions, for the entire   |
//?   pattern or specific components. For example you could say the behavior must be done by     |
//?   a specific type of process, or define specific details of an event to be more precise.     |
//?==============================================================================================+

type BehaviorPattern struct {
	Name                string
	Description         string
	Category            []string
	Severity            int
	Score               int
	TimeRange           int
	UniversalConditions *UniversalConditions
	Components          []Component
	Timeline            string
}

type Component interface {
	GetName() string
	GetGroup() int
	GetResult(p *Process) *ComponentResult // does this behavior appear in telemetry history (and conditions are ok)
	IsTimeSensitive() bool
	IsRequired() bool
	GetBonus() int
}

type ComponentMatch struct {
	Match      bool
	TimeStamps []int64
}

// this may be extended. Currently it's for condition checks.
type Event interface {
	GetEventType() int
	GetParameter(name string) Parameter
}

// This describes one event in the timeline. An api call specifically.
type ApiComponent struct {
	Name              string
	Options           []string
	Conditions        []Condition
	UniversalOverride *UniversalConditions
	TimeMatters       bool
	Bonus             int
}

// This describes one event in the timeline. A file system event specifically.
type FileComponent struct {
	Name              string
	Action            uint32
	Conditions        []Condition
	UniversalOverride *UniversalConditions
	TimeMatters       bool
	Bonus             int
}

// This describes one event in the timeline. A registry event specifically.
type RegComponent struct {
	Name              string
	Action            uint32
	Conditions        []Condition
	UniversalOverride *UniversalConditions
	TimeMatters       bool
	Bonus             int
}

type HandleComponent struct {
	Name              string
	Type              uint32
	Access            []uint32
	Conditions        []Condition
	UniversalOverride *UniversalConditions
	TimeMatters       bool
	Bonus             int
}

// this is a generic interface to describe a condition on a component.
// It allow you to define more complex and precise patterns
type Condition interface {
	Check(p *Process, event Event) bool
}

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

// condition set for generic 32-bit flags
type GenericFlags struct {
	Flags    []uint32 `yaml:"flags"`
	FlagsNot []uint32 `yaml:"flags_not"`
}

type GenericAccess struct {
	Access    []uint32 `yaml:"access"`
	AccessNot []uint32 `yaml:"access_not"`
}

// this is special case from generics flags because of the create suspended
type ThreadCreationFilter struct {
	Flags           []uint32 `yaml:"flags"`
	FlagsNot        []uint32 `yaml:"flags_not"`
	CreateSuspended Bool     `yaml:"create_suspended"`
}

// parent spoofing is not covered here, because it's an in-built mechanism, not reliant on patterns
type ProcessCreationFilter struct {
	Flags     []uint32 `yaml:"flags"`
	FlagsNot  []uint32 `yaml:"flags_not"`
	Target    []string `yaml:"path"`
	TargetNot []string `yaml:"path_not"`
	TargetDir []string `yaml:"dir"`
	DirNot    []string `yaml:"dir_not"`
	TokenUsed Bool     `yaml:"token_used"` // signifies a token was specified.
}

// "target_process" / "process" conditions
// This should only be for components operating on a process (remote alloc, process creation, etc.)
type ProcessFilter struct {
	Name       []string `yaml:"name"`
	NameNot    []string `yaml:"name_not"`
	Path       []string `yaml:"path"`
	PathNot    []string `yaml:"path_not"`
	Dir        []string `yaml:"dir"`
	DirNot     []string `yaml:"dir_not"`
	Integrity  []int    `yaml:"integrity"`
	IsSigned   Bool     `yaml:"is_signed"`
	IsElevated Bool     `yaml:"is_elevated"`
}

// "target_file" condition
// Describes a file being operated on => requires component to be file operation
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

// conditions for memory allocation only
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

// conditions for changing memory page protections
type ProtectFilter struct {
	OldProtection    []uint32 `yaml:"old_protect"`
	NewProtection    []uint32 `yaml:"new_protect"`
	OldProtectionNot []uint32 `yaml:"old_protect_not"`
	NewProtectionNot []uint32 `yaml:"new_protect_not"`
}

// specifically for GetProcAddress
type GetFnFilter struct {
	Function    []string `yaml:"function"`
	FunctionNot []string `yaml:"function_not"`
}

// GetModuleHandle, or LoadLibrary
type ModuleFilter struct {
	Module    []string `yaml:"module"`
	ModuleNot []string `yaml:"module_not"`
}

// Remote memory read or write
type ReadWriteFilter struct {
	// process filter additionally; not included here
	SizeMin uint64 `yaml:"size_min"`
	SizeMax uint64 `yaml:"size_max"`
	//might want to add a function to check if it points to certain module
}

type ApcFilter struct {
	//TODO:
	Flags    []uint32
	FlagsNot []uint32
	Unbacked Bool
}

type RegistryFilter struct {
	Path         []string `yaml:"path"`
	PathNot      []string `yaml:"path_not"`
	PathDir      []string `yaml:"dir"` // recursive version of path
	PathDirNot   []string `yaml:"dir_not"`
	ValueName    []string `yaml:"value_name"`
	ValueNameNot []string `yaml:"value_name_not"`
	//TODO: others?
}

type HandleFilter struct {
	Access        []uint32 `yaml:"access"`
	AccessNot     []uint32 `yaml:"access_not"`
	TargetPath    []string `yaml:"target_path"`     // only if thread or process
	TargetPathNot []string `yaml:"target_path_not"` // only if thread or process
	TargetDir     []string `yaml:"target_dir"`      // only if thread or process
	TargetDirNot  []string `yaml:"target_dir_not"`  // only if thread or process
}

// DuplicateToken
type TokenDupFilter struct {
	ImpersonationLevel    []uint32 // SECURITY_IMPERSONATION_LEVEL
	ImpersonationLevelNot []uint32
	//TODO: info about the token handle to be duplicated
}

type HandleDupFilter struct {
	Type    []uint32 // handle type
	TypeNot []uint32
}

// simple getter methods for Component interface
func (c ApiComponent) GetBonus() int {
	return c.Bonus
}

func (c ApiComponent) IsRequired() bool {
	return c.Bonus == 0
}

func (c FileComponent) GetBonus() int {
	return c.Bonus
}

func (c FileComponent) IsRequired() bool {
	return c.Bonus == 0
}

func (c RegComponent) GetBonus() int {
	return c.Bonus
}

func (c RegComponent) IsRequired() bool {
	return c.Bonus == 0
}

func (c HandleComponent) GetBonus() int {
	return c.Bonus
}

func (c HandleComponent) IsRequired() bool {
	return c.Bonus == 0
}

func (c HandleComponent) IsTimeSensitive() bool {
	return c.TimeMatters
}

func (c ApiComponent) GetName() string {
	return c.Name
}

func (c FileComponent) GetName() string {
	return c.Name
}

func (c RegComponent) GetName() string {
	return c.Name
}

func (c HandleComponent) GetName() string {
	return c.Name
}
