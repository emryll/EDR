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
	Parent    []string
	ParentNot []string
	Process   *ProcessFilter
	//IsRemote  	 bool
	//? ^for this one you need to implement calling thread collection into all telemetry packets (add tid field to header)
	SessionId    []uint32
	SessionIdNot []uint32
	User         []string
	UserNot      []string
}

// condition set for generic 32-bit flags
type GenericFlags struct {
	Flags    []uint32 // flags
	FlagsNot []uint32 // flags_not
}

type GenericAccess struct {
	Access    []uint32 // access
	AccessNot []uint32 // access_not
}

// this is special case from generics flags because of the create suspended
type ThreadCreationFilter struct {
	Flags           []uint32 // flags
	FlagsNot        []uint32 // flags_not
	CreateSuspended bool     // create_suspended. could be flag or bool with NtCreateThread
}

// parent spoofing is not covered here, because it's an in-built mechanism, not reliant on patterns
type ProcessCreationFilter struct {
	Flags     []uint32
	FlagsNot  []uint32
	Target    []string
	TargetNot []string
	TokenUsed Bool // token_used. signifies a token was specified.
}

// "target_process" / "process" conditions
// This should only be for components operating on a process (remote alloc, process creation, etc.)
type ProcessFilter struct {
	Name       []string
	NameNot    []string
	Path       []string
	PathNot    []string
	Dir        []string
	DirNot     []string
	Integrity  []int // which integrity levels are needed for a match (enums)
	IsSigned   Bool
	IsElevated Bool
}

//TODO
// "target_file" condition
// Describes a file being operated on => requires component to be file operation
type FileFilter struct {
	Path          []string
	PathNot       []string
	Dir           []string
	DirNot        []string
	Extension     []string
	ExtNot        []string
	IsSigned      Bool
	HashMismatch  Bool
	IsUserPath    Bool // user writeable path, no elevated privileges needed
	HasScaryMagic Bool // magic of an executable file format
	MagicMismatch Bool
}

//TODO
// conditions for memory allocation only
type AllocFilter struct {
	SizeMin        int64
	SizeMax        int64
	Protection     []uint32 // enums
	ProtectionNot  []uint32
	AllocType      []uint32
	AllocTypeNot   []uint32
	TargetPath     []uint32
	TargetPathNot  []uint32
	IsImageSection Bool
	IsRemoteAlloc  Bool
}

//TODO
// conditions for changing memory page protections
type ProtectFilter struct {
	OldProtection []uint32
	NewProtection []uint32
}

// specifically for GetProcAddress
type GetFnFilter struct {
	Function    []string
	FunctionNot []string
}

// GetModuleHandle, or LoadLibrary
type ModuleFilter struct {
	Module    []string
	ModuleNot []string
}

//TODO
// Remote memory read or write
type RemoteMemRwFilter struct {
	// process filter additionally; not included here
	SizeMin uint64
	SizeMax uint64
	//might want to add a function to check if it points to certain module
}

// for creating process or thread (seperate one for files/reg)
type PTCreationFilter struct {
	CreationFlags    []uint32 // enums
	CreationFlagsNot []uint32 // enums
}

type RegistryFilter struct {
	Path         []string
	PathNot      []string
	PathDir      []string // recursive version of path
	PathDirNot   []string
	ValueName    []string
	ValueNameNot []string
	//TODO: others?
}

type HandleFilter struct {
	Access        []uint32
	AccessNot     []uint32
	TargetPath    []string // only if thread or process
	TargetPathNot []string // only if thread or process
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
