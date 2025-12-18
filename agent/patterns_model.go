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
	GetDefaultName() string            // fallback naming if pattern is missing a name and description
	IsMatch(p *Process) ComponentMatch // does this behavior appear in telemetry history (and conditions are ok)
	IsTimeSensitive() bool
	IsRequired() bool
	GetBonus() int
}

type ComponentMatch struct {
	Match      bool
	TimeStamps []int64
}

//TODO: Api, file and reg components can maybe be combined into one
// tbh probably cleaner this way because the methods have different logic anyways

// This describes one event in the timeline. An api call specifically.
type ApiComponent struct {
	Options           []string
	Conditions        []Condition
	UniversalOverride *UniversalConditions
	TimeMatters       bool
	Bonus             int
}

// This describes one event in the timeline. A file system event specifically.
type FileComponent struct {
	Action            uint32
	Conditions        []Condition
	UniversalOverride *UniversalConditions
	TimeMatters       bool
	Bonus             int
}

// This describes one event in the timeline. A registry event specifically.
type RegComponent struct {
	Action            uint32
	Name              []string
	NameNot           []string
	DirOptions        []string
	DirNot            []string
	KeyOptions        []string
	Conditions        []Condition
	UniversalOverride *UniversalConditions
	TimeMatters       bool
	Bonus             int
}

type HandleComponent struct {
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
	Check(p *Process, event interface{}) bool
	GetParameter(name string) Parameter
}

// "target_process" / "process" conditions
// This should only be for components operating on a process (remote alloc, process creation, etc.)
type ProcessFilter struct {
	Name       []string
	NameNot    []string
	Path       []string
	PathNot    []string
	Integrity  []int // which integrity levels are needed for a match (enums)
	IsSigned   bool
	IsElevated bool
}

// "target_file" condition
// Describes a file being operated on => requires component to be file operation
type FileFilter struct {
	PathNot       []string
	Extension     []string
	ExtNot        []string
	IsSigned      bool
	IsUserPath    bool // user writeable path, no elevated privileges needed
	HasScaryMagic bool // magic of an executable file format
	MagicMatch    bool
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
	IsImageSection bool
	IsRemoteAlloc  bool
}

// conditions for changing memory page protections
type ProtectFilter struct {
	OldProtection []uint32
	NewProtection []uint32
}

// for opening handle to thread or process
type PTHandleFilter struct {
	TargetPath       []string
	TargetPathNot    []string
	DesiredAccess    []uint32 // enums
	DesiredAccessNot []uint32
}

// for creating process or thread (seperate one for files/reg)
type PTCreationFilter struct {
	CreationFlags    []uint32 // enums
	CreationFlagsNot []uint32 // enums
}

//TODO: registry filter
// target path, target

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
