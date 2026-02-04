package main

import (
	"bytes"
	"io"
	"sync"
	"unsafe"

	"github.com/fatih/color"
)

const VERSION = "0.0.1-demo"

type Process struct {
	Path           string
	ProcessId      uint32
	ParentPid      uint32
	ParentPath     string
	IsSigned       bool
	IsElevated     bool
	Integrity      uint32
	StaticScanDone bool // represents the first static scan to avoid unnecessary extra scans. might also want a file scan history
	Score          Score
	ApiMu          sync.Mutex
	// this is collected telemetry data history
	APICalls map[string]*ApiEvent // key: api call name
	// to make behavioral patterns more flexible, file events are organized into directories,
	// so this will point to a directory map, which has all the files. key is the filename
	FileEvents FileTelemetryCatalog
	RegEvents  RegTelemetryCatalog
	// these are the matched patterns that make up the total score
	PatternMatches map[string]PatternMatch // key: name of pattern
	LastHeartbeat  int64                   // telemetry dll heartbeat
}

type RegTelemetryCatalog struct {
	RegPathTree   map[string][]*RegistryEvent // path
	RegActionTree map[int][]*RegistryEvent    // action
}

type FileTelemetryCatalog struct {
	FilePathTree   map[string]map[string]map[int]*FileEvent // map[dir]map[filename]map[action]
	FileActionTree map[int][]*FileEvent                     // search by action
}

type Score struct {
	Mu          sync.Mutex
	TotalScore  int
	StaticScore int
	RansomScore int
}

// This is the universal result type for portraying multiple matches from a single scan.
// The Log method should be called always after receiving Result from a function,
// it will handle logging/printing and saving matches to Process structure.
type Result struct {
	TotalScore int
	Results    []StdResult
}

// wrapper to allow for "timeline reconstruction". This is how matches should be stored
type PatternMatch struct {
	Result *StdResult
	Events []Event
	Pid    uint32
}

// universal type for portraying results. Portrays a matched pattern: YARA, static, behavioral
type StdResult struct {
	Name        string   // short name of pattern
	Description string   // what the pattern match means
	Tag         string   // to help portray results; for example "imports"
	Category    []string // for example "evasion"; describes what sort of pattern it was
	Score       int      // actual score for how likely its malicious
	Severity    int      // 0, 1, 2 (low, medium, high); only for colors, doesnt affect anything else
	Count       int      // how many times this has appeared
	TimeStamp   int64    // time of latest occurance
}

// embedded for custom log method
type Color struct {
	*color.Color
}

// Structure describing logger config
type DualWriter struct {
	file   io.Writer
	stdout io.Writer
	print  bool
}

// representation of a scan task for the scheduler and workers
type Scan struct {
	Pid  int
	Type int
	Arg  string
}

// representation of a cli command, for the help function
type CliCommand struct {
	Syntax      string
	Description string
}

// representation of an API call seen as potentially malicious
type MalApi struct {
	Name     string   `json:"name"`
	Severity int      `json:"severity"`
	Score    int      `json:"score"`
	Tag      []string `json:"tag"`
}

// Describe results of a hash lookup originating from malwarebazaar
type HashLookup struct {
	Sha256 string
	Status string `json:"query_status"` // ok / hash_not_found
	Data   []struct {
		Signature string   `json:"signature"`
		Tags      []string `json:"tags"`
		YaraRules []struct {
			Name        string `json:"rule_name"`
			Description string `json:"description"`
		} `json:"yara_rules"`
	} `json:"data"`
}

//*======================[TELEMETRY]==============================

type Heartbeat struct {
	Pid       uint32
	Heartbeat [64]byte
}

type Command struct {
	Pid     uint32
	Command [64]byte
}

// each telemetry packet (not including heartbeat and command, as that is classed as different)
// will send this in the beginning of the packet, to allow for dynamically sized packets.
// Calling the Log method will handle everything once youve received the packet
type TelemetryHeader struct {
	Pid       uint32
	Type      uint32
	DataSize  uint64
	TimeStamp int64
}

type Parameter struct {
	Name   string
	Type   uint32
	Buffer []byte
}

type EtwHeader struct {
	Pid  uint32
	Type uint32
}

/*
type ApiArg struct {
	Type    int
	RawData [API_ARG_MAX_SIZE]byte
}

type ApiArgV2 struct {
	Type    int
	Name    string
	RawData [API_ARG_MAX_SIZE]byte
}
*/

// results of an integrity check of a modules .text section
type TextCheckData struct {
	Result    bool
	Module    string
	TimeStamp int64
}

type IatIntegrityData struct {
	FuncName string
	Address  uint64
}

// why is this needed????
/*
	type PatternResult struct {
		Name      string
		Score     int   // actual score for how malicious it is
		Severity  int   // severity only for coloring output: 0(low), 1(medium) or 2(high)
		TimeStamp int64 // time of detection, not call
		Count     int
	}

	func (p PatternResult) GetTime() int64 {
		return p.TimeStamp
	}
*/
type MemRegion struct {
	Address unsafe.Pointer
	Size    uint64
}

type RemoteModule struct {
	Name        [260]byte
	NumSections uint64
	Sections    []MemRegion
}

// go version of THREAD_ENTRY, for thread scans
type ThreadEntry struct {
	ThreadId     uint32
	ProcessId    uint32
	Reason       uint32
	StartAddress uintptr
}

type Alert struct {
	TimeStamp int64
	Caption   string
	Message   string
	Score     int
	Type      int
	Pid       int
}

func (m *RemoteModule) GetName() string {
	i := bytes.IndexByte(m.Name[:], 0)
	if i == -1 {
		return string(m.Name[:]) // fallback
	}
	return string(m.Name[:i])
}

type Magic struct {
	Bytes     []byte
	Type      string // database of magic bytes is in consts.go
	Extension []string
}
