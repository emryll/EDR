package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/fatih/color"
)

func (r StdResult) Log() {
	switch r.Severity {
	case 0:
		green.Log("[*] ")
		if r.Name == "" {
			white.Log("%s ", r.Description) //text in white so its easier to read
			green.Log("(+%d)\n", r.Score)
		} else {
			white.Log("%s ", r.Name) //text in white so its easier to read
			green.Log("(+%d)\n", r.Score)
			if r.Description != "" {
				green.Log("\t[?] ")
				white.Log("%s\n", r.Description)
			}
		}
	case 1:
		yellow.Log("[*] ")
		if r.Name == "" {
			white.Log("%s ", r.Description)
			yellow.Log("(+%d)\n", r.Score)
		} else {
			white.Log("%s ", r.Name)
			yellow.Log("(+%d)\n", r.Score)
			if r.Description != "" {
				yellow.Log("\t[?] ")
				white.Log("%s\n", r.Description)
			}
		}
	case 2:
		red.Log("[*] ")
		if r.Name == "" {
			white.Log("%s ", r.Description)
			red.Add(color.Bold)
			red.Log("(+%d)\n", r.Score)
		} else {
			white.Log("%s ", r.Name)
			red.Add(color.Bold)
			red.Log("(+%d)\n", r.Score)
			if r.Description != "" {
				white.Log("\t[?] %s\n", r.Description)
			}
		}
	default:
		red.Log("[!] Invalid severity value in YARA rule (%d), must be 0(low), 1(medium) or 2(high)", r.Severity)
		white.Log("[*] ")
		if r.Name == "" {
			white.Log("%s (+%d)\n", r.Description, r.Score)
		} else {
			white.Log("%s (+%d)\n", r.Name, r.Score)
			if r.Description != "" {
				white.Log("\t[?] %s\n", r.Description)
			}
		}
	}
	if len(r.Category) > 0 {
		white.Log("\tCategory: ")
		for i, t := range r.Category {
			white.Log("%s", t)
			if len(r.Category) > i+1 {
				white.Log(", ")
			}
		}
		white.Log("\n")
	}
}

// This method will log telemetry packet to file on disk (logFile), add it to process history,
// and print it out if printLog is enabled. It will also launch further action if needed
func (header TelemetryHeader) Log(dataBuf []byte) {
	switch header.Type {
	case TM_TYPE_EMPTY_VALUE:
		return
	case TM_TYPE_API_CALL:
		white.Log("\n\nPID: %d, new API call\n", header.Pid)

		//* Parse packet and add to process' API call history
		apiCall := ParseApiTelemetryPacket(dataBuf, header.TimeStamp)
		if _, exists := processes[int(header.Pid)]; !exists {
			if header.Pid <= 0 || header.Pid > 1000000 {
				return
			}

			var signed bool
			path, err := GetProcessExecutable(uint32(header.Pid))
			if err != nil {
				red.Log("\n[!] Failed to get executable path of process %d", header.Pid)
				white.Log("\tError: %v\n", err)
			} else {
				signedstatus, err := IsSignatureValid(path)
				if err != nil {
					red.Log("\n[!] Failed to check digital certificate!")
					white.Log("\tError: %v\n", err)
				} else {
					switch signedstatus {
					case IS_UNSIGNED:
						signed = false
					case HASH_MISMATCH:
						red.Log("\n[!] Hash mismatch in process %d!", header.Pid)
						TerminateProcess(int(header.Pid))
					case HAS_SIGNATURE:
						signed = true
					}
				}
			}
			processes[int(header.Pid)] = &Process{
				Path:           path,
				IsSigned:       signed,
				APICalls:       make(map[string]ApiCallData),
				FileEvents:     make(map[string]FileEventData),
				RegEvents:      make(map[string]RegEventData),
				PatternMatches: make(map[string]*StdResult),
			}
		}
		mu.Lock()
		processes[int(header.Pid)].PushToApiCallHistory(apiCall)
		mu.Unlock()

		printMu.Lock()
		white.Log("* [TID: %d] %s!%s:\n", apiCall.ThreadId, apiCall.DllName, apiCall.FuncName)
		//* Log the args
		for i, arg := range apiCall.Args {
			switch arg.Type {
			case API_ARG_TYPE_EMPTY:
				continue
			case API_ARG_TYPE_DWORD:
				white.Log("\tArg #%d (DWORD): %d\n", i, arg.Read())
			case API_ARG_TYPE_ASTRING:
				white.Log("\tArg #%d (ASTRING): %s\n", i, arg.Read())
			case API_ARG_TYPE_WSTRING:
				white.Log("\tArg #%d (WSTRING): %s\n", i, arg.Read())
			case API_ARG_TYPE_PTR:
				white.Log("\tArg #%d (LPVOID): 0x%X\n", i, arg.Read())
			case API_ARG_TYPE_BOOL:
				bval := arg.Read().(bool) //? ^probably need to do this cast with all of them
				if bval {
					white.Log("\tArg #%d (BOOL): TRUE\n", i)
				} else {
					white.Log("\tArg #%d (BOOL): FALSE\n", i)
				}
			}
		}
		printMu.Unlock()

	case TM_TYPE_TEXT_INTEGRITY: //TODO: maybe only log hash mismatches
		printMu.Lock()
		white.Log("\n\nPID: %d, new .text integrity check\n", header.Pid)

		//* Parse and log result of check
		textCheck := ParseTextTelemetryPacket(dataBuf)
		if textCheck.Result { // true means the integrity remains, its fine
			white.Log("\tModule \"%s\" integrity: TRUE\n", textCheck.Module)
		} else { // hash mismatch
			red.Log("\tModule \"%s\" integrity: FALSE\n", textCheck.Module)
			go func() { // goroutine so memscan does not block execution
				results, err := MemoryScanEx(header.Pid, scanner)
				if err != nil {
					red.Log("\n[!] Failed to launch MemoryScanEx on process %d: %v\n", header.Pid, err)
				} else if results.TotalScore > 0 {
					go results.Log("MemoryScanEx", int(header.Pid)) // goroutine to not block execution, self-explanatory func
				}
			}()
		}
		printMu.Unlock()
	case TM_TYPE_IAT_INTEGRITY:
		printMu.Lock()
		white.Log("\n\nPID: %d, new IAT integrity check\n", header.Pid)

		//* Parse and log result of check
		iatMismatches := ParseIatTelemetryPacket(dataBuf)
		red.Log("%d", len(iatMismatches))
		white.Log(" Mismatches in IAT! Highly suspicious!\n")
		for _, mismatch := range iatMismatches {
			white.Log("\t%s points to", mismatch.FuncName)
			red.Log(" 0x%X\n", mismatch.Address)
		}

		printMu.Unlock()
	case TM_TYPE_GENERIC_ALERT:
		size := binary.LittleEndian.Uint64(dataBuf[0:8])
		description := ReadAnsiStringValue(dataBuf[8:size])
		printMu.Lock()
		red.Log("\n[ALERT]")
		white.Log(" %s\n", description)
		printMu.Unlock()

		//TODO: instead add some universal tag to communicate termination
		if strings.HasPrefix(strings.ToLower(description), "dll injection") {
			if strings.HasSuffix(VERSION, "demo") {
				time.Sleep(time.Duration(300) * time.Millisecond)
			}
			TerminateProcess(int(header.Pid))
			white.Log("[i] Terminated process %d\n", header.Pid)
		}
	case TM_TYPE_FILE_EVENT:
		//? first comes etw header, it tells you how many parameters come after it
		var (
			event  FileEventData
			cursor = 0
		)

		event.Action = binary.LittleEndian.Uint32(dataBuf[0:4])
		cursor += 4
		event.TargetPath = ReadAnsiString(dataBuf[cursor : cursor+260])
		cursor += 260
		attributeCount := binary.LittleEndian.Uint32(dataBuf[cursor : cursor+4])
		cursor += 4 + 4 // 4 byte padding, because size_t has to align with 8
		totalAttributeSize := binary.LittleEndian.Uint64(dataBuf[cursor : cursor+8])
		cursor += 8

		//fmt.Printf("attributeCount: %d\n\ttotalAttributeSize: %d\n", attributeCount, totalAttributeSize)
		if attributeCount > 0 && totalAttributeSize > 0 {
			event.Parameters = make(map[string]Parameter)
			params := ParseParameters(dataBuf[cursor:])
			if params == nil {
				return
			}
			for _, p := range params {
				event.Parameters[p.Name] = p
			}
		}

		fmt.Printf("\n%s\n\n", stars)
		//* debug test print
		switch event.Action {
		case FILE_CREATE:
			color.Green("[+] File CREATE event on %s", event.TargetPath)
		case FILE_READ:
			color.Green("[+] File READ event on %s", event.TargetPath)
		case FILE_WRITE:
			color.Green("[+] File WRITE event on %s", event.TargetPath)
		case FILE_DELETE:
			color.Green("[+] File DELETE event on %s", event.TargetPath)
		default:
			color.Green("[+] UNKNOWN file event (%d) on %s", event.Action, event.TargetPath)
		}
		if len(event.Parameters) == 0 {
			fmt.Println("\tNo parameters.")
		} else {
			PrintParameters(event.Parameters)
		}
		fmt.Printf("\n%s\n", stars)

	case TM_TYPE_REG_EVENT:
		//? first comes etw header, it tells you how many parameters come after it
		var (
			event  RegEventData
			cursor = 0
		)

		event.Action = binary.LittleEndian.Uint32(dataBuf[0:4])
		cursor += 4
		event.Path = ReadAnsiString(dataBuf[cursor : cursor+260])
		cursor += 260
		attributeCount := binary.LittleEndian.Uint32(dataBuf[cursor : cursor+4])
		cursor += 4 + 4
		totalAttributeSize := binary.LittleEndian.Uint64(dataBuf[cursor : cursor+8])
		cursor += 8

		if attributeCount <= 0 || totalAttributeSize <= 0 || int(totalAttributeSize) > len(dataBuf) {
			return
		}
		event.Parameters = make(map[string]Parameter)
		params := ParseParameters(dataBuf[cursor:])
		if params == nil {
			return
		}
		for _, p := range params {
			event.Parameters[p.Name] = p
		}

		fmt.Printf("\n%s\n\n", stars)
		//* debug test print
		switch event.Action {
		case REG_CREATE_KEY:
			color.Green("[+] Registry CREATE KEY event on %s", event.Path)
			//fmt.Println("[debug] memory layout of data packet (excludes TELEMETRY_HEADER):")
			//DumpPacket(dataBuf)

			//fmt.Printf("[debug] memory layout of just the parameters\n")
			//DumpPacket(dataBuf[FILE_EVENT_SIZE:])

		case REG_OPEN_KEY:
			color.Green("[+] Registry OPEN KEY event on %s", event.Path)
		case REG_DELETE_KEY:
			color.Green("[+] Registry DELETE KEY event on %s", event.Path)
		case REG_SET_KEY_VALUE:
			color.Green("[+] Registry SET KEY VALUE event on %s", event.Path)
		case REG_CLOSE_KEY:
			color.Green("[+] Registry CLOSE KEY event on %s", event.Path)
		}
		PrintParameters(event.Parameters)
		fmt.Printf("\n%s\n", stars)
	}
	//* Add a line after the log
	white.Log("\n")
}

// Process and log results. Launch further actions or alerts if needed
func (r Result) Log(scanName string, pid int) {
	printMu.Lock()
	if r.TotalScore > 0 {
		white.Log("\n\nGot %d total score from %s (%d matches)\n", r.TotalScore, scanName, len(r.Results))
	}

	_, pidExists := processes[pid]
	if pidExists {
		processes[pid].IncrementScore(r.TotalScore)
	}
	//TODO: check if score exceeds thresholds, make a function for this

	//TODO: if m.Severity is severe, trigger an alert
	for _, m := range r.Results {
		t := time.Unix(m.TimeStamp, 0)
		formatted := t.Format("15:04:05")

		var name string
		if m.Name == "" {
			name = m.Description
		} else {
			name = m.Name
		}
		white.Log("[%s] %s (+%d)\n", formatted, name, m.Score)
		if m.Description != "" {
			white.Log("\t[?] %s\n", m.Description)
		}
		if len(m.Category) > 0 {
			categories := "\tCategory: "
			for i, c := range m.Category {
				categories += c
				if len(m.Category) > i+1 {
					categories += ", "
				}
			}
			categories += "\n"
			white.Log(categories)
		}
		//* update process' history
		if pidExists {
			mu.Lock()
			_, exists := processes[pid].PatternMatches[name]
			if exists {
				processes[pid].PatternMatches[name].Count++
			} else {
				processes[pid].PatternMatches[name] = &m
			}
			mu.Unlock()
		}
	}
	white.Log("\n\n")
	printMu.Unlock()
}

// Initialize a color that can be used with custom log method
func NewColor(c *color.Color) *Color {
	return &Color{Color: c}
}

// Initialize everything. After this you can just call Color's Log method
func InitializeLogger(logPath string) error {
	var err error
	logFile, err = os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	writer = &DualWriter{
		file:   logFile,
		stdout: os.Stdout,
		print:  printLog,
	}

	logger = log.New(writer, "", log.LstdFlags|log.Lshortfile)

	white = NewColor(color.New())
	red = NewColor(color.New(color.FgRed))
	green = NewColor(color.New(color.FgGreen, color.Bold))
	yellow = NewColor(color.New(color.FgYellow, color.Bold))
	return nil
}

// required method for writer interface. Write to log file
func (w *DualWriter) Write(p []byte) (int, error) {
	n, err := w.file.Write(p)
	if err != nil {
		return n, err
	}
	return n, nil
}

// Log to file and optionally also print it, with color
func (c *Color) Log(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	// write to file
	logMu.Lock()
	logger.Output(2, msg)

	if printLog {
		if c != nil {
			c.Print(msg)
		} else {
			fmt.Print(msg)
		}
	}
	logMu.Unlock()
}

func (p *Process) AddToHistory(result *StdResult, components map[string]*ComponentResult) *PatternMatch {
	var match = &PatternMatch{Pid: p.ProcessId, Result: result}
	for _, comp := range components {
		match.Events = append(match.Events, comp.LeftEdge...)
		match.Events = append(match.Events, comp.RightEdge...)
	}
	p.PatternMatches[result.Name] = match
	return match
}
