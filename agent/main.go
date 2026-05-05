package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/fatih/color"
	"golang.org/x/sys/windows"
)

//? If you're wondering why some comments in the codebase start with a symbol like this one;
//* It's because I'm using a "better comments" plugin, where these symbols color the comment a certain color.

//?==================================================================+
//?   This file contains the main routine, global variables, and     |
//?     implements the main scan scheduler routines.                 |
//?==================================================================+

var (
	printMu sync.Mutex // this makes sure a print is not interrupted
	white   = NewColor(color.New())
	green   = NewColor(color.New(color.FgGreen, color.Bold))
	yellow  = NewColor(color.New(color.FgYellow, color.Bold))
	red     = NewColor(color.New(color.FgRed))
	logger  = Logger{name: "agent.log"}

	config           Config
	scanner          *MemoryScanner
	psTable          = ProcessTable{processes: make(map[int]*Process)}
	malapi           map[string]MalApi
	BehaviorPatterns []BehaviorPattern
	Alerts           AlertHistory
)

func PeriodicScanScheduler(wg *sync.WaitGroup, ctx context.Context) {
	defer wg.Done()
	heartbeat := time.NewTicker(time.Duration(HEARTBEAT_INTERVAL) * time.Second)
	memoryScan := time.NewTicker(time.Duration(MEMORYSCAN_INTERVAL) * time.Second)
	threadScan := time.NewTicker(time.Duration(THREADSCAN_INTERVAL) * time.Second)
	handleScan := time.NewTicker(time.Duration(HANDLESCAN_INTERVAL) * time.Second)
	defer memoryScan.Stop()
	defer heartbeat.Stop()

	var (
		tasks         = make(chan Scan)
		priorityTasks = make(chan Scan)
	)

	const numWorkers = 10
	for w := 0; w < numWorkers; w++ {
		wg.Add(1)
		go PeriodicScanHandler(wg, priorityTasks, tasks, ctx)
	}

	for {
		select {
		case <-ctx.Done():
			close(tasks)
			close(priorityTasks)
			scanner.Destroy()
			rules.Destroy()
			return
		case <-memoryScan.C:
			go func() { // launch a goroutine to schedule memory scans
				for pid, process := range psTable.GetProcesses() {
					if process.IsSigned {
						tasks <- Scan{Pid: pid, Type: SCAN_MEMORYSCAN}
					} else {
						priorityTasks <- Scan{Pid: pid, Type: SCAN_MEMORYSCAN}
					}
				}
			}()
		case <-threadScan.C: // global thread scan
			priorityTasks <- Scan{Pid: 0, Type: SCAN_THREADSCAN}
		case <-handleScan.C:
			priorityTasks <- Scan{Pid: 0, Type: SCAN_HANDLESCAN}

		case <-heartbeat.C:
			go func() { // launch a goroutine to check each heartbeat
				for pid, process := range psTable.GetProcesses() {
					now := time.Now().Unix()
					if process.LastHeartbeat < (now - MAX_HEARTBEAT_DELAY) {
						TerminateProcess(pid)
						psTable.Delete(pid)
					}
				}
			}()
		}
	}
}

func PeriodicScanHandler(wg *sync.WaitGroup, priorityTasks chan Scan, tasks chan Scan, ctx context.Context) {
	defer wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case scan := <-priorityTasks: // prioritize unsigned processes
			switch scan.Type {
			case SCAN_MEMORYSCAN:
				results, err := BasicMemoryScan(uint32(scan.Pid), scanner)
				if err != nil {
					red.Log("[!] Failed to perform memory scan: %v", err)
				}
				results.Log("basic memory scan", scan.Pid)
				if results.TotalScore > 10 {
					priorityTasks <- Scan{Pid: scan.Pid, Type: SCAN_MEMORYSCAN_FULL}
				}
			}
		//TODO: case SCAN_HANDLESCAN:
		case SCAN_THREADSCAN:
			var count C.size_t
			cThreads := C.ScanProcessThreads(uint32(scan.Pid), &count)
			if count == 0 {
				continue
			}

			threads := unsafe.Slice((*ThreadEntry)(unsafe.Pointer(cThreads)), int(count))
			for _, thread := range threads {
				switch thread.Reason {
				case THREAD_ENTRY_UNBACKED_MEM:
					alert := CreateAlert(THREAD_ENTRY_UNBACKED_MEM,
						"Found a thread belonging to process %d with a start address pointing to unbacked executable memory!",
						60, thread.Pid)
					alert.PushAlert()
				case THREAD_ENTRY_OUTSIDE_MODULE:
					msg := fmt.Sprintf("Found a thread belonging to process %d with a start address pointing outside of any module (%p)", thread.StartAddress)
					alert := CreateAlert(THREAD_ENTRY_OUTSIDE_MODULE, msg, thread.Pid, 50)
					alert.PushAlert()
				}
			}
		case scan := <-tasks:
			switch scan.Type {
			case SCAN_MEMORYSCAN:
				results, err := BasicMemoryScan(uint32(scan.Pid), scanner)
				if err != nil {
					red.Log("[!] Failed to perform memory scan: %v", err)
				}
				results.Log("basic memory scan", scan.Pid)
				if results.TotalScore > 10 {
					priorityTasks <- Scan{Pid: scan.Pid, Type: SCAN_MEMORYSCAN_FULL}
				}

			case SCAN_UNBACKED_CODE:
				var (
					count     C.size_t
					totalSize C.size_t
				)
				hProcess, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION, false, uint32(scan.Pid))
				if err != nil {
					red.Log("[!] Failed to open handle to process %d", err)
					white.Log("\tError: %v", err)
					continue
				}
				defer windows.CloseHandle(hProcess)
				cRegions := C.GetUnbackedExecutablePages(C.HANDLE(hProcess), &count, &totalSize)
				defer C.free(cRegions)
				if totalSize < UNBACKED_CODE_THRESHOLD {
					continue
				}
				// check if this process is allowed to have this
				if BehaviorRules.IsAllowedUnbackedExecution(scan.Pid) {
					continue
				}

				//* send alert
				msg := fmt.Sprintf("Process %d has %d unbacked executable regions (%dB)", scan.Pid, count, totalSize)
				alert := CreateAlert(ALERT_UNBACKED_CODE, "", msg, UNBACKED_CODE_SCORE, scan.Pid)
				alert.PushAlert(true)

				//* scan all the regions
				go ScanMemoryRegions(hProcess, scan.Pid, cRegions, count)
			}
		}
	}
}

// * This is not up to date currently. will be updated soon...
func main() {
	var wg sync.WaitGroup
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := InitializeLogger(logName)
	if err != nil {
		color.Red("\n[!] Failed to initialize logger!")
		fmt.Printf("\tError: %v\n", err)
		return
	}

	defer logFile.Close()
	//wg.Add(5)
	wg.Add(4)
	go heartbeatListener(&wg, ctx)
	go telemetryListener(&wg, ctx)
	//go commandListener(&wg) //TODO add terminate
	go PeriodicScanScheduler(&wg, ctx)
	go HistoryCleaner(&wg, ctx)

	//? should it be allowed to run without yara ruleset or api patterns?

	//TODO: add option to specify rules directory
	//* load ruleset
	rules, scanner, err = LoadYaraRulesFromFolder("")
	if err != nil {
		red.Log("\n[FATAL] Unable to load yara rules!")
		white.Log("\tError: %v\n", err)
		return
	}

	// simple malapi list used for trivial static analysis
	malapi, err = LoadMaliciousApiListFromDisk("")
	if err != nil {
		red.Log("\n[!] Failed to load malicious API list!")
		white.Log("\tError: %v\n", err)
	}

	//TODO: add cl flag option to specify dirs
	CompileBehaviorPatterns()

	// setup for static engine for reading magic bytes
	SortMagic()

	//* cli loop
	PrintBanner(DEFAULT_BANNER)
Cli:
	for {
		if ctx.Err() != nil { // shutdown signal
			break Cli
		}
		// main loop code here
		g := color.New(color.FgGreen, color.Bold)
		g.Print(" $ ")
		reader := bufio.NewReader(os.Stdin)
		command, _ := reader.ReadString('\n')
		command = strings.TrimSpace(command)
		if command == "" {
			continue
		}
		tokens := strings.Fields(command)
		exit := cli_parse(tokens, cancel)
		if exit {
			break Cli
		}
	}
	wg.Wait()
}
