package main

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"
	"unsafe"

	yara "github.com/VirusTotal/yara-x/go"
	"github.com/fatih/color"
)

//? If you're wondering why some comments in the codebase start with a symbol like this one;
//* It's because I'm using a "better comments" plugin, where these symbols color the comment a certain color.

var ( // all global variables belong here
	white            *Color
	green            *Color
	yellow           *Color
	red              *Color
	printLog         = true
	logName          = "agent.log"
	logFile          *os.File
	logger           *log.Logger
	logMu            sync.Mutex
	writer           *DualWriter
	processes        = make(map[int]*Process) // key: pid
	mu               sync.Mutex               // is this necessary? i dont think so
	printMu          sync.Mutex               // this makes sure a print is not interrupted
	scannerMu        sync.Mutex
	scanner          *yara.Scanner
	rules            *yara.Rules
	malapi           map[string]MalApi
	BehaviorPatterns []BehaviorPattern
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
				for pid, process := range processes {
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
				for pid, process := range processes {
					now := time.Now().Unix()
					if process.LastHeartbeat < (now - MAX_HEARTBEAT_DELAY) {
						TerminateProcess(pid)
						mu.Lock()
						delete(processes, pid)
						mu.Unlock()
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
					PushAlert(THREAD_ENTRY_UNBACKED_MEM,
						"Found a thread belonging to process %d with a start address pointing to unbacked executable memory!",
						60, thread.Pid)
				case THREAD_ENTRY_OUTSIDE_MODULE:
					msg := fmt.Sprintf("Found a thread belonging to process %d with a start address pointing outside of any module (%p)", thread.StartAddress)
					PushAlert(THREAD_ENTRY_OUTSIDE_MODULE, msg, thread.Pid, 50)
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

				//TODO: case SCAN_UNBACKED_CODE:
			}
		}
	}
}

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

	malapi, err = LoadMaliciousApiListFromDisk("")
	if err != nil {
		red.Log("\n[!] Failed to load malicious API list!")
		white.Log("\tError: %v\n", err)
	}

	//TODO: load v3 patterns

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
