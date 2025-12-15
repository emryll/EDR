package main

//#include "memscan.h"
import "C"

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	winio "github.com/Microsoft/go-winio"
	"github.com/fatih/color"
)

var (
	HEARTBEAT_PIPE string = "\\\\.\\pipe\\vgrd_hb"
	TELEMETRY_PIPE string = "\\\\.\\pipe\\vgrd_tm"
	COMMANDS_PIPE  string = "\\\\.\\pipe\\vgrd_cmd"
	ETW_PIPE       string = "\\\\.\\pipe\\em_etw"
)

// create pipe, accept connections
func heartbeatListener(wg *sync.WaitGroup, ctx context.Context) error {
	defer wg.Done()
	l, err := winio.ListenPipe(HEARTBEAT_PIPE, nil)
	if err != nil {
		return err
	}
	defer l.Close()

	for {
		if ctx.Err() != nil {
			yellow.Log("[heartbeat] Exiting listener...")
			return nil
		}
		conn, err := l.Accept()
		if err != nil {
			return fmt.Errorf("Failed to accept connection: %v", err)
		}

		go heartbeatHandler(conn, wg, ctx)
		wg.Add(1)
	}
}

// handle individual connection
func heartbeatHandler(conn net.Conn, wg *sync.WaitGroup, ctx context.Context) {
	defer wg.Done()
	defer conn.Close()
	green.Log("[heartbeat] Client connected!\n")
	for {
		if ctx.Err() != nil {
			return
		}
		var hb Heartbeat
		err := binary.Read(conn, binary.LittleEndian, &hb)
		if err != nil {
			//red.Log("\n[heartbeat] Read error: %v\n", err)
			//continue
			return
		}

		// Convert C-style string (null-terminated) into Go string
		heartbeat := string(hb.Heartbeat[:])
		if i := bytes.IndexByte(hb.Heartbeat[:], 0); i >= 0 {
			heartbeat = heartbeat[:i]
		}

		printMu.Lock()
		green.Log("[heartbeat] Received %s from %d\n", heartbeat, hb.Pid)
		printMu.Unlock()

		if p, exists := processes[int(hb.Pid)]; exists {
			p.LastHeartbeat = time.Now().Unix()
		} else {
			green.Log("[heartbeat] New tracked process detected (%d)\n", hb.Pid)
			path, err := GetProcessExecutable(hb.Pid)
			if err != nil {
				TerminateProcess(int(hb.Pid))
				continue
			}
			result, err := IsSignatureValid(path)
			if err != nil {
				TerminateProcess(int(hb.Pid))
				continue
			}
			var isSigned bool
			switch result {
			case IS_UNSIGNED:
				isSigned = false
				white.Log("[i] Process %d with path %s is not signed\n", hb.Pid, path)
			case HAS_SIGNATURE:
				isSigned = true
				green.Log("[+] Process %d with path %s is signed\n", hb.Pid, path)
			case HASH_MISMATCH:
				red.Log("[!] Signature hash mismatch in %s! (PID %d)\n", path, hb.Pid)
				TerminateProcess(int(hb.Pid))
				continue
			}
			// add new process to process map
			mu.Lock()
			//TODO: perhaps make the other maps' values pointers as well
			processes[int(hb.Pid)] = &Process{Path: path,
				LastHeartbeat:  time.Now().Unix(),
				IsSigned:       isSigned,
				APICalls:       make(map[string]ApiCallData),
				FileEvents:     make(map[string]FileEventData),
				RegEvents:      make(map[string]RegEventData),
				PatternMatches: make(map[string]*StdResult)}
			mu.Unlock()
		}
	}
}

// accept connections
func telemetryListener(wg *sync.WaitGroup, ctx context.Context) error {
	defer wg.Done()
	l, err := winio.ListenPipe(TELEMETRY_PIPE, nil)
	if err != nil {
		return err
	}
	defer l.Close()

	for {
		if ctx.Err() != nil {
			yellow.Log("[telemetry] Exiting listener...\n")
			return nil
		}
		conn, err := l.Accept()
		if err != nil {
			return fmt.Errorf("Failed to accept connection: %v", err)
		}

		wg.Add(1)
		go telemetryHandler(conn, wg, ctx)
	}
}

// handle individual connection
func telemetryHandler(conn net.Conn, wg *sync.WaitGroup, ctx context.Context) {
	defer wg.Done()
	defer conn.Close()
	green.Log("[telemetry] Client connected!\n")
	for {
		if ctx.Err() != nil {
			return
		}
		conn.SetReadDeadline(time.Now().Add(1 * time.Second))

		//* first read the header to get size and type of data
		var tmHeader TelemetryHeader
		tmhBuf := make([]byte, TM_HEADER_SIZE)
		_, err := io.ReadFull(conn, tmhBuf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			if err == io.EOF {
				//yellow.Log("[telemetry] Client disconnected (EOF)")
				return
			}
			red.Log("[telemetry] Failed to read telemetry header\n")
			white.Log("\tError: %v\n", err)
			return
		}

		err = binary.Read(bytes.NewReader(tmhBuf), binary.LittleEndian, &tmHeader)
		if err != nil {
			red.Log("[telemetry] binary.Read failed on buffer: %v\n", err)
			continue
		}
		//fmt.Printf("Header - PID: %d, Type: %d, TimeStamp: %d, DataSize: %d\n",
		//tmHeader.Pid, tmHeader.Type, tmHeader.TimeStamp, tmHeader.DataSize)

		// skip garbage data
		if tmHeader.Type > 10 || tmHeader.DataSize > TM_MAX_DATA_SIZE {
			red.Log("[telemetry] Invalid header - Type: %d, DataSize: %d (max: %d)",
				tmHeader.Type, tmHeader.DataSize, TM_MAX_DATA_SIZE)
			continue
		}
		if tmHeader.Type == TM_TYPE_EMPTY_VALUE {
			continue
		}

		if tmHeader.DataSize <= 0 {
			yellow.Log("[telemetry] Warning: Data size: %d", tmHeader.DataSize)
		}
		//* now read the actual data which comes after the header
		dataBuf := make([]byte, tmHeader.DataSize)
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		_, err = io.ReadFull(conn, dataBuf)
		if err != nil {
			red.Log("[telemetry] Failed to read data of telemetry packet.\n")
			white.Log("\tError: %v\n", err)
			continue
		}

		//* this will add it to process' history and handle logging
		tmHeader.Log(dataBuf)
	}
}

/*
func commandListener(wg *sync.WaitGroup) error {
	wg.Done()
	l, err := winio.ListenPipe(COMMANDS_PIPE, nil)
	if err != nil {
		return fmt.Errorf("Failed to start command pipe: %v", err)
	}
	defer l.Close()
	for {
		conn, err := l.Accept()
		if err != nil {
			color.Red("\n[!] Failed to accept command pipe connection: %v", err)
			continue
		}
		defer conn.Close()
		go commandHandler(conn, cmdChan, wg)
		wg.Add(1)
	}
}

func commandHandler(conn net.Conn, commands chan Command, wg *sync.WaitGroup) {
	defer wg.Done()
	//* wait for new commands on channel, then pass it to pipe
	for {
		select {
		case cmd := <-commands:
			var cmdBuf [68]byte
			binary.LittleEndian.PutUint32(cmdBuf[0:4], cmd.Pid)
			copy(cmdBuf[4:], cmd.Command[:])

			err := binary.Write(conn, binary.LittleEndian, &cmdBuf)
			if err != nil {
				color.Red("\n[!] Failed to write command to pipe: %v", err)
				return
			}
			color.Green("[cmd] Sent command!")
		}
	}
}
*/
// Function to accept ETW pipe connections. Error is returned ONLY if it failed to create pipe.
func etwListener(wg *sync.WaitGroup, ctx context.Context) error {
	defer wg.Done()
	fmt.Println("[debug] etwlistener")
	// needs to be inside so listener can be closed
	l, err := winio.ListenPipe(ETW_PIPE, nil)
	if err != nil {
		return err
	}
	defer l.Close()
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		// no timeout in the blocking l.Accept()
		conn, err := l.Accept()
		if err != nil {
			time.Sleep(time.Duration(3) * time.Second)
			continue
		}

		color.Green("[etw] Connected to ETW consumer pipe\n")
		wg.Add(1)
		go telemetryHandler(conn, wg, ctx)
	}
}

// pipe server for commands to etw
func etwCmdListener(wg *sync.WaitGroup, ctx context.Context) error {
	defer wg.Done()
	l, err := winio.ListenPipe(COMMANDS_PIPE, nil)
	if err != nil {
		return fmt.Errorf("Failed to start command pipe: %v", err)
	}
	defer l.Close()

	// this is a loop, because then if ETW consumer crashes, connection can be restored
	// it can be assumed no one else can connect due to handshake (implemented in future)
	fmt.Println("[debug] commandlistener")
	for {
		if ctx.Err() != nil { // shutdown signal
			return ctx.Err()
		}

		conn, err := l.Accept()
		if err != nil {
			time.Sleep(time.Duration(3) * time.Second)
		}

		cmdConnMu.Lock()
		if cmdConn != nil {
			cmdConn.Close()
		}
		cmdConn = conn
		cmdConnMu.Unlock()
		color.Green("[etw] Connected to command pipe\n")
	}
}

func ParseParameters(data []byte) []Parameter {
	var params []Parameter
	cursor := 0
	for cursor < len(data) {
		parameter := ReadAnsiString(dataBuf[cursor:])
		cursor += len(parameter) + 1
		param, err := ParseParameterString(parameter, dataBuf[cursor:])
		if err != nil || param.Buffer == nil {
			color.Red("\n[!] Failed to parse parameter: %v", err)
			if len(parameter) == 0 {
				break // prevent infinite loop
			}
			continue
		}
		cursor += len(param.Buffer)
		params = append(params, param)
	}
	return params
}

func ParseParameterString(header string, data []byte) (Parameter, error) {
	var (
		param   Parameter
		isArray = false
	)

	parts := strings.Split(header, ":")
	if len(parts) < 2 {
		return Parameter{}, fmt.Errorf("packet string does not contain \":\" (%s)", header)
	}

	head := strings.Split(parts[0], "/")
	param.Name = head[0]

	// non-array types should have only one string in head (no "/")
	if len(head) > 1 {
		if len(head[1]) == 0 {
			return Parameter{}, fmt.Errorf("invalid header: size (%s)", header)
		}
		size, err := strconv.Atoi(head[1])
		if err != nil {
			return Parameter{}, fmt.Errorf("failed to read size into integer: %v (%s)", err, header)
		}
		param.Buffer = append([]byte(nil), data[:size]...)
		isArray = true
	}

	param.Type = GetParameterType(parts[1], isArray)

	if !isArray {
		switch param.Type {
		case PARAMETER_ANSISTRING:
			str := ReadAnsiStringValue(data)
			param.Buffer = append([]byte(nil), data[:len(str)+1]...)
		case PARAMETER_BOOLEAN, PARAMETER_UINT32:
			param.Buffer = append([]byte(nil), data[:4]...)
		case PARAMETER_UINT64, PARAMETER_POINTER:
			param.Buffer = append([]byte(nil), data[:8]...)
		}
	}
	return param, nil
}

func GetParameterType(ptype string, isArray bool) uint32 {
	switch ptype[0] {
	case 's':
		return PARAMETER_ANSISTRING
	case 'x':
		return PARAMETER_BYTES
	case 'd':
		if isArray {
			return PARAMETER_UINT32_ARR
		}
		return PARAMETER_UINT32
	case 'q':
		if isArray {
			return PARAMETER_UINT64_ARR
		}
		return PARAMETER_UINT64
	case 'p':
		if isArray {
			return PARAMETER_POINTER_ARR
		}
		return PARAMETER_POINTER
	case 'b':
		if isArray {
			return PARAMETER_BOOLEAN_ARR
		}
		return PARAMETER_BOOLEAN
	}
	return 0
}

func (p Parameter) PrintValue() {
	fmt.Printf("[*] %s: ", p.Name)
	switch p.Type {
	case PARAMETER_BYTES:
		DumpBytes(p.Buffer)
	case PARAMETER_ANSISTRING:
		fmt.Printf("%s\n", ReadAnsiStringValue(p.Buffer))
	case PARAMETER_UINT32:
		fmt.Printf("%d\n", binary.LittleEndian.Uint32(p.Buffer))
	case PARAMETER_UINT64:
		fmt.Printf("%d\n", binary.LittleEndian.Uint64(p.Buffer))
	case PARAMETER_POINTER:
		fmt.Printf("%p\n", binary.LittleEndian.Uint64(p.Buffer))
	case PARAMETER_BOOLEAN:
		cb := binary.LittleEndian.Uint32(p.Buffer)
		if cb == 0 {
			fmt.Printf("false\n")
		} else {
			fmt.Printf("true\n")
		}
	default:
		color.Red("Print method not created for this type (%d), sorry...", p.Type)
	}
}
