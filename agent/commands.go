package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
)

// CLI command implementations and IPC commands

func SendEtwTrackCmd(conn net.Conn, pids []uint32) error {
	if conn == nil {
		return fmt.Errorf("pipe not initialized")
	}

	header := EtwCmd{
		Type:     ETW_CMD_PLIST_ADD,
		DataSize: uint64(len(pids) * 4), // DWORD 4 byte values
	}

	packet := new(bytes.Buffer)
	err := binary.Write(packet, binary.LittleEndian, header)
	if err != nil {
		return fmt.Errorf("Failed to write header into packet: %v", err)
	}

	// you might want to rewrite this with []byte and putuint for better efficiency (less allocs)
	for _, pid := range pids {
		err = binary.Write(packet, binary.LittleEndian, pid)
		if err != nil {
			return fmt.Errorf("Failed to write list of pids into packet: %v", err)
		}
	}
	//* send packet
	cmdConnMu.Lock()
	n, err := conn.Write(packet.Bytes())
	cmdConnMu.Unlock()
	if err != nil {
		return fmt.Errorf("Failed to send packet to ETW consumer: %v", err)
	}
	if n < packet.Len() {
		return fmt.Errorf("Partial write to ETW consumer (%d/%d)", n, packet.Len())
	}
	return nil
}

func SendEtwUntrackCmd(conn net.Conn, pids []uint32) error {
	if conn == nil {
		return fmt.Errorf("pipe not initialized")
	}

	header := EtwCmd{
		Type:     ETW_CMD_PLIST_REMOVE,
		DataSize: uint64(len(pids) * 4), // DWORD 4 byte values
	}

	packet := new(bytes.Buffer)
	err := binary.Write(packet, binary.LittleEndian, header)
	if err != nil {
		return fmt.Errorf("Failed to write header into packet: %v", err)
	}

	// you might want to rewrite this with []byte and putuint for better efficiency (less allocs)
	for _, pid := range pids {
		err = binary.Write(packet, binary.LittleEndian, pid)
		if err != nil {
			return fmt.Errorf("Failed to write list of pids into packet: %v", err)
		}
	}
	//* send packet
	cmdConnMu.Lock()
	n, err := conn.Write(packet.Bytes())
	cmdConnMu.Unlock()
	if err != nil {
		return fmt.Errorf("Failed to send packet to ETW consumer: %v", err)
	}
	if n < packet.Len() {
		return fmt.Errorf("Partial write to ETW consumer (%d/%d)", n, packet.Len())
	}
	return nil
}

func SendEtwShutdownCmd(conn net.Conn) error {
	if conn == nil {
		return fmt.Errorf("pipe not initialized")
	}

	var header EtwCmd
	header.Type = ETW_CMD_SHUTDOWN

	packet := new(bytes.Buffer)
	err := binary.Write(packet, binary.LittleEndian, header)
	if err != nil {
		return fmt.Errorf("Failed to write header into packet: %v", err)
	}

	//* send packet
	cmdConnMu.Lock()
	n, err := conn.Write(packet.Bytes())
	cmdConnMu.Unlock()
	if err != nil {
		return fmt.Errorf("Failed to send packet to ETW consumer: %v", err)
	}
	if n < packet.Len() {
		return fmt.Errorf("Partial write to ETW consumer (%d/%d)", n, packet.Len())
	}
	return nil
}
