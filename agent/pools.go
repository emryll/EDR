package main

import (
	"sync"
)

//  this file is for the experimental process pool idea, for multi-process correlation
//  it is going to be fully implemented in later versions but already basing some stuff on the skeleton

// A pool is a subset of a graph,
// based on a read-only snapshot
type Pool map[uint32]*ProcessNode

type Graph struct {
	mu      sync.RWMutex
	Members map[uint32]*ProcessNode
}

type ProcessNode struct {
	Process     *Process
	Connections map[uint32]*Connection
}

type Connection struct {
	Target *ProcessNode
	Weight uint8
	Type   Bitmask
}

type GraphEntry struct {
	id    int
	Graph *Graph
}

type GraphRegistry map[uint32]Graph // key is id

var (
	g_ObjectAccessRegistry *ObjectAccessRegistry
	g_GraphRegistry        GraphRegistry // should there be an id?
)

// add new connection or add on top of existing
// weight is incremented by the specified amount
func (g *Graph) AddConnection(flags Bitmask, weight int, node1 uint32, node2 uint32) {
	//TODO: this should take into account the merging of pools
	if GetProcessGraph(node1) != GetProcessGraph(node2) {
		g.Merge() //TODO: untracked processes are a problem? what to do with them?
	}

	g.mu.Lock()
	defer g.mu.Unlock()
	if g.Connections[node1] == nil {
		g.Connections[node1] = make(map[uint32]Connection)
	}
	if g.Connections[node2] == nil {
		g.Connections[node2] = make(map[uint32]Connection)
	}
	conn_k := g.Connections[node1][node2]
	conn_n := g.Connections[node2][node1]
	// alter edges
	conn_k.Weight += weight
	conn_n.Weight += weight
	conn_k.Type |= flags
	conn_k.Type |= flags
	// add connection
	g.Connections[node1][node2] = conn_k
	g.Connections[node2][node1] = conn_n
}

// remove weight or type from connection
// if the connection doesnt exist, or they dont have the flags, no-op
func (g *Graph) StripConnection(flags Bitmask, weight int, node1 uint32, node2 uint32) {
	if p.Connections[node1] != nil {
		if _, exists := p.Connections[node1][node2]; exists {
			conn := p.Connections[node1][node2]
			conn.Weight -= weight
			conn.Type &^= flags // strip flags
			p.Connections[node1][node2] = conn
			if conn.Type == 0 {
				// note that node1 process struct still points to pool
				delete(p.Connections[node1], node2)
			}
		}
	}
	if p.Connections[node2] != nil {
		if _, exists := p.Connections[node2][node1]; exists {
			conn := p.Connections[node2][node1]
			conn.Weight -= weight
			conn.Type &^= flags // strip flags
			p.Connections[node2][node1] = conn
			if conn.Type == 0 {
				// note that node2 process struct still points to pool
				delete(p.Connections[node2], node1)
			}
		}
	}
}

// no-op if connection does not exist
func (g *Graph) RemoveConnection(node1 uint32, node2 uint32) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.Connections[node1] == nil || p.Connections[node2] == nil {
		return
	}

	delete(p.Connections[node1], node2)
	delete(p.Connections[node2], node1)
	//TODO: should you also check if each node's pool changed?
}

// Merge another graph into this graph.
// This will delete the other graph with merge.
// This method should be used on the larger graph.
func (g *Graph) Merge(other *Graph, graphRegistry GraphRegistry) {
	g.mu.Lock()
	other.mu.Lock()
	defer g.mu.Unlock()
	defer other.mu.Unlock()
	for pid, node := range other.Members {
		g.Members[pid] = node
		SetGraph(pid, g)
	}
	if graphRegistry != nil {
		graphRegistry.Remove(other)
	}
}

type Traversal struct {
	Weight int
	Filter Bitmask
}

// Returns a set of subgraphs constructed with a traversal rule.
// The filter determines which connections count as an edge.
func (g *Graph) CreatePools(filter Traversal) []Pool {
	//TODO: traverse graph with given rules
}

func GetGraph(pid uint32) *Graph {
	processes[int(pid)].graphMu.RLock()
	defer processes[int(pid)].graphMu.RUnlock()
	return processes[int(pid)].ProcessNetwork
}

//*===================[ Object Access Lookup ]==========================

// Describe an interaction with an object
type AccessEntry struct {
	Object uint32  // type enum
	Name   string  // name of object
	Type   Bitmask // type of interaction
	Handle uint32  // the process handle to the object
	Pid    uint32
}

// Lookup table for object interactions
// 500 000 entries would be around 32MB
type ObjectAccessRegistry struct {
	mu sync.RWMutex // used internally in methods
	// process -> object type -> name -> entry
	ProcessLookup map[uint32]map[ProcessAccessKey][]*AccessEntry // array is for anon objects
	// object type -> name -> process -> entry
	ObjectLookup map[uint32]map[ObjectAccessKey][]*AccessEntry
}

// With the triple nested map, amount of maps grows very quickly.
// To fix this issue, the structure is partially flattened.
// Instead of a triple map its a double map with a struct key,
// which has a very big effect on the amount of maps created.

// This key struct is made to flatten ProcessLookup
type ProcessAccessKey struct {
	ObjType uint32
	Name    string
}

// This key struct is made to flatten ObjectLookup
type ObjectAccessKey struct {
	Pid  uint32
	Name string
}

// Add an interaction to the registry. Updates existing if one exists.
func (reg *ObjectAccessRegistry) AddEntry(entry AccessEntry, pid uint32) {
	reg.mu.Lock()
	defer reg.mu.Unlock()
	// check that maps are initialized (avoid panic)
	if reg.ProcessLookup[pid] == nil {
		reg.ProcessLookup[pid] = make(map[ProcessAccessKey][]*AccessEntry)
	}
	if reg.ObjectLookup[entry.Object] == nil {
		reg.ObjectLookup[entry.Object] = make(map[ObjectAccessKey][]*AccessEntry)
	}

	objectKey := entry.CreateObjectKey()
	processKey := entry.CreateProcessKey()

	// check if entry exists, update existing if does
	entries := reg.FindByProcess([]uint32{pid}, []uint32{entry.Object}, entry.Name)
	if len(entries) > 0 {
		for _, ent := range entries {
			if ent.Handle != entry.Handle {
				continue
			}
			ent.Type |= entry.Type
			return
		}
	}

	e := entry // just to be safe with uniqueness...
	reg.ProcessLookup[pid][processKey] = append(reg.ProcessLookup[pid][processKey], &e)
	reg.ObjectLookup[pid][objectKey] = append(reg.ObjectLookup[pid][objectKey], &e)
}

// Delete all interaction entries under a certain process.
// This function should be called when a process exits, to cleanup.
func (reg *ObjectAccessRegistry) RemoveEntriesByProcess(pid uint32) {
	reg.mu.Lock()
	defer reg.mu.Unlock()

	if len(reg.ProcessLookup[pid]) == 0 {
		return
	}

	// remove entries
	for psKey, entries := range reg.ProcessLookup[pid] {
		for _, entry := range entries {
			objKey := ObjectAccessKey{Name: psKey.Name, Pid: pid}
			if len(reg.ObjectLookup[uint32(entry.Type)]) > 0 {
				delete(reg.ObjectLookup[uint32(entry.Type)], objKey)
			}
		}
	}
	delete(reg.ProcessLookup, pid)
}

// Find all corresponding entries based on the acting process.
// @param  pids    The type of object to be accessed.
// @param  objs   (optional) Object type filter for entries.
// @param  names  (optional) Whitelist for object names.
// @return          All matching object access entries.
func (reg *ObjectAccessRegistry) FindByProcess(pids []uint32, objs []uint32, names ...string) []*AccessEntry {
	reg.mu.RLock()
	defer reg.mu.RUnlock()
	if len(pids) == 0 {
		return nil
	}

	var (
		entries    []*AccessEntry
		typeFilter = make(map[uint32]bool)
		nameFilter = make(map[string]bool)
		pidFilter  = make(map[uint32]bool)
	)

	for _, val := range pids {
		pidFilter[val] = true
	}
	for _, val := range objs {
		typeFilter[val] = true
	}
	for _, val := range names {
		nameFilter[val] = true
	}

	for _, pid := range pids {
		if len(reg.ProcessLookup[pid]) == 0 {
			continue
		}
		for objKey, accessEntries := range reg.ProcessLookup[pid] {
			if len(objs) > 0 && !typeFilter[objKey.ObjType] {
				continue
			}
			if len(names) > 0 && !nameFilter[objKey.Name] {
				continue
			}
			entries = append(entries, accessEntries...)
		}
	}
	return entries
}

// Find all corresponding entries based on object description.
// @param  objectType    The type of object to be accessed.
// @param  interaction   (optional) Bitmask describing type of interaction.
// @param  names         (optional) Whitelist for object names.
// @return               All matching object access entries.
func (reg *ObjectAccessRegistry) FindByObject(objectType Bitmask, interaction Bitmask, names ...string) []*AccessEntry {
	if len(reg.ObjectLookup[uint32(objectType)]) == 0 {
		return nil
	}
	var (
		result     []*AccessEntry
		nameFilter = make(map[string]bool)
	)

	for _, name := range names {
		nameFilter[name] = true
	}

	for key, entries := range reg.ObjectLookup[uint32(objectType)] {
		if len(names) > 0 && !nameFilter[key.Name] {
			continue
		}
		for _, entry := range entries {
			if entry.Type.HasFlags(interaction) {
				result = append(result, entry)
			}
		}
	}
	return result
}

// Register a tracked interaction to the registry and graph.
// Before running this you should check that the interaction
// is something used in the relationship graphing (for efficiency).
func (entry *AccessEntry) RegisterInteraction() {
	g_ObjectAccessRegistry.AddEntry(*entry, entry.Pid)

	connections := entry.GetNewConnections()
	if len(connections) == 0 {
		return
	}

	graph := GetGraph(entry.Pid)
	for _, newConn := range connections {
		graph.AddConnection(entry.Type, entry.GetWeight(), entry.Pid, newConn)
	}
}

func (entry *AccessEntry) GetNewConnections() []uint32 {
	entries := g_ObjectAccessRegistry.FindByObject((Bitmask)(entry.Object), entry.Type, entry.Name)
	for _, ent := range entries {
		//TODO: see if the connection is already registered in graph

	}
}

func (entry *AccessEntry) GetWeight() int {
	var weight int
	switch entry.Type {
	//TODO:
	}
	return weight
}

func (entry *AccessEntry) CreateObjectKey() ObjectAccessKey {
	return ObjectAccessKey{Name: entry.Name, Pid: entry.Pid}
}

func (entry *AccessEntry) CreateProcessKey() ProcessAccessKey {
	return ProcessAccessKey{Name: entry.Name, ObjType: entry.Object}
}
