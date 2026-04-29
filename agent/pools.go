package main

import (
	"sync"
)

//  this file is for the experimental process pool idea used for multi-process correlation
//  it is going to be fully implemented in later versions but already basing some stuff on the skeleton

// A pool is a subset of a graph,
// based on a read-only snapshot
type Pool map[uint32]*ProcessNode

type Graph struct {
	id      int
	mu      sync.RWMutex
	Members map[uint32]*ProcessNode
}

type ProcessNode struct {
	ProcessId   uint32 // included for ease / stability with untracked processes
	Process     *Process
	Connections map[uint32]*Connection
}

type Connection struct {
	Target *ProcessNode
	Weight uint32
	Type   Bitmask
}

type GraphRegistry map[int]*Graph // key is id

var (
	ID_COUNTER             = 1
	g_ObjectAccessRegistry *ObjectAccessRegistry
	g_GraphRegistry        GraphRegistry
)

// Returns resulting bitmask after stripping
func (c *Connection) Strip(flags Bitmask, weight int) Bitmask {
	c.Weight -= uint32(weight)
	c.Type &^= flags // strip flags
	return c.Type
}

// Add weight or new connection type to a connection.
func (c *Connection) Expand(flags Bitmask, weight int) {
	c.Weight += uint32(weight)
	c.Type |= flags
}

// Add a graph connection between two processes, or update existing.
// Weight is incremented by the specified amount and flags are appended.
func (g *Graph) AddConnection(flags Bitmask, weight int, node1 uint32, node2 uint32) {
	graph1 := GetGraph(node1)
	graph2 := GetGraph(node2)
	// merge if they are different graphs
	if graph1 != nil && graph2 != nil && graph1 != graph2 {
		if graph1 == g {
			g.Merge(graph2, g_GraphRegistry)
		} else if graph2 == g {
			g.Merge(graph1, g_GraphRegistry)
		} else {
			graph1.Merge(graph2, g_GraphRegistry)
		}
	}

	g.mu.Lock()
	defer g.mu.Unlock()
	// make sure maps are allocated (avoid panic)
	if g.Members[node1] == nil {
		g.Members[node1].Connections = make(map[uint32]*Connection)
	}
	if g.Members[node2] == nil {
		g.Members[node2].Connections = make(map[uint32]*Connection)
	}

	g.Members[node1].Connections[node2].Expand(flags, weight)
	g.Members[node2].Connections[node1].Expand(flags, weight)
}

// remove weight or type from connection IN BOTH NODES.
// if the connection doesnt exist, or they dont have the flags, no-op
func (g *Graph) StripConnection(flags Bitmask, weight int, node1 uint32, node2 uint32) {
	var (
		node1Remove bool
		node2Remove bool
	)
	if g.Members[node1] != nil {
		if _, exists := g.Members[node1].Connections[node2]; exists {
			conn := g.Members[node1].Connections[node2].Strip(flags, weight)
			if conn == 0 { // no connection type left
				node1Remove = true
			}
		}
	} else {
		node1Remove = true
	}
	if g.Members[node2] != nil {
		if _, exists := g.Members[node2].Connections[node1]; exists {
			conn := g.Members[node2].Connections[node1].Strip(flags, weight)
			if conn == 0 {
				node2Remove = true
			}
		}
	} else {
		node2Remove = true
	}

	// a connection could be one-way,
	// so it is fully removed only if
	// there is no connection at all.
	if node1Remove && node2Remove {
		g.RemoveConnection(node1, node2)
	}
}

// no-op if connection does not exist
func (g *Graph) RemoveConnection(node1 uint32, node2 uint32) {
	g.mu.Lock()
	defer g.mu.Unlock()

	if p1, exists := g.Members[node1]; exists && p1 != nil {
		delete(p1.Connections, node2)
		// if there is nothing connecting this process
		// to the current graph, then move it to new one
		if len(p1.Connections) == 0 {
			CreateNewGraph(g_GraphRegistry, p1)
		}
	}

	if p2, exists := g.Members[node2]; exists && p2 != nil {
		delete(p2.Connections, node1)
		// if there is nothing connecting this process
		// to the current graph, then move it to new one
		if len(p2.Connections) == 0 {
			CreateNewGraph(g_GraphRegistry, p2)
		}
	}
}

// Merge another graph into this graph.
// This will delete the other graph with merge.
// This method should be used on the larger graph.
func (g *Graph) Merge(other *Graph, graphRegistry GraphRegistry) {
	g.mu.Lock()
	other.mu.Lock()
	defer g.mu.Unlock()
	defer other.mu.Unlock()

	var (
		larger  *Graph
		smaller *Graph
	)
	// merge smaller into larger for efficiency
	if len(g.Members) > len(other.Members) {
		larger = g
		smaller = other
	} else {
		larger = other
		smaller = g
	}

	for pid, node := range smaller.Members {
		larger.Members[pid] = node
		SetGraph(pid, g)
	}
	if graphRegistry != nil {
		graphRegistry.Remove(smaller)
	}
}

type Traversal struct {
	Weight uint32
	Filter Bitmask
}

func (t Traversal) Passes(c *Connection) bool {
	return c.Weight >= t.Weight && c.Type.HasFlags(t.Filter)
}

// Returns a set of subgraphs constructed with a traversal rule.
// The filter determines which connections count as an edge.
func (g *Graph) CreatePools(filter Traversal) []Pool {
	g.mu.RLock()
	defer g.mu.RUnlock()

	var (
		visited = make(map[uint32]bool)
		pools   []Pool
	)

	for pid := range g.Members {
		if visited[pid] {
			continue
		}
		// breadth first search
		pool := make(Pool)
		queue := []uint32{pid}
		visited[pid] = true

		for len(queue) > 0 {
			curr := queue[0]
			queue = queue[1:]

			node := g.Members[curr]
			pool[curr] = node

			for outPid, conn := range node.Connections {
				if !visited[outPid] && filter.Passes(conn) {
					visited[outPid] = true
					queue = append(queue, outPid)
				}
			}
		}
		pools = append(pools, pool)
	}
	return pools
}

func GetGraph(pid uint32) *Graph {
	processes[int(pid)].graphMu.RLock()
	defer processes[int(pid)].graphMu.RUnlock()
	return processes[int(pid)].ProcessNetwork
}

func SetGraph(pid uint32, graph *Graph) {
	processes[int(pid)].graphMu.Lock()
	defer processes[int(pid)].graphMu.Unlock()
	processes[int(pid)].ProcessNetwork = graph
}

func (r GraphRegistry) Add(graph *Graph) {
	r[graph.id] = graph
}

func (r GraphRegistry) Remove(graph *Graph) {
	delete(r, graph.id)
}

func (r GraphRegistry) Lookup(id int) *Graph {
	if graph, exists := r[id]; exists {
		return graph
	}
	return nil
}

// Create new graph and add it to registry. Start empty or define nodes
func CreateNewGraph(gr GraphRegistry, nodes ...*ProcessNode) *Graph {
	var id int
	for {
		id = ID_COUNTER
		if g := gr.Lookup(id); g == nil {
			break
		}
	}

	graph := Graph{
		id:      id,
		Members: make(map[uint32]*ProcessNode),
	}

	for _, node := range nodes {
		graph.Members[node.ProcessId] = node
	}

	// should you check that connections are valid?
	// it adds slight overhead, but without it nodes
	// could be passed even if they dont form a coherent
	// graph, i.e. there are "islands", not all are connected.

	gr.Add(&graph)
	return &graph
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
	if entry.Type.HasFlags(PG_DIRECT_RELATIVE) {
		weight += PG_DIRECT_RELATIVE_WEIGHT
	}
	if entry.Type.HasFlags(PG_INTERPROCESS_COMMS) {
		weight += PG_INTERPROCESS_COMMS_WEIGHT
	}
	if entry.Type.HasFlags(PG_SAME_FILE_WRITE) {
		weight += PG_SAME_FILE_WRITE_WEIGHT
	}
	if entry.Type.HasFlags(PG_SAME_FILE_READ) {
		weight += PG_SAME_FILE_READ_WEIGHT
	}
	if entry.Type.HasFlags(PG_SAME_DIR_FS_OP) {
		weight += PG_SAME_DIR_FS_OP_WEIGHT
	}
	if entry.Type.HasFlags(PG_SAME_PS_ACCESS) {
		weight += PG_SAME_PS_ACCESS_WEIGHT
	}
	if entry.Type.HasFlags(PG_SAME_MEM_ACCESS) {
		weight += PG_SAME_MEM_ACCESS_WEIGHT
	}
	if entry.Type.HasFlags(PG_PROCESS_EXEC) {
		weight += PG_PROCESS_EXEC_WEIGHT
	}
	if entry.Type.HasFlags(PG_SHARED_SYNC) {
		weight += PG_SHARED_SYNC_WEIGHT
	}
	if entry.Type.HasFlags(PG_SAME_BINARY) {
		weight += PG_SAME_BINARY_WEIGHT
	}
	return weight
}

func (entry *AccessEntry) CreateObjectKey() ObjectAccessKey {
	return ObjectAccessKey{Name: entry.Name, Pid: entry.Pid}
}

func (entry *AccessEntry) CreateProcessKey() ProcessAccessKey {
	return ProcessAccessKey{Name: entry.Name, ObjType: entry.Object}
}
