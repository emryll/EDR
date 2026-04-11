package main

import (
	"sync"
)

//  this file is for the experimental process pool idea, for multi-process correlation
//  it is going to be fully implemented in later versions but already basing some stuff on the skeleton

// Represents a group of processes with some sort of connection.
/*type Pool struct {
	mu          sync.RWMutex
	Connections map[uint32]map[uint32]Connection // node(pid) -> next(pid)
	//TODO: add merged telemetry storage access
}
*/
type Pool struct {
	mu          sync.RWMutex
	Members map[uint32]*Process // connections in process struct
	Untracked map[uint32]map[uint32] // node(pid) -> next(pid)
	//TODO: add merged telemetry storage access
}
// Connections are stored in a map in Process structure
type Connection struct {
	Type   Bitmask
	Weight int
}

/*
* Pool connections should not be directly tied to Process struct,
* this way it also allows processes which are not tracked.
*
* However, it would be good to have a node based structure,
* so that you could just "rebuild" all soft pools for merging.
*
* Connecting two pools is a problem!
 */

/*
* To rebuild pools, iterate processes
*/


//TODO: todo add a way to figure out which soft pool a given process is in

//TODO: should probably create a function create the base pools from process list

/*func CreatePool(processes ...*Process) Pool {
	var pool Pool
	for _, process := range processes {
		pool[]
	}
	return pool
}*/

var PoolRegistry []*Pool // should there be an id?
func RefreshPools() []*Pool {}

// add new connection or add on top of existing
// weight is incremented by the specified amount
func (p *Pool) AddConnection(flags Bitmask, weight int, node1 uint32, node2 uint32) {
	//TODO: this should take into account the merging of pools
	if processes[int(node1)].SoftPool != processes[int(node2)].SoftPool {
		p.Merge() //TODO: untracked processes are the problem? what to do with them?
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	if p.Connections[node1] == nil {
		p.Connections[node1] = make(map[uint32]Connection)
	}
	if p.Connections[node2] == nil {
		p.Connections[node2] = make(map[uint32]Connection)
	}
	conn_k := p.Connections[node1][node2]
	conn_n := p.Connections[node2][node1]
	// alter edges
	conn_k.Weight += weight
	conn_n.Weight += weight
	conn_k.Type |= flags
	conn_k.Type |= flags
	// add connection
	p.Connections[node1][node2] = conn_k
	p.Connections[node2][node1] = conn_n
}

// remove weight or type from connection
// if the connection doesnt exist, or they dont have the flags, no-op
func (p *Pool) StripConnection(flags Bitmask, weight int, node1 uint32, node2 uint32) {
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
func (p *Pool) RemoveConnection(node1 uint32, node2 uint32) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.Connections[node1] == nil || p.Connections[node2] == nil {
		return
	}

	delete(p.Connections[node1], node2)
	delete(p.Connections[node2], node1)
	//TODO: should you also check if each node's pool changed?
}


//*===================[ Object Access Lookup ]==========================

// Describe an interaction with an object
type AccessEntry struct {
	Object uint32 // type enum
	Name   string // name of object
	Type   Bitmask // type of interaction
	Handle uint32 // the process handle to the object
}

// Lookup table for object interactions
// 500 000 entries would be around 32MB
type ObjectAccessRegistry struct {
	mu sync.RWMutex // used internally in methods
	// process -> object type -> name -> entry
	ProcessLookup map[uint32]map[uint32]map[string][]*AccessEntry // array is for anon objects
	// object type -> name -> process -> entry 
	ObjectLookup map[uint32]map[string]map[uint32][]*AccessEntry
}

// Add an interaction to the registry. Updates existing if one exists.
func (reg *ObjectAccessRegistry) AddEntry(entry AccessEntry, pid uint32) {
	reg.mu.Lock()
	defer reg.mu.Unlock()
	// check that maps are initialized (avoid panic)
	if reg.ProcessLookup[pid] == nil {
		reg.ProcessLookup[pid] = make(map[uint32]map[string][]*AccessEntry)
	}
	if reg.ProcessLookup[pid][entry.Object] == nil {
		reg.ProcessLookup[pid][entry.Object] = make(map[string][]*AccessEntry)
	}
	if reg.ObjectLookup[entry.Object] == nil {
		reg.ObjectLookup[entry.Object] = make(map[uint32]map[string][]*AccessEntry)
	}
	if reg.ObjectLookup[entry.Object][entry.Name] == nil {
		reg.ObjectLookup[entry.Object][entry.Name] = make(map[uint32][]*AccessEntry)
	}
	
	// check if entry exists, update existing if does
	entries := FindEntry(pid, entry.Object, entry.Name)
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
	reg.ProcessLookup[pid][entry.Object][entry.Name] = append(reg.ProcessLookup[pid][entry.Object][entry.Name], &e)
	reg.ObjectLookup[entry.Object][entry.Name][pid] = append(reg.ObjectLookup[entry.Object][entry.Name][pid], &e)
}