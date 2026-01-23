package main

import (
	"path/filepath"
)

// This is the function you should call to trigger a behavioral scan for a process.
// It will go through each pattern and check if it matches telemetry history.
// Before running this, BehaviorPatterns global list must be loaded (should happen at startup)
func (p *Process) CheckBehaviorPatterns() Result {
	var matches Result
	for _, pattern := range BehaviorPatterns {
		//* 1. Check universal conditions
		if !pattern.UniversalConditions.Check(p) {
			continue
		}
		//* 2. Check each component and save results
		components := make(map[string]*ComponentResult)
		for _, component := range pattern.Components {
			// syntax checker checks validity of patterns at startup, so don't need to worry about that.
			components[component.GetName()] = component.GetResult(p)
			// later adding early exit here. the problem currently is conditional branches (required in conditional is not strictly required)
		}

		var bonus int // if its < 2 components, there cant be any bonus
		if len(pattern.Components) > 1 {
			//* 3. Evaluate timeline; validating the chronological relationships
			var result bool // avoid bug with shadow variable...
			if result, bonus = EvaluateTimeline(pattern.Timeline, components); !result {
				continue
			}
		} else if len(pattern.Components) == 1 && !components[pattern.Components[0].GetName()].Exists {
			continue // this will later be replaced by early exit in component checks
		}
		match := pattern.GetStdResult(bonus)
		matches.TotalScore += match.Score
		matches.Results = append(matches.Results, match)
	}
	return matches
}

// Method to implement Component interface.
// This tells if the component matched, and returns the timestamp options.
func (c ApiComponent) GetResult(p *Process) *ComponentResult {
	var result ComponentResult
	//* 1. Check potential universal condition override
	if c.UniversalOverride != nil && !c.UniversalOverride.Check(p) {
		return &ComponentResult{Exists: false, Required: c.IsRequired()}
	}
Options:
	//* 2. Retrieve a list of corresponding events
	for _, fn := range c.Options {
		api, exists := p.APICalls[fn]
		if !exists {
			continue
		}
		//* 3. Check if conditions are passed
		for _, condition := range c.Conditions {
			if !condition.Check(p, api) {
				continue Options
			}
		}
		//* 4. Collect timestamps of matches, prepare result
		result.FirstTimestamps = append(result.FirstTimestamps, api.TimeStamp)
		for _, a := range api.History {
			result.FirstTimestamps = append(result.FirstTimestamps, a.TimeStamp)
		}
		result.Exists = true
		result.Bonus = c.Bonus
	}
	result.Required = c.IsRequired()
	return &result
}

// Method to implement Component interface.
// This tells if the component matched, and returns the timestamp options.
func (c FileComponent) GetResult(p *Process) *ComponentResult {
	var result ComponentResult
	//* 1. Check potential universal condition override
	if c.UniversalOverride != nil && !c.UniversalOverride.Check(p) {
		return &ComponentResult{Exists: false, Required: c.IsRequired()}
	}
	var filter FileFilter
	// due to storage structure, need to peek at the filter to retrieve list of events
	for _, set := range c.Conditions {
		if v, ok := set.(FileFilter); ok {
			filter = v
		}
	}
	var events []*FileEvent
	// Look at the FileTelemetryCatalog type to see how file events are stored. (types.go)
	//* 2. Retrieve a list of corresponding events
	if len(filter.Path) == 0 && len(filter.Dir) == 0 {
		events = append(events, p.FileEvents.FileActionTree[int(c.Action)]...)
	} else if len(filter.Path) > 0 { // if path options are defined, dir will not be used
		for _, path := range filter.Path {
			dir := filepath.Dir(path)
			events = append(events, p.FileEvents.FilePathTree[dir][filepath.Base(path)][int(c.Action)])
		}
	} else if len(filter.Dir) > 0 {
		for _, dir := range filter.Dir {
			for _, file := range p.FileEvents.FilePathTree[dir] {
				events = append(events, file[int(c.Action)])
			}
		}
	}

Events:
	for _, event := range events {
		//* 3. Check if conditions are passed
		for _, condition := range c.Conditions {
			if !condition.Check(p, event) {
				continue Events
			}
		}
		//* 4. Collect timestamps of matches, prepare result
		result.FirstTimestamps = append(result.FirstTimestamps, event.TimeStamp)
		for _, e := range event.History {
			result.FirstTimestamps = append(result.FirstTimestamps, e.TimeStamp)
		}
		result.Exists = true
		result.Bonus = c.Bonus
	}
	result.Required = c.IsRequired()
	return &result
}

func (c RegComponent) GetResult(p *Process) *ComponentResult {
	var result ComponentResult
	//* 1. Check potential universal condition override
	if c.UniversalOverride != nil && !c.UniversalOverride.Check(p) {
		return &ComponentResult{Exists: false, Required: c.IsRequired()}
	}
	//? registry events are stored by path (hive+key)
	// need to peek at the filter to retrieve list of events
	var filter RegistryFilter
	for _, set := range c.Conditions {
		if v, ok := set.(RegistryFilter); ok {
			filter = v
		}
	}

	var events []*RegistryEvent
	//* 2. Retrieve a list of corresponding events
	if len(filter.Path) == 0 {
		events = append(events, p.RegEvents.RegActionTree[int(c.Action)]...)
	} else {
		for _, path := range filter.Path {
			events = append(events, p.RegEvents.RegPathTree[path]...)
		}
	}

Events:
	for _, event := range events {
		//* 3. Check if conditions are passed
		for _, condition := range c.Conditions {
			if !condition.Check(p, event) {
				continue Events
			}
		}
		//* 4. Collect timestamps of matches, prepare result
		result.FirstTimestamps = append(result.FirstTimestamps, event.TimeStamp)
		for _, e := range event.History {
			result.FirstTimestamps = append(result.FirstTimestamps, e.TimeStamp)
		}
		result.Exists = true
		result.Bonus = c.Bonus
	}
	result.Required = c.IsRequired()
	return &result
}

// This unfortunately currently parses the entire global handle table, therefore should be avoided
func (c HandleComponent) GetResult(p *Process) *ComponentResult {
	var result ComponentResult
	//TODO: check universal override

	//TODO: Get all handles of this process (same object type)
	//TODO: Check conditions
	1
	return result
}

func (p Parameter) GetValue() any {
	switch p.Type {
	//TODO
	}
}
