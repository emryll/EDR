package main

import (
	"encoding/binary"
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
			components[component.GetName()] = component.GetResult()
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
	if c.UniversalOverride != nil && !c.UniversalOverride.Check(p) {
		return &ComponentResult{Exists: false, Required: c.IsRequired()}
	}
Options:
	//* first check if any of these apis exist in history
	for _, fn := range c.Options {
		api, exists := p.APICalls[fn]
		if !exists {
			continue
		}
		//* now check that the defined conditions apply to this api
		for _, condition := range c.Conditions {
			if !condition.Check(p, api) {
				continue Options
			}
		}
		//? collect timestamps so you can check if any align in the timeline of other components
		result.FirstTimestamps = append(result.FirstTimestamps, api.TimeStamp)
		for _, a := range api.History {
			result.FirstTimestamps = append(result.FirstTimestamps, a.TimeStamp)
		}
		result.Exists = true
		result.Bonus = c.Bonus
		result.Required = c.IsRequired()
	}
	return &result
}

// Method to implement Component interface.
// This tells if the component matched, and returns the timestamp options.
func (c FileComponent) GetResult(p *Process) *ComponentResult {
	var result ComponentResult
	if c.UniversalOverride != nil && !c.UniversalOverride.Check(p) {
		return result // false
	}
	// file events are currently stored in a map that points to a directory,
	//  which is a map containing the files of that directory.
	// In the future this will structure will be reworked to be recursive.
	// One or more of either name or dir options must be defined, this is
	//  enforced by the syntax checker, so don't need to worry about it here.

	//TODO get corresponding events
	//TODO for this you need to inspect the file filter, to see if name/dir options are defined
	var filter FileFilter
	for _, set := range c.Conditions {
		if v, ok := set.(FileFilter); ok {
			filter = v
		}
	}
	//TODO if name or dir is not defined, look up events by action
	var events []*FileEvent
	if len(filter.Path) == 0 && len(filter.Dir) == 0 {
		events = append(events, p.FileEvents.FileActionTree[c.Action]...)
	} else if len(filter.Path) > 0 { // if path options are defined, dir will not be used
		for _, path := range filter.Path {
			dir := filepath.Dir(path)
			// this one has one event entry for each action on that file
			events = append(events, p.FileEvents.FilePathTree[dir][filepath.Base(path)]...)
		}
	} else if len(filter.Dir) > 0 {
		for _, dir := range filter.Dir {
			for _, event := range p.FileEvents.FilePathTree[dir] {
				events = append(events, event...)
			}
		}
	}

Events:
	for _, event := range events {
		for _, condition := range c.Conditions {
			if !condition.Check(p, event) {
				continue Events
			}
		}
		//? collect timestamps so you can check if any align in the timeline of other components
		result.FirstTimestamps = append(result.FirstTimestamps, event.TimeStamp)
		for _, e := range event.History {
			result.FirstTimestamps = append(result.FirstTimestamps, e.TimeStamp)
		}
		result.Exists = true
		result.Bonus = c.Bonus
		result.Required = c.IsRequired()
	}
	return &result
}

// Method to implement Component interface.
// This tells if the component matched, and returns the timestamp options.
func (c RegComponent) IsMatch(p *Process) ComponentMatch {
	var result ComponentMatch
	if c.UniversalOverride != nil && !c.UniversalOverride.Check(p) {
		return result // false
	}
	//TODO:
}

func (p Parameter) GetValue() any {
	switch p.Type {
	//TODO
	}
}
