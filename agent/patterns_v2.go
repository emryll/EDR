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
func (c FileComponent) IsMatch(p *Process) ComponentMatch {
	var result ComponentMatch
	if c.UniversalOverride != nil && !c.UniversalOverride.Check(p) {
		return result // false
	}
	// file events are currently stored in a map that points to a directory,
	//  which is a map containing the files of that directory.
	// In the future this will structure will be reworked to be recursive.
	// One or more of either name or dir options must be defined, this is
	//  enforced by the syntax checker, so don't need to worry about it here.


	//TODO: check if any files are in pathoptions
	var dirFound bool
	if len(c.DirOptions) == 0 {
		dirFound = true
	}


	
	//TODO: check dir options
	//TODO: check dir not options
	//TODO: if no name or dir is defined, search any path (iterate map...)




	// one of these must be found
	for _, path := range c.DirOptions {
		if _, exists := p.FileEventDir[path]; exists {
			pathFound = true
			break
		}
	}
	if !pathFound {w
		return ComponentMatch{Match: false}
	}

	//TODO: allow names like "*.txt"
	for _, name := range c.NameOptions {
		if _, exists := p.FileEventDir[filepath.Dir(name)][filepath.Base(name)]
	}
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
