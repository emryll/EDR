package main

import (
	"strings"
)

//?====================================================================================================+
//?    This set of functions is responsible for evaluating the chronological timeline of a             |
//?  behavioral pattern. At this point each individual components existance has already been checked.  |
//?====================================================================================================+

// The terms "logic" and "timeline" are used interexchangably here, both refer to the same thing.
// The timeline is typically represented as a slice of words, instead of a single string, for ease of parsing.
// The idea for solving a timeline is to simplify it one step at a time, until it becomes a simple linear timeline.

// IMPORTANT: this timeline evaluation does not take into account a timerange, as that would add a lot of
// complexity into the checks, making it much slower. It also does not add much value, since you already have
// a set time limit for telemetry collection. In the future timerange may be added to patterns and checks.

// This is the outer function to be called; it handles the entire evaluation process.
// Components refers to a map containing the results of forementioned per-component checks.
// Return value is the boolean result (did it match) and the accumulated bonus score.
func EvaluateTimeline(timeline string, components map[string]*ComponentResult) (bool, int) {
	tokens := strings.Fields(timeline)
	if len(tokens) < 3 {
		if timeline == "" || components == nil || len(components) == 0 {
			return true, 0
		}
		return components[tokens[0]].Exists, components[tokens[0]].Bonus
	}

	var firstBonus int // timeless components
	tokens, firstBonus = EvaluateTimelessComponents(tokens, components)
	tokens = EvaluateParantheses(tokens, components)
	tokens = EvaluateConditionalBranches(tokens, components)
	result, bonus := EvaluateFlatTimeline(tokens, components)
	return result, bonus + firstBonus
}

// This function is responsible for checking/solving the time-insensitive components (+).
// At this point components have already been individually checked, and early exits have been made.
// It can be assumed that these exist, and the timeline doesnt matter for these, therefore we can just remove them.
func EvaluateTimelessComponents(logic []string, components map[string]*ComponentResult) ([]string, int) {
	// find and remove them from the start of timeline. Accumulate bonus if any
	var bonus int
	for logic[1] == "+" {
		bonus += components[logic[0]].Bonus
		logic = logic[2:]
	}
	// now same thing backwards
	for logic[len(logic)-2] == "+" {
		bonus += components[logic[len(logic)-1]].Bonus
		logic = logic[:len(logic)-2]
	}
	return logic, bonus
}

// This function is responsible for solving (getting rid of) conditional branches.
// It will return the altered timeline string and make the appropriate changes to the components map.
func EvaluateConditionalBranches(logic []string, components map[string]*ComponentResult) []string {
	var (
		insideBranch bool
		end          int
	)
	for i := len(logic) - 1; i >= 0; i -= 2 {
		// make sure its not just a parantheses block (there shouldnt be any though?? they were solved before this)
		if logic[i][len(logic[i])-1] == ')' {
			start := GetStartOfParantheses(logic, i)
			if start != -1 {
				logic = checkOrBlockToLeft(logic, start, i, &insideBranch, &end, components)
				i = start // jump over the parantheses
				continue
			}
		}
		// this is if no parantheses were encountered/skipped. they are treated differently, because if it
		// starts with parantheses and after it comes "or", you havent saved the real beginning of the or-block
		logic = checkOrBlockToLeft(logic, i, i, &insideBranch, &end, components)
	}
	return logic
}

// inner function for one iteration of a walk to find complete or-block.
func checkOrBlockToLeft(logic []string, index int, begin int, insideBranch *bool, end *int, components map[string]*ComponentResult) []string {
	if index > 0 && strings.ToLower(logic[index-1]) == "or" {
		if !*insideBranch {
			*insideBranch = true
			*end = begin // if parantheses were just jumped over, you want the beginning edge of it.
		}
	} else if *insideBranch { // previously inside or-block, no longer in or block,
		*insideBranch = false
		reduced := ReduceConditionalBranch(logic[index:(*end)+1], components)
		logic = ReplaceWithReduced(logic, index, *end, reduced, components)
	}
	return logic
}

// This is the inner part of evaluating conditional branches. This function will take a single conditional block,
// solving it into one reduced component, which is then returned. No changes are made to the components map.
func ReduceConditionalBranch(orBlock []string, components map[string]*ComponentResult) ComponentResult {
	var result ComponentResult
	for i := 0; i < len(orBlock); i += 2 {
		comp := components[orBlock[i]]
		if !comp.Exists {
			continue
		}
		result.Exists = true

		// if this component is a reduced one, it has two edges in the timeline, that must be taken into account.
		if comp.LastTimestamps == nil || len(comp.LastTimestamps) == 0 {
			result.FirstTimestamps = append(result.FirstTimestamps, comp.FirstTimestamps...)
			result.LastTimestamps = append(result.LastTimestamps, comp.FirstTimestamps...)
		} else { // normal ones are copied to both lists so they work on both sides of the timeline comparison
			result.FirstTimestamps = append(result.FirstTimestamps, comp.FirstTimestamps...)
			result.LastTimestamps = append(result.LastTimestamps, comp.LastTimestamps...)
		}
	}
	return result
}

// returns boolean result and bonus score.
func EvaluateFlatTimeline(logic []string, components map[string]*ComponentResult) (bool, int) {
	// its possible components were reduced into a single component in previous steps
	if len(logic) < 3 {
		if len(logic) > 0 && components != nil && len(components) != 0 {
			return components[logic[0]].Exists, components[logic[0]].Bonus
		}
		return false, 0
	}
	result := ReduceFlatBlock(logic, components)
	return result.Exists, result.Bonus
}

// This function solves a linear timeline into one result component. No changes are made to the map.
func ReduceFlatBlock(logic []string, components map[string]*ComponentResult) ComponentResult {
	// first remove parantheses if there are any (i.e. if this is called for solving parantheses)
	if logic[0][0] == '(' {
		logic[0] = logic[0][1:]
	}
	lastToken := len(logic) - 1
	if logic[lastToken][len(logic[lastToken])-1] == ')' {
		logic[lastToken] = logic[lastToken][:len(logic[lastToken])-1]
	}

	var result ComponentResult
	// First make sure the first one exists because you start iterating at second one; first is always valid if it exists, there is no comparison
	for !components[logic[0]].Exists {
		if components[logic[0]].Required {
			return ComponentResult{Exists: false, Required: true}
		}
		logic = RemoveFromSlice(logic, 0, 2)
	}
	if len(logic) < 3 { // above loop could remove it all technically, or all but one, and below loop would panic with out of bounds access
		if len(logic) == 0 {
			return ComponentResult{Exists: false, Required: true}
		}
		return *components[logic[0]]
	}

	// iterate through the rest of components, checking if previous one has a valid timeline for it.
	for i := 2; i < len(logic); { //TODO: "a -> b" will skip and return true because 3 is not < 3. WHAT IS THE NEED FOR i+1 < len(logic)????
		comp := components[logic[i]]
		// start by checking if it exists
		if !comp.Exists {
			if comp.Required {
				return ComponentResult{Exists: false, Required: true}
			}
			// remove non-existent optional component from the timeline
			logic = RemoveFromSlice(logic, i, 2)
			continue
		}

		var (
			prevStamps         []int64
			validTimelineFound bool
		)
		// if it has stamps listed in the end "edge", compare against those (i.e. reduced blocks)
		if components[logic[i-2]].LastTimestamps == nil || len(components[logic[i-2]].LastTimestamps) == 0 {
			prevStamps = components[logic[i-2]].FirstTimestamps
		} else {
			prevStamps = components[logic[i-2]].LastTimestamps
		}
		// iterate the stamps of current component, check if there is any timestamps from
		// previous component which are not greater than the current stamp. If none are found it is removed.
	Current:
		for n := len(comp.FirstTimestamps) - 1; n >= 0; n-- {
			for j := len(prevStamps) - 1; j >= 0; j-- {
				if comp.FirstTimestamps[n] >= prevStamps[j] {
					validTimelineFound = true
					continue Current
				}
			}
			// no valid continuation from previous component was found, so this timeline is not possible.
			components[logic[i]].FirstTimestamps = RemoveSliceMember(components[logic[i]].FirstTimestamps, n)
		}

		if !validTimelineFound {
			if comp.Required {
				return ComponentResult{Exists: false, Required: true}
			}
			logic = RemoveFromSlice(logic, i, 2)
			continue
		}
		result.Bonus += comp.Bonus
		i += 2 // incrementing manually so you can choose not to increment when you remove items
	}
	//* so since it reached this point, all components fit into a valid timeline
	//* now add the edge timestamps and return positive result (match)
	result.Exists = true
	result.FirstTimestamps = append(result.FirstTimestamps, components[logic[0]].FirstTimestamps...)
	result.FirstTimestamps = append(result.FirstTimestamps, components[logic[0]].LastTimestamps...)
	result.LastTimestamps = append(result.LastTimestamps, components[logic[len(logic)-1]].FirstTimestamps...)
	result.LastTimestamps = append(result.LastTimestamps, components[logic[len(logic)-1]].LastTimestamps...)
	return result
}

func ReplaceWithReduced(logic []string, start int, end int, reduced ComponentResult, components map[string]*ComponentResult) []string {
	tmpName := DerivePlaceholderName(logic[start : end+1])
	components[tmpName] = &reduced
	logic = RemoveFromSlice(logic, start, len(logic[start:end]))
	logic[start] = tmpName
	return logic
}

// create the name of a reduced branch
func DerivePlaceholderName(block []string) string {
	return strings.Join(block, "_")
}

// determine if a given component is inside of parantheses. also works for nested parantheses. walks in the direction which is shortest.
func IsInsideParantheses(logic []string, index int) bool {
	var (
		limit   int
		closing rune // the closing bracelet; as in, it includes this one. this allows iteration both ways
		depth   int  // for tracking incoming brackets the wrong way (counter for how many closing brackets are needed)
		walk    int  // this is to enable iteration forwards or backwards (shortest one)
	)
	if index > (len(logic) / 2) {
		// walk forward
		limit = len(logic) - 1
		closing = ')'
		walk = 1
	} else {
		// walk backwards
		limit = 0
		closing = '('
		walk = -1
	}
	// walk until you find a closing bracelet or end of slice. take into account nested parantheses.
	for ; indexBeforeLimit(index, limit, walk); index += walk {
		delta := getParanthesesCount(logic[index], closing)
		depth -= delta
		if delta > 0 && depth < 0 {
			return true
		}
	}
	return false
}

// check if limit of iteration has been exceeded. this allows iteration both ways
func indexBeforeLimit(index int, limit int, walk int) bool {
	if walk > 0 { // walk forwards
		return index <= limit
	} else { // walk backwards
		return index >= limit
	}
}

// parantheses is the one you want the count for. for example: with "(a))", parantheses as ")" will return 1, while with "(" -1
func getParanthesesCount(token string, parantheses rune) int {
	var count int
	for token[len(token)-1] == ')' {
		token = token[:len(token)-1]
		count++
	}
	for token[0] == '(' {
		token = token[1:]
		count--
	}
	if parantheses == '(' { // ")" is used as the default
		return -count
	}
	return count
}

// takes the starting index of parantheses and returns end
func GetEndOfParantheses(tokens []string, index int) int {
	var depth int
	for i := index; index < len(tokens); i++ {
		switch tokens[i][len(tokens[i])-1] {
		case ')':
			if depth == 0 {
				return i
			}
			depth--
		case '(':
			depth++
		}
	}
	return index
}

// takes the ending index of parantheses and returns start
func GetStartOfParantheses(tokens []string, index int) int {
	var depth int
	for i := index; index >= 0; i-- {
		switch tokens[i][0] {
		case '(':
			if depth == 0 {
				return i
			}
			depth--
		case ')':
			depth++
		}
	}
	return index
}
