package main

import (
	"strings"
)

// at this point individual components were already checked
// return value is the boolean result (did it match) and the accumulated bonus score
func EvaluateTimeline(logic string, components map[string]*ComponentResult) (bool, int) {
	var firstBonus int // timeless components
	tokens := strings.Fields(logic)

	tokens, firstBonus = EvaluateTimelessComponents(tokens, components)
	tokens = EvaluateParantheses(tokens, components)
	tokens = EvaluateConditionalBranches(tokens, components)
	result, bonus := EvaluateFlatTimeline(tokens, components)
	return result, bonus + firstBonus
}

// at this components have already been individually checked, so it can be assumed
// that they exist, and the timeline doesnt matter for these, therefore we can just remove them.
func EvaluateTimelessComponents(logic []string, components map[string]*ComponentResult) ([]string, int) {
	// walk it until there is no more time-insensitive components,
	// each time you find one, process and remove it
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

func EvaluateConditionalBranches(logic []string, components map[string]*ComponentResult) []string {
	// find all OR blocks
	var (
		insideBranch bool
		start        int
	)
	for i := len(logic) - 1; i >= 0; i -= 2 {
		if i > 0 && strings.ToLower(logic[i-1]) == "or" {
			if !insideBranch {
				insideBranch = true
				start = i
			}
		} else if insideBranch { // or block has now ended
			// make sure its not just a parantheses block (there shouldnt be any though??)
			if logic[i][len(logic[i])-1] == ')' {
				end := GetEndOfParantheses(logic, i)
				if end != -1 {
					i = end
					continue
				}
			}
			insideBranch = false
			reduced := ReduceConditionalBranch(logic[i:start+1], components)
			// replace it in the logic string
			tmpName := DerivePlaceholderName(logic[i : start+1])
			logic = RemoveFromSlice(logic, i, len(logic[i:start]))
			components[tmpName] = &reduced
			logic[i] = tmpName
		}
	}
	return logic
}

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
