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
