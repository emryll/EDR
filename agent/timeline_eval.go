package main

import (
	"fmt"
	"strings"
)

type ComponentResult struct {
	Exists          bool
	Required        bool
	FirstTimestamps []int64
	LastTimestamps  []int64
	Bonus           int
}

func RemoveFromSlice[T any](slice []T, index int, amount int) []T {
	return append(slice[:index], slice[index+amount:]...)
}

func RemoveSliceMember[T any](slice []T, index int) []T {
	return append(slice[:index], slice[index+1:]...)
}

// at this components have already been individually checked,
// and the timeline doesnt matter for these, therefore we can just remove them.
func EvaluateTimelessComponents(logic []string) []string {
	// walk it until there is no more time-insensitive components,
	// each time you find one, process and remove it
	for logic[1] == "+" {
		logic = logic[2:]
	}
	// now same thing backwards
	for logic[len(logic)-2] == "+" {
		logic = logic[:len(logic)-2]
	}
	return logic
}

func EvaluateParantheses(logic []string, components map[string]*ComponentResult) []string {
	// find all parantheses
	var start int // this saves the start of current parantheses
	for i, token := range logic {
		if token[0] == '(' {
			start = i
		}

		if token[len(token)-1] == ')' {
			ReduceFlatBlock(logic[start:i+1], components)
			//TODO replace the strings with a tmp one and add result to components map
		}
	}
	return logic
}

//IMPORTANT: this does not take into account a timerange, as that would add a lot of complexity
// into the check, making it much slower. It also does not add much value, since you already have
// a set time limit for telemetry collection. In the future timerange may be added to patterns and checks.
func ReduceFlatBlock(logic []string, components map[string]*ComponentResult) ComponentResult {
	// first remove parantheses if there are any
	if logic[0][0] == '(' {
		logic[0] = logic[0][1:]
	}
	lastToken := len(logic) - 1
	if logic[lastToken][len(logic[lastToken])-1] == ')' {
		logic[lastToken] = logic[lastToken][:len(logic[lastToken])-1]
	}

	var result ComponentResult
	// First make sure the first one exists because you start iterating at second one
  for !components[logic[0]].Exists {
    if components[logic[0]].Required {
      return ComponentResult{Exists: false, Required: true}
    }
    logic = RemoveFromSlice(logic, 0, 2)
  }
  if len(logic) == 0 { // above loop could remove it all technically, and below loop would panic with out of bounds access
    return ComponentResult{Exists: false, Required: true}
  }

	// iterate through the rest
	for i := 2; i < len(logic); {
    //TODO check if it exists: if it does not and is required, return false
    //TODO if it does not and is not required, remove it from the logic string
    //TODO from previous component remove the timestamps which are larger than any of current ones stamps
    //TODO what about the last one? wouldnt it end up not being checked...
		comp := components[logic[i]]
		// start by checking if it exists
		if !comp.Exists {
			if comp.Required {
				return ComponentResult{Exists: false, Required: true}
			}
			// remove from the timeline
			logic = RemoveFromSlice(logic, i, 2)
			continue
		}

		var (
			prevStamps         []int64
			validTimelineFound bool
		)
		if components[logic[i-2]].LastTimestamps == nil || len(components[logic[i-2]].LastTimestamps) == 0 {
			prevStamps = components[logic[i-2]].FirstTimestamps
		} else {
			prevStamps = components[logic[i-2]].LastTimestamps
		}
		// now make sure it is in the right chronological order
		// iterating backwards so you can remove from the slice while iterating
	Previous:
		for n := len(prevStamps) - 1; n >= 0; n-- {
			for j := len(comp.FirstTimestamps) - 1; j >= 0; j-- {
				if comp.FirstTimestamps[j] >= prevStamps[n] {
					validTimelineFound = true
					continue Previous
				}
			}
			// none match this timeline, so it cannot be valid
			//TODO except it could be valid if current one is an optional component! fix that
			prevStamps = RemoveSliceMember(prevStamps, n)
		}

		if !validTimelineFound {
      //TODO except if it is an optional component, remove and continue
			if comp.Required {
				return ComponentResult{Exists: false, Required: true}
			}
			logic = RemoveFromSlice(logic, i, 2)
		}

		components[logic[i-2]].LastTimestamps = prevStamps
		result.Bonus += comp.Bonus
		i += 2
	}
	return result
}

// returns boolean result and bonus score.
/*func EvaluateFlatTimeline(logic []string, components map[string]ComponentResult) (bool, int) {

}


// at this point individual components were already checked
// return value is the boolean result (did it match) and the accumulated bonus score
func EvaluateTimeline(logic string, components map[string]ComponentResult) (bool, int) {
  tokens := strings.Fields(logic)

  tokens = EvaluateTimelessComponents(tokens, components)
  tokens = EvaluateParantheses(tokens, components)
  tokens = EvaluateConditionalBranches(tokens, components)
  return EvaluateFlatTimeline(tokens, components)
}
*/

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
        end := GetEndOfParantheses()
        if end != -1 {
          i = end
          continue
        }
      }
			insideBranch = false
			reduced := ReduceConditionalBranch(logic[i:start+1], components)
			// replace it in the logic string
			logic = RemoveFromSlice(logic, i, len(logic[i:start]))
			tmpName := DerivePlaceholderName(logic[i : start+1])
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

    // if this component is a reduced one, it has two edges in the timeline, and that must be taken into account
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

func DerivePlaceholderName(block []string) string {
	return strings.Join(block, "_")
}

// determine if a given component is inside of parantheses. also works for nested parantheses
func IsInsideParantheses(logic []string, index int) bool {
	// just walk to one side to see if you find a "(" without it closing
	var (
		limit   int
		nesting rune
		closing rune // the closing bracelet, as in it includes this one
		depth   int  // for tracking incoming brackets the wrong way (counter for how many closing bracelets are needed)
		walk    int  // this is to enable iteration forwards or backwards (shortest one)
	)
	if index > (len(logic) / 2) {
		// walk forward
		limit = len(logic) - 1
		closing = ')'
		nesting = '('
		walk = 1
	} else {
		// walk backwards
		limit = 0
		closing = '('
		nesting = ')'
		walk = -1
	}
	for index >= limit {
		switch rune(logic[index][0]) {
		case nesting:
			depth++
		case closing:
			if depth == 0 {
				return true
			}
			depth--
		}
		index += walk
	}
	return false
}

// function for checking if a component in a timeline is a part of a conditional
func IsInsideConditional(logic []string) bool {

}

func PrintTokens(tokens []string, head string) {
	if head == "" {
		fmt.Printf("[debug]")
	} else {
		fmt.Printf("%s", head)
	}
	for _, str := range tokens {
		fmt.Printf(" %s", str)
	}
	fmt.Printf("\n")
}

func main() {
	test1 := "c1 + c2 + c3 -> c4 or (c5 -> c6) + c7"
	r := EvaluateTimelessComponents(strings.Fields(test1))
	fmt.Printf("test1 result (%s):\n", test1)
	PrintTokens(r, "\t")
	//EvaluateParantheses(r, nil)
	EvaluateConditionalBranches(r, nil)

	test2 := "c1 -> c4 or (c5 -> c6) + c7"
	r = EvaluateTimelessComponents(strings.Fields(test2))

	fmt.Printf("test2 result (%s):\n", test2)
	PrintTokens(r, "\t")
	//EvaluateParantheses(r, nil)

	test3 := "c1 -> c4 or (c5 -> c6)"
	r = EvaluateTimelessComponents(strings.Fields(test3))

	fmt.Printf("test3 result (%s):\n", test3)
	PrintTokens(r, "\t")
	//EvaluateParantheses(r, nil)
}


func CreateTestTimeline(option int) (string, map[string]ComponentResult) {
  switch option {
  case 0: // should be a match with 30 bonus
    timeline := "c1 + c2 -> c3 -> c4 or (c5 -> c6) + c7"
    components := make(map[string]ComponentResult)
    components["c1"] = ComponentResult{
      Exists: false,
      Required: false,
    }
    components["c2"] = ComponentResult{
      Exists: true,
      Required: false,
      FirstTimestamps: [1860, 2857, 8429]
    }
    components["c3"] = ComponentResult{
      Exists: true,
      Required: false,
    }
    components["c4"] = ComponentResult{}
    components["c5"] = ComponentResult{}
    components["c6"] = ComponentResult{ // not required, bonus
      Exists: true,
      Required: false,
      Bonus: 20,
      FirstTimestamps: []
    }
    components["c7"] = ComponentResult{
      Exists: true,
      Required: false,
      Bonus: 10
    }

    return timeline, components
  case 1:
    timeline := ""
    components := make(map[string]ComponentResult)
    return timeline, components
  case 2:
    timeline := ""
    components := make(map[string]ComponentResult)
    return timeline, components
  }
  return "", nil
}
*/
