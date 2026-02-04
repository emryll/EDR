package main

import (
	"fmt"
	"testing"

	"github.com/fatih/color"
)

func TestTimelineEvaluation(t *testing.T) {
	var (
		count int
		red   = color.New(color.FgRed)
		green = color.New(color.FgGreen)
		stars = "***********************************************************************************************************"
	)
	tests := CreateTimelineTests()
	for i, test := range tests {
		fmt.Printf("\n%s\n\t\tTest case %d: %s\n%s\n\n", stars, i+1, test.Name, stars)
		fmt.Printf("\ttimeline: %s\n", test.Timeline)
		match, bonus := EvaluateTimeline(test.Timeline, test.Components)
		var fail bool
		if match != test.ExpectedMatch {
			fail = true
			red.Printf("[FAIL]")
			fmt.Printf(" \"%s\" unit test failed. Got ", test.Name)
			if match {
				fmt.Printf("match, but was expecting no match.\n")
			} else {
				fmt.Printf("no match, but was expecting match.\n")
			}
		}
		if bonus != test.ExpectedBonus {
			fail = true
			red.Printf("[FAIL]")
			fmt.Printf(" \"%s\" unit test failed. Got %d bonus, but was expecting %d bonus.", test.Name, bonus, test.ExpectedBonus)
		}

		if !fail {
			green.Printf("[SUCCESS]")
			fmt.Printf(" \"%s\" unit test was successful!\n", test.Name)
			count++
		}
	}
	fmt.Printf("\n\n%s\n\t\t[*] Passed %d/%d tests.\n", stars, count, len(tests))
}

type Test struct {
	Name          string
	Timeline      string
	Components    map[string]*ComponentResult
	ExpectedMatch bool
	ExpectedBonus int
}

func CreateTestTimeline(option int) Test {
	switch option {
	case 0: // Simple linear function. all required components, all exist
		test := Test{
			Name:          "Simple linear timeline",
			Timeline:      "c1 -> c2 -> c3",
			Components:    make(map[string]*ComponentResult),
			ExpectedMatch: true,
		}
		test.Components["c1"] = &ComponentResult{
			Exists:   true,
			Required: true,
			LeftEdge: []Event{ApiEvent{TimeStamp: 1275}, FileEvent{TimeStamp: 2590}, RegistryEvent{TimeStamp: 12842}},
		}
		test.Components["c2"] = &ComponentResult{
			Exists:   true,
			Required: true,
			LeftEdge: []Event{ApiEvent{TimeStamp: 579}, ApiEvent{TimeStamp: 11002}, FileEvent{TimeStamp: 4820}, ApiEvent{TimeStamp: 2200}},
		}
		test.Components["c3"] = &ComponentResult{
			Exists:   true,
			Required: true,
			LeftEdge: []Event{ApiEvent{TimeStamp: 1870}, ApiEvent{TimeStamp: 12800}, ApiEvent{TimeStamp: 4000}},
		}
		return test

	case 1: // Simple timeline with conditional. all required
		test := Test{
			Name:          "Simple conditional timeline",
			Timeline:      "c1 -> c2 or c3 -> c4",
			Components:    make(map[string]*ComponentResult),
			ExpectedMatch: true,
		}

		test.Components["c1"] = &ComponentResult{
			Exists:   true,
			Required: true,
			LeftEdge: []Event{ApiEvent{TimeStamp: 1275}, ApiEvent{TimeStamp: 2590}, ApiEvent{TimeStamp: 12842}},
		}
		test.Components["c2"] = &ComponentResult{ // not a match
			Exists:   true,
			Required: true,
			LeftEdge: []Event{ApiEvent{TimeStamp: 579}, ApiEvent{TimeStamp: 420}},
		}
		test.Components["c3"] = &ComponentResult{
			Exists:   true,
			Required: true,
			LeftEdge: []Event{FileEvent{TimeStamp: 579}, FileEvent{TimeStamp: 11002}, FileEvent{TimeStamp: 4820}, FileEvent{TimeStamp: 2200}},
		}
		test.Components["c4"] = &ComponentResult{
			Exists:   true,
			Required: true,
			LeftEdge: []Event{FileEvent{TimeStamp: 1870}, FileEvent{TimeStamp: 12800}, FileEvent{TimeStamp: 4000}},
		}
		return test

	case 2: // Simple-ish timeline with conditional and parantheses
		test := Test{
			Name:          "Simple conditional timeline with parantheses",
			Timeline:      "c1 -> c2 or (c3 -> c4) -> c5",
			Components:    make(map[string]*ComponentResult),
			ExpectedMatch: true,
		}
		test.Components["c1"] = &ComponentResult{
			Exists:   true,
			Required: true,
			LeftEdge: []Event{FileEvent{TimeStamp: 1275}, FileEvent{TimeStamp: 2590}, FileEvent{TimeStamp: 12842}},
		}
		test.Components["c2"] = &ComponentResult{ // not a match
			Exists:   true,
			Required: true,
			LeftEdge: []Event{RegistryEvent{TimeStamp: 579}, RegistryEvent{TimeStamp: 420}},
		}
		test.Components["c3"] = &ComponentResult{
			Exists:   true,
			Required: true,
			// timestamps that align after c1
			LeftEdge: []Event{FileEvent{TimeStamp: 420}, ApiEvent{TimeStamp: 1892}, RegistryEvent{TimeStamp: 2890}},
		}
		test.Components["c4"] = &ComponentResult{
			Exists:   true,
			Required: true,
			// timestamps that align after c3
			LeftEdge: []Event{RegistryEvent{TimeStamp: 500}, RegistryEvent{TimeStamp: 2000}, RegistryEvent{TimeStamp: 18900}},
		}
		test.Components["c5"] = &ComponentResult{
			Exists:   true,
			Required: true,
			// timestamps that align after c4
			LeftEdge: []Event{FileEvent{TimeStamp: 600}, FileEvent{TimeStamp: 4000}},
		}
		return test
	case 3:
		test := Test{
			Name:          "Timeline with early exit",
			Timeline:      "c1 -> c2 -> c3 -> c4", // exit at c3
			Components:    make(map[string]*ComponentResult),
			ExpectedMatch: false,
		}
		test.Components["c1"] = &ComponentResult{
			Exists:   true,
			Required: true,
			LeftEdge: []Event{FileEvent{TimeStamp: 420}, FileEvent{TimeStamp: 69}, FileEvent{TimeStamp: 5000}},
		}
		test.Components["c2"] = &ComponentResult{
			Exists:   true,
			Required: true,
			LeftEdge: []Event{RegistryEvent{TimeStamp: 5200}, RegistryEvent{TimeStamp: 6800}},
		}
		test.Components["c3"] = &ComponentResult{
			Exists:   true,
			Required: true,
			LeftEdge: []Event{FileEvent{TimeStamp: 420}, FileEvent{TimeStamp: 69}, FileEvent{TimeStamp: 5000}},
		}
		test.Components["c4"] = &ComponentResult{
			Exists:   true,
			Required: true,
			LeftEdge: []Event{ApiEvent{TimeStamp: 500}, ApiEvent{TimeStamp: 7000}},
		}
		return test
	case 4:
		test := Test{
			Name:          "Timeline with early exit in conditional",
			Timeline:      "c1 -> c2 or (c3 -> c4) -> c5 -> c6",
			Components:    make(map[string]*ComponentResult),
			ExpectedMatch: false,
		}

		test.Components["c1"] = &ComponentResult{
			Exists:   true,
			Required: true,
			LeftEdge: []Event{ApiEvent{TimeStamp: 420}, RegistryEvent{TimeStamp: 69}, RegistryEvent{TimeStamp: 5000}},
		}

		test.Components["c2"] = &ComponentResult{ // not a match
			Exists:   false,
			Required: true,
		}

		test.Components["c3"] = &ComponentResult{
			Exists:   true,
			Required: true,
			LeftEdge: []Event{FileEvent{TimeStamp: 5800}},
		}

		test.Components["c4"] = &ComponentResult{ // not a match
			Exists:   true,
			Required: true,
			LeftEdge: []Event{FileEvent{TimeStamp: 2800}, FileEvent{TimeStamp: 499}},
		}

		test.Components["c5"] = &ComponentResult{
			Exists:   true,
			Required: true,
			LeftEdge: []Event{FileEvent{TimeStamp: 7000}, FileEvent{TimeStamp: 8000}},
		}

		test.Components["c6"] = &ComponentResult{
			Exists:   true,
			Required: true,
			LeftEdge: []Event{FileEvent{TimeStamp: 9000}, FileEvent{TimeStamp: 90000}},
		}
		return test
	case 5:
		test := Test{
			Name:          "Timeline with partial bonus",
			Timeline:      "c1 -> c2 -> c3 -> c4 -> c5",
			Components:    make(map[string]*ComponentResult),
			ExpectedMatch: true,
			ExpectedBonus: 20,
		}

		test.Components["c1"] = &ComponentResult{
			Exists:   false,
			Required: false,
			Bonus:    30,
		}
		test.Components["c2"] = &ComponentResult{
			Exists:   true,
			Required: true,
			LeftEdge: []Event{FileEvent{TimeStamp: 200}, FileEvent{TimeStamp: 420}, FileEvent{TimeStamp: 3000}},
		}
		test.Components["c3"] = &ComponentResult{
			Exists:   true,
			Required: false,
			LeftEdge: []Event{RegistryEvent{TimeStamp: 500}, RegistryEvent{TimeStamp: 2000}},
			Bonus:    20,
		}
		test.Components["c4"] = &ComponentResult{
			Exists:   true,
			Required: true,
			LeftEdge: []Event{RegistryEvent{TimeStamp: 69}, RegistryEvent{TimeStamp: 550}, FileEvent{TimeStamp: 3000}},
		}
		test.Components["c5"] = &ComponentResult{
			Exists:   true,
			Required: true,
			LeftEdge: []Event{ApiEvent{TimeStamp: 9000}, ApiEvent{TimeStamp: 13}},
		}
		return test
	case 6:
		test := Test{
			Name:          "Timeline with invalid optional component",
			Timeline:      "c1 -> c2 -> c3 -> c4", // c2 invalid
			Components:    make(map[string]*ComponentResult),
			ExpectedMatch: true,
			ExpectedBonus: 0,
		}
		test.Components["c1"] = &ComponentResult{
			Exists:   true,
			Required: true,
			LeftEdge: []Event{FileEvent{TimeStamp: 1275}, FileEvent{TimeStamp: 2590}, FileEvent{TimeStamp: 12842}},
		}
		test.Components["c2"] = &ComponentResult{
			Exists:   true,
			Required: false,
			LeftEdge: []Event{ApiEvent{TimeStamp: 123}, ApiEvent{TimeStamp: 420}},
			Bonus:    20,
		}
		test.Components["c3"] = &ComponentResult{
			Exists:   true,
			Required: true,
			LeftEdge: []Event{ApiEvent{TimeStamp: 579}, FileEvent{TimeStamp: 11002}, FileEvent{TimeStamp: 4820}, FileEvent{TimeStamp: 2200}},
		}
		test.Components["c4"] = &ComponentResult{
			Exists:   true,
			Required: true,
			LeftEdge: []Event{FileEvent{TimeStamp: 1870}, RegistryEvent{TimeStamp: 12800}, FileEvent{TimeStamp: 4000}},
		}
		return test
	case 7:
		test := Test{
			Name:          "Complex timeline",
			Timeline:      "c0 + c00 + c1 -> c2 or (c3 -> c4) -> c5 or c6 -> c7",
			Components:    make(map[string]*ComponentResult),
			ExpectedMatch: true,
			ExpectedBonus: 20,
		}
		test.Components["c0"] = &ComponentResult{
			Exists:   true,
			Required: false,
			Bonus:    20,
			LeftEdge: []Event{FileEvent{TimeStamp: 1}},
		}
		test.Components["c00"] = &ComponentResult{
			Exists:   false,
			Required: false,
			Bonus:    10,
		}
		test.Components["c1"] = &ComponentResult{
			Exists:   true,
			Required: true,
			LeftEdge: []Event{FileEvent{TimeStamp: 1275}, FileEvent{TimeStamp: 2590}, FileEvent{TimeStamp: 12842}},
		}
		test.Components["c2"] = &ComponentResult{ // not a match
			Exists:   true,
			Required: true,
			LeftEdge: []Event{RegistryEvent{TimeStamp: 579}, RegistryEvent{TimeStamp: 420}},
		}
		test.Components["c3"] = &ComponentResult{
			Exists:   true,
			Required: true,
			LeftEdge: []Event{FileEvent{TimeStamp: 421}, FileEvent{TimeStamp: 1892}, FileEvent{TimeStamp: 2890}},
		}
		test.Components["c4"] = &ComponentResult{
			Exists:   true,
			Required: true,
			LeftEdge: []Event{FileEvent{TimeStamp: 500}, RegistryEvent{TimeStamp: 2000}, ApiEvent{TimeStamp: 18900}},
		}
		test.Components["c5"] = &ComponentResult{
			Exists:   true,
			Required: true,
			LeftEdge: []Event{FileEvent{TimeStamp: 600}, FileEvent{TimeStamp: 4000}},
		}
		test.Components["c6"] = &ComponentResult{
			Exists:   true,
			Required: true,
			LeftEdge: []Event{FileEvent{TimeStamp: 3000}},
		}
		test.Components["c7"] = &ComponentResult{
			Exists:   true,
			Required: false,
			LeftEdge: []Event{FileEvent{TimeStamp: 1000}}, // not a match
			Bonus:    5,
		}
		return test
		//TODO: test case including handle event in linear (timestamp 0)
	}
	return Test{}
}

// Creates all available test cases from CreateTestTimeline. Assumes all of them are in sequential order
func CreateTimelineTests() []Test {
	var tests []Test
	for i := 0; ; i++ {
		test := CreateTestTimeline(i)
		if test.Timeline == "" || test.Name == "" || test.Components == nil || len(test.Components) == 0 {
			break
		}
		tests = append(tests, test)
	}
	return tests
}
