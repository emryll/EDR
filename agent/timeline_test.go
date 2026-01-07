package main

import (
	"testing"
)

func TestTimelineEvaluation(t *testing.T) {
	var (
		count int
		stars = "************************************************************************************"
	)
	tests := CreateTimelineTests()
	for i, test := range tests {
		t.Logf("\n%s\n\tTest case %d: %s\n%s\n\n", stars, i, test.Name, stars)
		match, bonus := EvaluateTimeline(test.Timeline, test.Components)
		var fail bool
		if match != test.ExpectedMatch {
			fail = true
			t.Logf("\n[FAIL] \"%s\" unit test failed. Got ", test.Name)
			if match {
				t.Logf("match, but was expecting no match.\n")
			} else {
				t.Logf("no match, but was expecting match.\n")
			}
		}
		if bonus != test.ExpectedBonus {
			fail = true
			t.Logf("\n[FAIL] \"%s\" unit test failed. Got %d bonus, but was expecting %d bonus.", test.Name, bonus, test.ExpectedBonus)
		}

		if !fail {
			t.Logf("[SUCCESS] \"%s\" unit test was successful!\n", test.Name)
			count++
		}
	}
	t.Logf("[i] Passed %d/%d tests.\n", count, len(tests))
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
			Exists:          true,
			Required:        true,
			FirstTimestamps: []int64{1275, 2590, 12842},
		}
		test.Components["c2"] = &ComponentResult{
			Exists:          true,
			Required:        true,
			FirstTimestamps: []int64{579, 11002, 4820, 2200},
		}
		test.Components["c3"] = &ComponentResult{
			Exists:          true,
			Required:        true,
			FirstTimestamps: []int64{1870, 12800, 4000},
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
			Exists:          true,
			Required:        true,
			FirstTimestamps: []int64{1275, 2590, 12842},
		}
		test.Components["c2"] = &ComponentResult{ // not a match
			Exists:          true,
			Required:        true,
			FirstTimestamps: []int64{579, 420},
		}
		test.Components["c3"] = &ComponentResult{
			Exists:          true,
			Required:        true,
			FirstTimestamps: []int64{579, 11002, 4820, 2200},
		}
		test.Components["c4"] = &ComponentResult{
			Exists:          true,
			Required:        true,
			FirstTimestamps: []int64{1870, 12800, 4000},
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
			Exists:          true,
			Required:        true,
			FirstTimestamps: []int64{1275, 2590, 12842},
		}
		test.Components["c2"] = &ComponentResult{ // not a match
			Exists:          true,
			Required:        true,
			FirstTimestamps: []int64{579, 420},
		}
		test.Components["c3"] = &ComponentResult{
			Exists:   true,
			Required: true,
			// timestamps that align after c1
			FirstTimestamps: []int64{420, 1892, 2890},
		}
		test.Components["c4"] = &ComponentResult{
			Exists:   true,
			Required: true,
			// timestamps that align after c3
			FirstTimestamps: []int64{500, 2000, 18900},
		}
		test.Components["c5"] = &ComponentResult{
			Exists:   true,
			Required: true,
			// timestamps that align after c4
			FirstTimestamps: []int64{600, 4000},
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
			Exists:          true,
			Required:        true,
			FirstTimestamps: []int64{420, 69, 5000},
		}
		test.Components["c2"] = &ComponentResult{
			Exists:          true,
			Required:        true,
			FirstTimestamps: []int64{5200, 6800},
		}
		test.Components["c3"] = &ComponentResult{
			Exists:          true,
			Required:        true,
			FirstTimestamps: []int64{420, 69, 5000},
		}
		test.Components["c4"] = &ComponentResult{
			Exists:          true,
			Required:        true,
			FirstTimestamps: []int64{500, 7000},
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
			Exists:          true,
			Required:        true,
			FirstTimestamps: []int64{420, 69, 5000},
		}

		test.Components["c2"] = &ComponentResult{ // not a match
			Exists:   false,
			Required: true,
		}

		test.Components["c3"] = &ComponentResult{
			Exists:          true,
			Required:        true,
			FirstTimestamps: []int64{5800},
		}

		test.Components["c4"] = &ComponentResult{ // not a match
			Exists:          true,
			Required:        true,
			FirstTimestamps: []int64{2800, 499},
		}

		test.Components["c5"] = &ComponentResult{
			Exists:          true,
			Required:        true,
			FirstTimestamps: []int64{7000, 8000},
		}

		test.Components["c6"] = &ComponentResult{
			Exists:          true,
			Required:        true,
			FirstTimestamps: []int64{9000, 90000},
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
			Exists:          true,
			Required:        true,
			FirstTimestamps: []int64{200, 420, 3000},
		}
		test.Components["c3"] = &ComponentResult{
			Exists:          true,
			Required:        false,
			FirstTimestamps: []int64{500, 2000},
			Bonus:           20,
		}
		test.Components["c4"] = &ComponentResult{
			Exists:          true,
			Required:        true,
			FirstTimestamps: []int64{69, 550, 3000},
		}
		test.Components["c5"] = &ComponentResult{
			Exists:          true,
			Required:        true,
			FirstTimestamps: []int64{9000, 13},
		}
		return test
	case 6:
		test := Test{ //TODO
			Name:          "Timeline with invalid optional component",
			Timeline:      "",
			Components:    make(map[string]*ComponentResult),
			ExpectedMatch: true,
			ExpectedBonus: 0,
		}
		return test
	case 7:
		test := Test{ //TODO
			Name:          "Complex timeline",
			Timeline:      "c1 -> c2 or (c3 -> c4) -> c5 or c6 -> c7",
			Components:    make(map[string]*ComponentResult),
			ExpectedMatch: true,
		}
		return test
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
