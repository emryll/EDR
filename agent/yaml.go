package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	yaml "gopkg.in/yaml.v3"
)

// Custom boolean type for yaml.
// Makes it so that default value is "not set" instead of false
type Bool struct {
	Value string `yaml:",inline"`
}

func (b Bool) IsSet() bool {
	return b.Value != ""
}

func (b Bool) True() bool {
	return strings.ToLower(b.Value) == "true"
}

// this tells yaml package how to parse Bool values
func (b *Bool) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind != yaml.ScalarNode {
		return fmt.Errorf("expected scalar, but node is %s", GetKind(node.Kind))
	}
	b.Value = node.Value
	return nil
}

type Bitmask uint32 // custom type allowing for string enums in yaml

// This is the outer function, which should be used to load behavior patterns.
// It will first make sure each file follows valid syntax and doesn't break any rules.
// After that it will go on to parse each pattern and add them to the global BehaviorPatterns
func CompileBehaviorPatterns() error {

}

//func CheckFileSyntax()

func loadBehaviorPatterns() {
	//TODO: find all pattern files
	//TODO: for each, read them, then call
}

func parsePatternFile(path string) ([]BehaviorPattern, error) {
	yamlBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var (
		root     yaml.Node
		patterns []BehaviorPattern
	)
	// Get root node because it needs to be parsed differently if its a list vs single pattern
	if err := yaml.Unmarshal(yamlBytes, &root); err != nil {
		return nil, fmt.Errorf("failed to parse yaml: %v", err)
	}
	// Root is DocumentNode, content[0] is the actual data
	if root.Kind != yaml.DocumentNode || len(root.Content) == 0 {
		return nil, fmt.Errorf("invalid YAML structure (root)")
	}

	doc := root.Content[0]
	// Check if it's a sequence (array) or single mapping
	if doc.Kind == yaml.SequenceNode {
		// Array of patterns
		fmt.Printf("Parsing %d patterns...\n", len(doc.Content))
		for i, patternNode := range doc.Content {
			pattern, err := parsePattern(patternNode)
			if err != nil {
				fmt.Printf("Failed to parse pattern %d: %v\n", i, err)
				continue
			}
			fmt.Printf("Successfully parsed pattern: %s\n", pattern.Name)
			patterns = append(patterns, *pattern)
		}
	} else if doc.Kind == yaml.MappingNode {
		// Single pattern
		pattern, err := parsePattern(doc)
		if err != nil {
			return nil, fmt.Errorf("Failed to parse pattern: %v\n", err)
		}
		fmt.Printf("Successfully parsed pattern: %s\n", pattern.Name)
		patterns = append(patterns, *pattern)
	} else {
		return nil, fmt.Errorf("Expected sequence or mapping node")
	}
	return patterns, nil
}

// This function will parse a single pattern.
func parsePattern(node *yaml.Node) (*BehaviorPattern, error) {
	// Create the pattern struct
	pattern := &BehaviorPattern{}

	// Decode the header fields directly into the struct. This will
	// ignore the polymorphic components field since it will be handled manually
	if err := node.Decode(pattern); err != nil {
		return nil, fmt.Errorf("failed to decode header: %w", err)
	}

	//TODO: parse bonus_attributes (mappingnode)
	//TODO: implement tracking of captures

	// Key-value pairs or collections of them (maps) are mapping nodes.
	if node.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("expected mapping node")
	}

	componentsNode := findNodeInMapping("components", node)
	if componentsNode == nil {
		// No components field, that's ok
		return pattern, nil
	}
	if componentsNode.Kind != yaml.SequenceNode {
		return nil, fmt.Errorf("components must be a sequence")
	}

	// Parse each component
	pattern.Components = make([]Component, 0, len(componentsNode.Content))
	for i, compNode := range componentsNode.Content {
		comp, err := parseComponent(compNode)
		if err != nil {
			return nil, fmt.Errorf("component %d: %w", i, err)
		}
		if len(componentsNode.Content) > 1 && comp.GetName() == "" {
			return nil, fmt.Errorf("\"%s\": components must be named (line %d)", pattern.Name, compNode.Line)
		}
		pattern.Components = append(pattern.Components, comp)
	}

	if len(pattern.Components) > 1 {
		if pattern.Timeline == "" {
			return nil, fmt.Errorf("must define a timeline")
		}
		if err := pattern.ValidateTimeline(); err != nil {
			return nil, fmt.Errorf("invalid timeline: %v", err)
		}
	}
	return pattern, nil
}

func parseComponent(node *yaml.Node) (Component, error) {
	// Node is a MappingNode representing one component
	var (
		group int
		comp  Component
		// Peek at type field
		peek struct {
			Type string `yaml:"type"`
		}
	)
	node.Decode(&peek)

	// Based on type, decode into right struct
	switch strings.ToLower(peek.Type) {
	case "api":
		var apiComp ApiComponent
		node.Decode(&apiComp) // Decodes all yaml-tagged fields
		group = apiComp.GetGroup()
		comp = &apiComp
		if len(apiComp.Options) == 0 {
			return nil, fmt.Errorf("must declare API options in API component")
		}
	case "file":
		var fileComp FileComponent
		node.Decode(&fileComp)
		group = fileComp.GetGroup()
		comp = &fileComp
		if fileComp.Action == "" {
			return nil, fmt.Errorf("must declare action in file component")
		}
		validOptions := map[string]bool{"write": true, "read": true, "create": true, "delete": true, "rename": true}
		if !validOptions[fileComp.Action] {
			return nil, fmt.Errorf("unknown file action: \"%s\"", fileComp.Action)
		}
	case "registry":
		var regComp RegComponent
		node.Decode(&regComp)
		group = regComp.GetGroup()
		comp = &regComp
		if regComp.Action == "" {
			return nil, fmt.Errorf("must declare action in registry component")
		}
		validOptions := map[string]bool{"create_key": true, "delete_key": true, "set_value": true, "delete_value": true, "set_info": true, "set_security": true}
		if !validOptions[regComp.Action] {
			return nil, fmt.Errorf("unknown registry action: \"%s\"", regComp.Action)
		}
	case "handle":
		var handleComp HandleEntry
		node.Decode(&handleComp)
		group = handleComp.GetGroup()
		comp = &handleComp
		if handleComp.Type == "" {
			return nil, fmt.Errorf("must declare object type in handle component")
		}
	case "etw-ti", "ti":
		var etwComp EtwComponent
		node.Decode(&etwComp)
		etwComp.Provider = "Microsoft-Windows-Threat-Intelligence"
		group = etwComp.GetGroup()
		comp = &etwComp
	case "etw":
		var etwComp EtwComponent
		node.Decode(&etwComp)
		if etwComp.Provider == "" {
			return nil, fmt.Errorf("must declare provider in generic ETW component")
		}
	default:
		return nil, fmt.Errorf("invalid component type: \"%s\"", peek.Type)
	}

	conditionsNode := findNodeInMapping("conditions", node)
	conditions, err := parseConditions(conditionsNode, group)
	if err != nil {
		return nil, fmt.Errorf("failed to parse conditions: %v\n", err)
	}
	comp.SetConditions(conditions)
	return comp, nil
}

// conditionMask is a bitmask telling which sets of conditions can be used.
func parseConditions(node *yaml.Node, group int) ([]Condition, error) {
	//? Conditions are mapping nodes containing mapping nodes and sequence nodes
	if node == nil {
		return nil, nil
	}
	var conditions []Condition
	sets := GetConditionSets(group)
	for _, set := range sets {
		if err := node.Decode(set); err != nil {
			return nil, err
		}
		conditions = append(conditions, set)
	}
	return conditions, nil
}

// Find a node of a specified key name, return that node.
// Made only for MappingNodes. If node was not found, or not MappingNode return is nil
func findNodeInMapping(key string, node *yaml.Node) *yaml.Node {
	if node.Kind != yaml.MappingNode {
		return nil
	}
	var newNode *yaml.Node
	for i := 0; i < len(node.Content); i += 2 {
		keyNode := node.Content[i]     // name of variable, scalar
		valueNode := node.Content[i+1] // value of variable, scalar

		if keyNode.Value == key {
			newNode = valueNode
			break
		}
	}
	return newNode
}

func (b *Bitmask) UnmarshalYAML(node *yaml.Node) error {
	var result Bitmask
	switch node.Kind {
	// a single string, for example "PROCESS_VM_WRITE | PROCESS_CREATE_THREAD", or raw value
	case yaml.ScalarNode:
		mask, err := ReadBitmask(node)
		if err != nil {
			return err
		}
		result |= mask

	// list of bitmask flags
	case yaml.SequenceNode:
		for _, elem := range node.Content {
			if elem.Kind != yaml.ScalarNode {
				return fmt.Errorf("invalid YAML node for bitmask value: %s (%v)", GetKind(elem.Kind), elem.Value)
			}
			mask, err := ReadBitmask(elem)
			if err != nil {
				return err
			}
			result |= mask
		}

	default:
		return fmt.Errorf("invalid YAML node for bitmask value: %s (%v)", GetKind(node.Kind), node.Value)
	}
	*b = result
	return nil
}

// Interpret a string as a Bitmask. Takes into account enums, raw values and "a | b"
func ReadBitmask(node *yaml.Node) (Bitmask, error) {
	var result Bitmask
	parts := strings.Split(node.Value, "|")
	for _, part := range parts {
		key := strings.TrimSpace(strings.ToUpper(part))
		numerical := BitmaskAsNumber(part)
		if numerical > 0 {
			result |= numerical
		} else {
			val, ok := enums[key]
			if !ok {
				return 0, fmt.Errorf("unknown bitmask value: %q", node.Value)
			}
			result |= val
		}
	}
	return result, nil
}

// Check if bitmask is an enum or raw value. enum returns 0
func BitmaskAsNumber(value string) Bitmask {
	str := strings.TrimSpace(value)
	if str == "" {
		return 0
	}

	val, err := strconv.ParseUint(str, 0, 64)
	if err != nil {
		return 0
	}
	return (Bitmask)(val)
}

func GetKind(kind yaml.Kind) string {
	switch kind {
	case yaml.DocumentNode:
		return "DocumentNode"
	case yaml.MappingNode:
		return "MappingNode"
	case yaml.ScalarNode:
		return "ScalarNode"
	case yaml.SequenceNode:
		return "SequenceNode"
	case yaml.AliasNode:
		return "AliasNode"
	}
	return ""
}

func (p *BehaviorPattern) ValidateTimeline() error {
	// convert components to map for quicker lookup
	components := make(map[string]Component)
	for _, comp := range p.Components {
		components[comp.GetName()] = comp
	}

	// it has already been checked that all components are named
	var insideParentheses bool
	var insideConditional bool
	tokens := strings.Fields(p.Timeline)
	for i := 0; i < len(tokens); i += 2 {
		//* check for illegal symbol usage
		if tokens[i] == "->" || strings.EqualFold(tokens[i], "or") {
			return fmt.Errorf("illegal usage of symbol \"%s\", expected component", tokens[i])
		}
		if tokens[i] == "(" || tokens[i] == ")" {
			return fmt.Errorf("invalid usage of parentheses; they must not be space-separated")
		}
		//* make sure all used components are defined
		if components[tokens[i]] == nil {
			return fmt.Errorf("unknown component in timeline: \"%s\"", tokens[i])
		}
		//* make sure all parentheses are valid
		if tokens[i][0] == '(' {
			if insideParentheses {
				return fmt.Errorf("nested parentheses are not allowed in timeline")
			}
			insideParentheses = true
		}
		if tokens[i][len(tokens[i])-1] == ')' {
			if !insideParentheses {
				return fmt.Errorf("unmatched closing parentheses without opening")
			}
			insideParentheses = false
		}
		//* make sure no conditionals inside parentheses
		if insideParentheses {
			if strings.EqualFold(tokens[i+1], "or") {
				return fmt.Errorf("conditionals are not allowed inside parentheses")
			}
		}
		//* make sure there are no optional components in conditionals
		if strings.EqualFold(tokens[i+1], "or") {
			insideConditional = true
			if components[tokens[i]].GetBonus() != 0 {
				return fmt.Errorf("bonus not allowed inside conditional")
			}
		} else if !insideParentheses && insideConditional {
			insideConditional = false
		}
	}
	return nil
}
