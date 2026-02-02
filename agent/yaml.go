package main

import (
	"fmt"
	"os"
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
		pattern.Components = append(pattern.Components, comp)
	}

	return pattern, nil
}

func parseComponent(node *yaml.Node) (Component, error) {
	// Node is a MappingNode representing one component

	// Peek at type field
	var peek struct {
		Type string `yaml:"type"`
	}
	node.Decode(&peek)

	// Based on type, decode into right struct
	switch peek.Type {
	case "api":
		var comp ApiComponent
		//TODO: check which group, i.e. which conditions can be used
		//TODO: iterate conditions; create function for it
		conditionsNode := findNodeInMapping("conditions", node)
		if conditionsNode != nil {
			if conditionsNode.Kind == yaml.MappingNode {
				fmt.Println("[debug] conditions is a mapping node")
			}
			if conditionsNode.Kind == yaml.SequenceNode {
				fmt.Println("[debug] conditions is a sequence node")
			}
			if conditionsNode.Kind == yaml.ScalarNode {
				fmt.Printf("[debug] conditions is a scalar node (%v)\n", conditionsNode.Value)
			}
			for i := 0; i < len(conditionsNode.Content); i += 2 {
				keyNode := conditionsNode.Content[i]     // name of variable, scalar
				valueNode := conditionsNode.Content[i+1] // value of variable, scalar
				fmt.Printf("[debug] node %d of conditions: %v\n\tnode %d of conditions: %v\n", i, keyNode.Value, i+1, valueNode.Value)
			}
		}

		//parseCondition(conditionNode, comp.GetConditionMask())
		node.Decode(&comp) // Decodes all yaml-tagged fields
		return &comp, nil

	case "file":
		var comp FileComponent
		node.Decode(&comp)
		return &comp, nil
	}
	return nil, nil
}

// Find a node of a specified key name, return that node.
// Made only for MappingNodes. If node was not found, or not MappingNode return is nil
func findNodeInMapping(key string, node *yaml.Node) *yaml.Node {
	if node.Kind != yaml.MappingNode {
		fmt.Println("[debug] Not a mapping node")
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
