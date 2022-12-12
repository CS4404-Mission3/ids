package main

import (
	"encoding/csv"
	"fmt"
	"io"
	"log"
	"math"
	"math/rand"
	"os"
	"sort"
	"strings"
	"time"
)

var (
	categoryName string
	printBuffer  string
)

// node is a node in the decision tree
type node struct {
	name        string // value name
	description string
	children    map[string]node // attribute value to child node
}

// readDataSet parses a CSV file and returns a slice of maps, where each map is an entry and a list of header attributes
func readDataSet(filename string) ([]map[string]string, []string) {
	var all []map[string]string
	var header []string

	file, err := os.Open(filename)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	reader := csv.NewReader(file)
	for {
		entry, err := reader.Read() // Read in one line
		if err == io.EOF {
			break
		} else if err != nil {
			log.Fatal(err)
		}

		// Extract the header
		if len(header) == 0 {
			header = entry
			categoryName = header[0]
		} else {
			newEntry := make(map[string]string)

			for i, item := range header {
				// This will fail if the subsequent (not header) entries length != len(header)
				newEntry[item] = entry[i]
			}

			all = append(all, newEntry)
		}
	}

	return all, header[1:]
}

// entropy returns the entropy of a given set of entries
func entropy(entries []map[string]string) float64 {
	entryValues := make(map[string]int)

	for _, entry := range entries {
		entryValues[entry[categoryName]] += 1
	}

	final := 0.0
	total := float64(len(entries))

	for _, val := range entryValues {
		percentage := float64(val) / total
		final += -(percentage * math.Log2(percentage))
	}

	return final
}

// gain returns the gain of a given attribute
func gain(entries []map[string]string, attr string) float64 {
	out := entropy(entries)
	values := make(map[string][]map[string]string) // All the possible values of attr

	for _, entry := range entries {
		values[entry[attr]] = append(values[entry[attr]], entry)
	}

	for value := range values {
		entryValue := values[value]
		out -= (float64(len(entryValue)) / float64(len(entries))) * entropy(entryValue) // Adjust entropy gain
	}

	return out
}

// sameCategory returns true if all entries are in the same category
func sameCategory(entries []map[string]string) (bool, string) {
	var lastCategory, currentCategory string

	for _, entry := range entries {
		currentCategory = entry[categoryName]

		if (lastCategory != "") && (currentCategory != lastCategory) {
			return false, ""
		} else {
			lastCategory = currentCategory
		}
	}

	return true, currentCategory
}

// uniqueValuesOf returns an array of unique values of attribute. (Essentially a set)
func uniqueValuesOf(entries []map[string]string, attribute string) []string {
	valueMap := make(map[string]bool) // This is the recommended way to make a set in Go.
	unique := make([]string, 0, len(valueMap))

	for _, entry := range entries {
		valueMap[entry[attribute]] = true
	}

	for key := range valueMap {
		unique = append(unique, key)
	}

	return unique
}

// attribWithLargestGain returns the attribute with the largest effective gain
func attribWithLargestGain(entries []map[string]string, attributes []string) string {
	var attribLargestGainSoFar string
	var largestGain = 0.0

	for _, attribute := range attributes {
		currentAttrGain := gain(entries, attribute)
		if currentAttrGain >= largestGain {
			attribLargestGainSoFar = attribute
			largestGain = currentAttrGain
		}
	}

	return attribLargestGainSoFar
}

// mostCommon returns the attribute value that occurs most often in the given entries
func mostCommon(entries []map[string]string, attribute string) string {
	valueMap := make(map[string]int) // map[attribute value]number of times

	for _, entry := range entries {
		valueMap[entry[attribute]]++
	}

	var out string
	valueMostCommon := 0

	for value := range valueMap {
		if valueMap[value] > valueMostCommon {
			out = value
			valueMostCommon = valueMap[value]
		}
	}

	return out
}

// indexOf returns the index of the given item in the given slice, or -1
func indexOf(element string, slice []string) int {
	for index, item := range slice {
		if item == element {
			return index
		}
	}

	return -1
}

// deleteFrom returns a new slice with the given value deleted from it
func deleteFrom(slice []string, item string) []string {
	indexOfItem := indexOf(item, slice)
	if indexOfItem != -1 { // If item is in slice
		sliceCopy := make([]string, len(slice))
		copy(sliceCopy, slice)

		return append(sliceCopy[:indexOfItem], sliceCopy[indexOfItem+1:]...)
	}

	return slice
}

// id3 is the main recursive function that builds the decision tree. It takes an array of entries and attributes and returns a node
func id3(entries []map[string]string, attributes []string) node {
	if ok, group := sameCategory(entries); ok {
		return node{
			name:        group,
			description: group, // categoryName + "=" + group,
			children:    nil,   // leaf
		}
	}

	if len(attributes) == 0 {
		mc := mostCommon(entries, categoryName)
		return node{
			name:     mc,
			children: nil, // leaf
		}
	}

	largestGain := attribWithLargestGain(entries, attributes)
	n := node{
		name:     largestGain,
		children: make(map[string]node),
	}

	for _, v := range uniqueValuesOf(entries, largestGain) {
		var subset []map[string]string
		for _, e := range entries {
			if e[largestGain] == v {
				subset = append(subset, e)
			}
		}

		if len(subset) == 0 { // No examples with the value v
			mc := mostCommon(entries, categoryName)
			n.children[v] = node{
				name:        mc,
				description: "Guessing: " + mc,
				children:    nil,
			}

		} else {
			newAttributes := deleteFrom(attributes, largestGain)
			n.children[v] = id3(subset, newAttributes)
		}
	}

	return n
}

// indent returns n number of indentation sequences
func indent(n int) string {
	out := ""
	for i := 0; i < n; i++ {
		out += "  "
	}
	return out
}

// String returns a string representation of the decision tree
func (n *node) String() string {
	printBuffer = ""
	printTreeText(*n, 0)
	return printBuffer
}

// GraphViz returns a string representation of the decision tree
func (n *node) GraphViz(filter string, minBranchLen int) string {
	printBuffer = "digraph {\n"
	printTreeGraphViz(*n, "", filter, minBranchLen)
	return printBuffer + "}\n"
}

func sanitize(s string) string {
	for _, replacement := range []string{".", "(", ")", "-", "_"} {
		s = strings.ReplaceAll(s, replacement, "_")
	}
	return s
}

// printTreeGraphViz prints the tree in GraphViz DOT format with
func printTreeGraphViz(root node, parent, filter string, minBranchLength int) {
	if root.children == nil { // leaf
		l := fmt.Sprintf("  %s -> %s", parent, sanitize(root.description))
		branchLen := strings.Count(l, "->")
		if root.description != "" && (strings.Contains(parent, filter) || filter == "") && (branchLen >= minBranchLength) {
			printBuffer += fmt.Sprintf("%s // Branch length %d\n", l, branchLen)
		}
	}

	for childValue, child := range root.children {
		if childValue != "" {
			ns := fmt.Sprintf("%s -> \"%s\"", sanitize(root.name), sanitize(childValue))
			if parent != "" {
				ns = parent + " -> " + ns
			}
			printTreeGraphViz(child, ns, filter, minBranchLength)
		}
	}
}

// printTreeText prints the tree as a text tree
func printTreeText(root node, indentation int) {
	if root.children == nil { // leaf
		printBuffer += fmt.Sprintf("%s%s\n", indent(indentation), root.description)
	} else {
		printBuffer += fmt.Sprintf("%sswitch %s:\n", indent(indentation), root.name)
	}

	for index, child := range root.children {
		printBuffer += fmt.Sprintf("%scase %s:\n", indent(indentation+1), index)
		printTreeText(child, indentation+2)
	}
}

// follow returns the leaf node that the given entry would end up at
func follow(entry map[string]string, root node) string {
	if root.children != nil { // If not leaf
		return follow(entry, root.children[entry[root.name]])
	} else { // If the base case is reached	return ""
		return root.name
	}
}

// accuracy returns the accuracy of the tree given a training set
func accuracy(tree node, testing []map[string]string) float64 {
	correct := 0.0
	for _, entry := range testing {
		prediction := follow(entry, tree)
		actual := entry[categoryName]
		if prediction == actual {
			correct++
		}
	}

	return correct / float64(len(testing)) * 100
}

func bench(filename string) {
	// Parse data
	all, header := readDataSet(filename)

	// Scramble the set
	rand.Seed(time.Now().UnixNano())
	rand.Shuffle(len(all), func(i, j int) { all[i], all[j] = all[j], all[i] })
	splitPoint := int(float64(len(all)) * 0.5)
	training, testing := all[:splitPoint], all[splitPoint:]

	fmt.Printf("Training on %d/%d packets\n", len(training), len(all))
	tree := id3(training, header)
	acc := accuracy(tree, testing)
	fmt.Printf("%.2f%% model accuracy\n", acc)

	gains := map[string]float64{}
	for _, field := range header {
		gains[field] = gain(training, field)
	}

	// Sort gains map by value
	var keys []string
	for k := range gains {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		return gains[keys[i]] > gains[keys[j]]
	})
	fmt.Println("Entropy Gains:")
	// Print entropy gain with left aligned equal whitespace between each field
	for _, k := range keys {
		fmt.Printf("%.4f: %s\n", gains[k], k)
	}

	//log.Println(tree.String())
}
