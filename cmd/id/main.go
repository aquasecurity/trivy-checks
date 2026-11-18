// Command id prints the next ID for every check prefix and for Kubernetes commands.
package main

import (
	"fmt"
	"maps"
	"slices"
)

// lastIDs holds the last ID taken for every prefix. Raise the number when you
// take a new ID and never lower it, so IDs of removed checks and commands are
// not given out again.
var lastIDs = map[string]int{
	"AWS":    346,
	"AZU":    76,
	"CLDSTK": 1,
	"CMD":    50,
	"DIG":    9,
	"DS":     31,
	"GCP":    79,
	"GIT":    4,
	"KCV":    93,
	"KSV":    127,
	"KUBE":   2,
	"NIF":    21,
	"OCI":    1,
	"OPNSTK": 5,
}

func main() {
	fmt.Println("Take the ID for the target you are writing for and raise its number in cmd/id/main.go.")
	for _, prefix := range slices.Sorted(maps.Keys(lastIDs)) {
		fmt.Printf("%16s: %s-%04d\n", prefix, prefix, lastIDs[prefix]+1)
	}
}
