package main

import (
	"fmt"
	"log"
	"sort"
	"strconv"
	"strings"

	"github.com/aquasecurity/trivy-checks/pkg/rego/metadata"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err.Error())
	}
}

func run() error {
	checksMetadata, err := metadata.LoadDefaultChecksMetadata()
	if err != nil {
		return fmt.Errorf("load checks metadata: %w", err)
	}

	keyMap := make(map[string][]string)

	for _, meta := range checksMetadata {
		avdid := meta.ID()
		parts := strings.Split(avdid, "-")
		keyMap[parts[0]] = append(keyMap[parts[0]], parts[1])
	}

	var freeIDs []string
	for key := range keyMap {
		sort.Strings(keyMap[key])
		all := keyMap[key]
		max := all[len(all)-1]
		i, _ := strconv.Atoi(max)
		free := fmt.Sprintf("%s-%04d", key, i+1)
		freeIDs = append(freeIDs, fmt.Sprintf("%16s: %s", key, free))
	}

	sort.Slice(freeIDs, func(i, j int) bool {
		return strings.TrimSpace(freeIDs[i]) < strings.TrimSpace(freeIDs[j])
	})

	println("The following IDs are free - choose the one for the service you are targeting.")
	println(strings.Join(freeIDs, "\n"))
	return nil
}
