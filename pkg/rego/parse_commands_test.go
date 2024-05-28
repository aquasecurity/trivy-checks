package rego

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseCommands(t *testing.T) {
	tests := []struct {
		cmdsSeq  string
		expected [][]string
	}{
		{
			cmdsSeq:  "apt update; apt install -y nginx",
			expected: [][]string{{"apt", "update"}, {"apt", "install", "-y", "nginx"}},
		},
		{
			cmdsSeq:  "apt update && apt install -y nginx",
			expected: [][]string{{"apt", "update"}, {"apt", "install", "-y", "nginx"}},
		},
		{
			cmdsSeq:  "apt update || apt install -y nginx",
			expected: [][]string{{"apt", "update"}, {"apt", "install", "-y", "nginx"}},
		},
		{
			cmdsSeq:  `echo "test;test" ;apt update && apt install -y nginx`,
			expected: [][]string{{"echo", "\"test;test\""}, {"apt", "update"}, {"apt", "install", "-y", "nginx"}},
		},
	}

	for _, test := range tests {
		t.Run(test.cmdsSeq, func(t *testing.T) {
			got, err := parseCommands(test.cmdsSeq)
			require.NoError(t, err)
			assert.Equal(t, test.expected, got)
		})
	}
}
