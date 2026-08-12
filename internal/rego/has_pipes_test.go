package rego

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHasPipes(t *testing.T) {
	tests := []struct {
		cmdsSeq  string
		expected bool
	}{
		{
			cmdsSeq:  "wget -O - https://some.site | wc -l",
			expected: true,
		},
		{
			cmdsSeq:  "set -o pipefail && wget -O - https://some.site | wc -l",
			expected: true,
		},
		{
			cmdsSeq:  "apt update && apt install -y nginx",
			expected: false,
		},
		{
			cmdsSeq:  "apt update; apt install -y nginx",
			expected: false,
		},
		{
			cmdsSeq:  `echo "foo|bar"`,
			expected: false,
		},
		{
			cmdsSeq:  "apt update || apt install -y nginx",
			expected: false,
		},
	}

	for _, test := range tests {
		t.Run(test.cmdsSeq, func(t *testing.T) {
			got, err := hasPipes(test.cmdsSeq)
			require.NoError(t, err)
			assert.Equal(t, test.expected, got)
		})
	}
}
