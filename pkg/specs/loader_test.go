package specs

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLoadSpecs(t *testing.T) {
	tests := []struct {
		name         string
		specName     string
		wantSpecPath string
	}{
		{name: "nsa spec", specName: "k8s-nsa-1.0", wantSpecPath: "./k8s-nsa-1.0.yaml"},
		{name: "k8s cis bench", specName: "k8s-cis-1.23", wantSpecPath: "./k8s-cis-1.23.yaml"},
		{name: "k8s pss baseline", specName: "k8s-pss-baseline-0.1", wantSpecPath: "./k8s-pss-baseline-0.1.yaml"},
		{name: "k8s pss restricted", specName: "k8s-pss-restricted-0.1", wantSpecPath: "./k8s-pss-restricted-0.1.yaml"},
		{name: "awscis1.2", specName: "aws-cis-1.2", wantSpecPath: "./aws-cis-1.2.yaml"},
		{name: "awscis1.4", specName: "aws-cis-1.4", wantSpecPath: "./aws-cis-1.4.yaml"},
		{name: "docker cis bench", specName: "docker-cis-1.6.0", wantSpecPath: "./docker-cis-1.6.0.yaml"},
		{name: "awscis1.2 by filepath", specName: "@./aws-cis-1.2.yaml", wantSpecPath: "./aws-cis-1.2.yaml"},
		{name: "bogus spec", specName: "foobarbaz"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantSpecPath != "" {
				wantSpecData, err := os.ReadFile(tt.wantSpecPath)
				assert.NoError(t, err)
				gotSpecData := GetSpec(tt.specName)
				assert.Equal(t, string(wantSpecData), gotSpecData)
			} else {
				assert.Empty(t, GetSpec(tt.specName), tt.name)
			}
		})
	}
}
