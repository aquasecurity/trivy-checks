package compliance

import (
	"embed"
	"fmt"
	"io"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// Loader access compliance specs
type Loader interface {
	GetSpecByName(name string) string
}

type specLoader struct {
}

// NewSpecLoader instansiate spec loader
func NewSpecLoader() Loader {
	return &specLoader{}
}

// GetSpecByName get spec name and return spec data
func (sl specLoader) GetSpecByName(name string) string {
	return GetSpec(name)
}

var (
	//go:embed *.yaml
	complianceFS embed.FS
)

var complianceSpecMap map[string]string

// Load compliance specs
func init() {
	dir, _ := complianceFS.ReadDir(".")
	complianceSpecMap = make(map[string]string)
	for _, r := range dir {
		if !strings.Contains(r.Name(), ".yaml") {
			continue
		}
		file, err := complianceFS.Open(fmt.Sprintf("%s", r.Name()))
		if err != nil {
			panic(err)
		}
		specContent, err := io.ReadAll(file)
		if err != nil {
			panic(err)
		}
		var fileSpec map[string]interface{}
		err = yaml.Unmarshal(specContent, &fileSpec)
		if err != nil {
			panic(err)
		}
		if specVal, ok := fileSpec["spec"].(map[string]interface{}); ok {
			if idVal, ok := specVal["id"].(string); ok {
				complianceSpecMap[idVal] = string(specContent)
			}
		}
	}
}

// GetSpec returns the spec content
func GetSpec(name string) string {
	if spec, ok := complianceSpecMap[name]; ok { // use embedded spec
		return spec
	}
	spec, err := os.ReadFile(strings.TrimPrefix(name, "@")) // use custom spec by filepath
	if err != nil {
		return ""
	}
	return string(spec)
}
