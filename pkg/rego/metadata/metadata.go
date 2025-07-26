package metadata

import (
	"strings"

	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

const (
	DefaultProvider = "generic"
	DefaultService  = "general"
)

type Metadata struct {
	Title       string
	Description string
	Links       []string
	Custom      map[string]any
}

func (m Metadata) ID() string {
	if v, ok := m.Custom["id"].(string); ok {
		return v
	}
	return ""
}

func (m Metadata) AVDID() string {
	aliases := m.Aliases()
	if len(aliases) > 0 {
		return aliases[0]
	}
	return ""
}

func (m Metadata) Severity() string {
	if v, ok := m.Custom["severity"].(string); ok {
		return v
	}
	return ""
}

func (m Metadata) Deprecated() bool {
	if v, ok := m.Custom["deprecated"].(bool); ok {
		return v
	}
	return false
}

func (m Metadata) Frameworks() map[string][]string {
	result := make(map[string][]string)

	raw, ok := m.Custom["frameworks"]
	if !ok {
		return result
	}

	rawMap, ok := raw.(map[string]any)
	if !ok {
		return result
	}

	for k, v := range rawMap {
		if arr, ok := v.([]any); ok {
			var strArr []string
			for _, item := range arr {
				if s, ok := item.(string); ok {
					strArr = append(strArr, s)
				}
			}
			result[k] = strArr
		}
	}
	return result
}

func (m Metadata) HasDefaultFramework() bool {
	frameworks := m.Frameworks()
	if len(frameworks) == 0 {
		return true
	}
	_, exists := frameworks["default"]
	return exists
}

func (m Metadata) Provider() Provider {
	if p, ok := m.Custom["provider"].(string); ok {
		return Provider(p)
	}

	input, ok := m.Custom["input"].(map[string]any)
	if !ok {
		return DefaultProvider
	}

	selector, ok := input["selector"].([]any)
	if !ok || len(selector) == 0 {
		return DefaultProvider
	}

	first, ok := selector[0].(map[string]any)
	if !ok {
		return DefaultProvider
	}

	if typ, ok := first["type"].(string); ok && typ != "" {
		return Provider(typ)
	}

	return DefaultProvider
}

func (m Metadata) Service() string {
	if s, ok := m.Custom["service"].(string); ok {
		return s
	}
	return DefaultService
}

func (m Metadata) Aliases() []string {
	raw, ok := m.Custom["aliases"]
	if !ok {
		return nil
	}

	s, ok := raw.([]any)
	if !ok {
		return nil
	}
	aliases := make([]string, 0, len(s))
	for _, ss := range s {
		if str, ok := ss.(string); ok {
			aliases = append(aliases, str)
		}
	}
	return aliases
}

func (m Metadata) MinimumTrivyVersion() string {
	if v, ok := m.Custom["minimum_trivy_version"].(string); ok {
		return v
	}
	return ""
}

type Provider string

func (p Provider) DisplayName() string {
	switch p {
	case "aws":
		return "AWS"
	case "digitalocean":
		return "Digital Ocean"
	case "github":
		return "GitHub"
	case "openstack":
		return "OpenStack"
	case "cloudstack":
		return "Cloudstack"
	default:
		return cases.Title(language.English).String(strings.ToLower(string(p)))
	}
}

func (p Provider) ConstName() string {
	return strings.ReplaceAll(p.DisplayName(), " ", "")
}
