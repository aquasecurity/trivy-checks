package metadata

import (
	"strings"

	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

type Metadata map[string]any

func (m Metadata) AVDID() string {
	return m["avd_id"].(string)
}

func (m Metadata) IsDeprecated() bool {
	deprecated, ok := m["deprecated"]
	return ok && deprecated.(bool)
}

func (m Metadata) HasDefaultFramework() bool {
	frameworks, ok := m["frameworks"]
	if !ok {
		return true
	}

	if f, ok := frameworks.(map[string]any); ok {
		if _, exists := f["default"]; exists {
			return true
		}
	}
	return false
}

func (m Metadata) Provider() Provider {
	if p, ok := m["provider"]; ok {
		return Provider(p.(string))
	}

	if input, ok := m["input"]; ok {
		if selector, ok := input.(map[string]any)["selector"]; ok {
			typ := selector.([]any)[0].(map[string]any)["type"].(string)
			if typ != "" {
				return Provider(typ)
			}
		}
	}
	return "generic"
}

func (m Metadata) Service() string {
	if s, ok := m["service"]; ok {
		return s.(string)
	}

	return "general"
}

type Provider string

func (p Provider) DisplayName() string {
	switch p {
	case "aws":
		return strings.ToUpper(string(p))
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
