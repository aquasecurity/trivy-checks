package trivy

import rego.v1

# disable all built-in checks
ignore if not startswith(input.ID, "USR-")
