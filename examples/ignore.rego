package trivy

# disable all built-in checks
ignore := startswith(input.Query, "data.builtin")
