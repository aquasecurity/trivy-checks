# Architecture

This document aims to answer the question *Where is the code that does X?*

## Project Layout

The directory structure is broken down as follows:

- `cmd/` - These CLI tools are primarily used during development for end-to-end testing without needing to pull the library into trivy/tfsec etc.
- `checks` - All of the checks are defined in this directory.
- `commands` - All Node-collector commands are defined in this directory.
- `pkg/spec` - Logic to handle standardized specs such as CIS.
- `pkg/rules` - This package exposes internal rules, and imports them accordingly (see _rules.go_).
- `specs/` - Standaridized compliance specs such as CIS.
- `test` - Integration tests and other high-level tests that require a full build of the project.
- `scripts` - Usefule generation scripts for bundle generation and verification purposes.
