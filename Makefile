DYNAMIC_REGO_FOLDER=./rules/kubernetes/policies/dynamic

.PHONY: test
test:
	go test -v ./...

.PHONY: rego
rego: fmt-rego test-rego

.PHONY: fmt-rego
fmt-rego:
	opa fmt -w rules/

.PHONY: test-rego
test-rego:
	go test --run Test_AllRegoRules ./test

.PHONY: bundle
bundle:
	./scripts/bundle.sh
	cp bundle.tar.gz scripts/bundle.tar.gz
	go run ./scripts/verify-bundle.go
	rm scripts/bundle.tar.gz

.PHONY: id
id:
	@go run ./cmd/id

.PHONY: outdated-api-updated
outdated-api-updated:
	sed -i.bak "s|recommendedVersions :=.*|recommendedVersions := $(OUTDATE_API_DATA)|" $(DYNAMIC_REGO_FOLDER)/outdated_api.rego && rm $(DYNAMIC_REGO_FOLDER)/outdated_api.rego.bak

