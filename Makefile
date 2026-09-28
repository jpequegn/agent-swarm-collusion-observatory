PYTHON ?= python3

.PHONY: check fmt-check vet test python-test

check: fmt-check vet test python-test

fmt-check:
	@unformatted="$$(gofmt -l $$(find . -type f -name '*.go' -not -path './.git/*'))"; \
	  test -z "$$unformatted" || (printf '%s\n' "$$unformatted"; exit 1)

vet:
	go vet ./...

test:
	go test ./...

python-test:
	PYTHONPATH=python $(PYTHON) -m unittest discover -s python/tests -v
