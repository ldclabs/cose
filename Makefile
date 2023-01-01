test:
	go test -v -failfast -tags=test --race ./...

.PHONY: test
