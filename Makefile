test:
	go test -v -failfast -tags=test --race ./...

update:
	go get -u all && go mod tidy

.PHONY: test update
