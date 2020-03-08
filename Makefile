otp:
	go build -o bin/otp ./cmd/otp

test:
	go test ./...

benchmark:
	go test ./... -bench=.

lint:
	golangci-lint run
