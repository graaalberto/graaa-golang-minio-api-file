.PHONY: run build test docker-up docker-down clean swagger lint

run:
	go run cmd/api/main.go

build:
	CGO_ENABLED=0 go build -o bin/govault-api cmd/api/main.go

test:
	go test -v -race -cover ./...

docker-up:
	docker-compose up -d --build

docker-down:
	docker-compose down -v

swagger:
	swag init -g cmd/api/main.go -o docs

lint:
	golangci-lint run ./...

clean:
	rm -rf bin/ tmp/
