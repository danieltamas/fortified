# No Go toolchain is installed on the operator's host (arm64 Mac, only
# Intel Homebrew available) — every recipe below runs inside the
# fortified-dev image instead. Rebuild the image after editing
# docker/Dockerfile.dev.

image := "fortified-dev"

_run *ARGS:
    docker run --rm \
        -v "{{justfile_directory()}}":/src -w /src \
        -v /var/run/docker.sock:/var/run/docker.sock \
        {{image}} bash -c '{{ARGS}}'

build-image:
    docker build -t {{image}} -f docker/Dockerfile.dev .

check:
    just _run 'test -z "$(gofmt -l .)" && go vet ./... && golangci-lint run && CGO_ENABLED=0 go build -trimpath ./cmd/fortified && go test ./...'

test:
    just _run 'go test ./...'

test-cover:
    just _run 'go test -cover ./...'

test-integration:
    just _run 'golangci-lint run --build-tags=integration && go vet -tags=integration ./... && go test -tags=integration ./...'

build:
    just _run 'CGO_ENABLED=0 go build -trimpath -o bin/fortified ./cmd/fortified'

fmt:
    just _run 'gofmt -w .'

tidy:
    just _run 'go mod tidy'
