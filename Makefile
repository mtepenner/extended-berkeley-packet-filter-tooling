.PHONY: all generate build clean

# The output binary name
APP=process-monitor

all: generate build

generate:
	@echo "Generating eBPF Go bindings..."
	go generate ./...

build:
	@echo "Building user-space loader..."
	go build -o $(APP) main.go

clean:
	@echo "Cleaning up..."
	rm -f $(APP)
	rm -f bpf_bpfel.* bpf_bpfeb.*
