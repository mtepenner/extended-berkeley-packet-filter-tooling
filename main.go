package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// Generate the eBPF bindings (Requires the bpf2go tool)
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type event bpf monitor.bpf.c

func main() {
	// Edge Case 1: Argument Parsing
	targetUid := flag.Int("uid", -1, "Only show executions by this UID (e.g., 1000)")
	flag.Parse()

	// Edge Case 2: Privilege check
	if os.Geteuid() != 0 {
		log.Fatal("This eBPF program must be run as root.")
	}

	// Remove resource limits for kernels < 5.11
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// Load the compiled eBPF ELF and load it into the kernel
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("Loading objects: %v", err)
	}
	defer objs.Close()

	// Attach the program to the tracepoint
	tp, err := link.Tracepoint("syscalls", "sys_enter_execve", objs.TraceExecve, nil)
	if err != nil {
		log.Fatalf("Opening tracepoint: %v", err)
	}
	defer tp.Close()

	// Open a ringbuf reader from user space
	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("Opening ringbuf reader: %v", err)
	}
	defer rd.Close()

	// Edge Case 3: Graceful shutdown
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-stopper
		fmt.Println("\nReceived signal, exiting gracefully...")
		rd.Close()
		os.Exit(0)
	}()

	fmt.Printf("%-10s %-10s %-16s\n", "PID", "UID", "COMMAND")
	fmt.Println("----------------------------------------")

	var event bpfEvent
	for {
		record, err := rd.Read()
		if err != nil {
			if err == ringbuf.ErrClosed {
				return
			}
			log.Printf("Error reading from reader: %v", err)
			continue
		}

		// Parse the ringbuf event into our Go struct
		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
			log.Printf("Parsing ringbuf event: %v", err)
			continue
		}

		// Apply user-space filtering if the flag was set
		if *targetUid != -1 && event.Uid != uint32(*targetUid) {
			continue
		}

		// Format the C string (remove null bytes)
		comm := bytes.TrimRight(event.Comm[:], "\x00")
		fmt.Printf("%-10d %-10d %-16s\n", event.Pid, event.Uid, string(comm))
	}
}
