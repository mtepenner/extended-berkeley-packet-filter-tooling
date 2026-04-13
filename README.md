# 🚀 eBPF Process Monitor Tooling

## 📖 Description
This repository contains a collection of Extended Berkeley Packet Filter (eBPF) tools designed to monitor process execution and creation in Linux environments. It demonstrates two distinct approaches to building eBPF tracing applications: a modern Go-based loader using `cilium/ebpf`, and a Python script leveraging the BPF Compiler Collection (BCC). To ensure a seamless and reproducible build experience without modifying your host system, a Vagrant-based development environment is included.

## 📑 Table of Contents
- [Features](#-features)
- [Technologies Used](#-technologies-used)
- [Installation & Setup](#-installation--setup)
- [Usage](#-usage)
  - [Go eBPF Monitor](#go-ebpf-monitor)
  - [Python BCC Monitor](#python-bcc-monitor)
- [Contributing](#-contributing)
- [License](#-license)

## ✨ Features
* **eBPF Kernel Tracing:** Hooks directly into kernel tracepoints (`sys_enter_execve`) and system calls (`clone`) for low-overhead monitoring.
* **Go User-Space Agent:** Utilizes Go and RingBuffers to parse and filter kernel events gracefully.
* **Python BCC Script:** Provides a lightweight alternative for tracing process creation using BPF and Python.
* **Target UID Filtering:** Includes command-line argument parsing in the Go application to filter process execution by a specific User ID (UID).
* **Isolated Development VM:** Fully automated VirtualBox provisioning using Ubuntu Jammy64, pre-configured with LLVM, Clang, Go, and Linux kernel headers.

## 🛠️ Technologies Used
* **Languages:** Go, C, Python
* **eBPF Frameworks:** `cilium/ebpf` (Go), BPF Compiler Collection (BCC)
* **Infrastructure:** Vagrant, VirtualBox, Ubuntu Linux

## ⚙️ Installation & Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/mtepenner/extended-berkeley-packet-filter-tooling.git
   cd extended-berkeley-packet-filter-tooling
````

2.  **Boot the Vagrant Environment:**
    To compile and run eBPF programs, specific kernel headers and LLVM tools are required. We recommend using the provided Vagrant VM.

    ```bash
    vagrant up
    ```

    *Note: The VM provisions with 2GB of memory and 2 CPUs, installing `build-essential`, `clang`, `llvm`, `golang-go`, and the necessary `linux-headers`.*

3.  **Access the VM:**

    ```bash
    vagrant ssh
    ```

    *The provisioning script automatically drops you into the `/vagrant` shared folder upon login.*

## 💻 Usage

> **⚠️ Note:** eBPF programs require root privileges to load into the kernel.

### Go eBPF Monitor

This tool monitors the `sys_enter_execve` tracepoint to capture newly executed commands.

1.  **Build the application:**
    Use the provided Makefile to generate the Go bindings and build the user-space loader.
    ```bash
    make all
    ```
2.  **Run the monitor:**
    ```bash
    sudo ./process-monitor
    ```
3.  **Run with UID filtering:**
    You can monitor executions by a specific UID (e.g., 1000).
    ```bash
    sudo ./process-monitor -uid 1000
    ```
4.  **Clean build artifacts:**
    ```bash
    make clean
    ```

### Python BCC Monitor

This script attaches an eBPF program to the `clone` system call to track when new processes are spawned.

1.  **Run the script:**
    ```bash
    sudo python3 process_monitor.py
    ```
    *Use `Ctrl+C` to exit and stop tracing.*

## 🤝 Contributing

Contributions, issues, and feature requests are welcome\! Feel free to check the issues page.

## 📄 License

This project is open-source and available under the [MIT License]
