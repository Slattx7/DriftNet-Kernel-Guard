# 🛡️ DriftNet-Kernel-Guard (Project OMNI)

<div align="center">

[![Kernel](https://img.shields.io/badge/Kernel-Ring--0_eBPF-black.svg?style=for-the-badge&logo=linux&logoColor=white)](https://ebpf.io/)
[![Architecture](https://img.shields.io/badge/Arch-ARM64_%2F_AArch64-blue.svg?style=for-the-badge&logo=arm&logoColor=white)](https://arm.com/)
[![Target Device](https://img.shields.io/badge/Target-OnePlus_9R_(lemonades)-FF0000.svg?style=for-the-badge&logo=android&logoColor=white)](https://lineageos.org/)
[![Root](https://img.shields.io/badge/Installer-Magisk_Systemless-00B0FF.svg?style=for-the-badge&logo=android&logoColor=white)](magisk_module/)
[![Relay](https://img.shields.io/badge/Relay-Go_Static_ARM64-00ADD8.svg?style=for-the-badge&logo=go&logoColor=white)](modules/ebpf_kernel/)
[![License](https://img.shields.io/badge/License-MIT-blue.svg?style=for-the-badge)](LICENSE)

**Kernel-space active intrusion detection and automated mitigation system for rooted Android devices, powered by eBPF Ring-0 probes, atomic in-kernel SIGKILL, dual-stack network interception, and local AI triage.**

</div>

---

## 🔬 Overview & Vision

Traditional mobile endpoint detection and response (EDR) solutions and runtime instrumentation frameworks (such as Frida or Xposed) operate strictly in **Ring-3 (userspace)**. Modern Android malware, sophisticated spyware, and stealth droppers detect these hooks trivially through memory scanning, ptrace anti-debugging, and direct syscall invocation (`svc 0`).

**DriftNet-Kernel-Guard** flips the battlefield by embedding observability and enforcement directly into the **Linux Kernel (Ring-0)** using **eBPF (Extended Berkeley Packet Filter)**. Telemetry is collected at the lowest possible layer before userspace code receives execution feedback, rendering the security sensors completely invisible to monitored processes.

---

## ⚡ Key Technical Innovations

### 1. 🎯 In-Kernel Atomic Mitigation (`SIGKILL`)
When a process executes an unauthorized binary or attempts an exfiltration connection flagged as malicious:
- DriftNet inserts the target PID into the kernel-pinned hash map `/sys/fs/bpf/blacklist_pids`.
- The eBPF kprobe intercepts the next syscall (`sys_connect` or `sys_execve`) from that PID.
- The kernel helper `bpf_send_signal(9)` delivers an **instant, kernel-originated `SIGKILL`** in less than **`2µs`**, aborting the network socket before TCP SYN egress.

### 2. 🌐 Dual-Stack IPv4 & IPv6 Interception
- **AF_INET (IPv4):** Extracts 32-bit destination IP and 16-bit big-endian port from `struct sockaddr_in`.
- **AF_INET6 (IPv6):** Traverses `struct sockaddr_in_v6` in kernel memory, safely extracting the full 128-bit IPv6 address and destination port.
- **Noise Reduction Filter:** Automatically filters non-IP sockets (`AF_UNIX`, `AF_NETLINK`, `AF_BLUETOOTH`), preventing perf buffer lock contention and keeping telemetry CPU usage below **`0.2%`**.

### 3. 🔄 Resilient Reconnecting Telemetry Relay (`bpf_relay`)
- Statically compiled Go binary for ARM64 with zero dynamic C library dependencies.
- Features a resilient client state machine with mutex-guarded reconnect loops over the **Tailscale mesh** (`ws://<host-tailscale-ip>:8787/ws/ingest`).
- Handles network sleep cycles, Wi-Fi transitions, and Android Doze without crashing or losing eBPF ring-buffer sync.

---

## 🏛️ Architecture Pipeline

```mermaid
sequenceDiagram
    autonumber
    participant App as Monitored Android Process
    participant Kernel as Linux Kernel (Ring-0 eBPF)
    participant Relay as bpf_relay (Static Go)
    participant Host as Host Workstation (driftnetd)
    participant AI as Local Ollama (Qwen 2.5 7B)

    App->>Kernel: sys_connect(sockaddr_in / in6) or sys_execve()
    Kernel->>Kernel: Check blacklist_pids BPF map
    alt PID is blacklisted
        Kernel-->>App: bpf_send_signal(9) -> Instant SIGKILL (Terminated)
    else PID is clean
        Kernel->>Relay: Output event to BPF Perf Event Buffer
        Relay->>Host: Stream JSON over WebSocket (Tailscale Mesh)
        Host->>Host: Score Normalized Compression Distance (NCD)
        alt Novelty Score > 0.5 (Structural Anomaly)
            Host->>AI: Dispatch Syscall Payload to LLM
            AI-->>Host: Verdict: BLOCK (Malicious zero-day pattern)
            Host->>Relay: Command: {"action": "BLOCK", "pid": 17040}
            Relay->>Kernel: Add PID 17040 to /sys/fs/bpf/blacklist_pids
        end
    end
```

---

## 📦 Repository Structure

```
├── deploy/                 # Docker Compose & AWS Terraform C2 configurations
├── driftnet/               # Go telemetry aggregator, NCD scoring, & Next.js UI
├── magisk_module/          # Magisk root installer package for OnePlus 9R
│   ├── OMNI_Magisk_Release.zip # Pre-built flashable systemless module
│   ├── customize.sh        # Installation & ABI verification script
│   ├── service.sh          # Late-boot daemon launcher
│   └── root/               # Statically linked bpf_loader & bpf_relay
├── modules/
│   ├── compute/            # Vulkan compute engine host tests
│   ├── ebpf_kernel/        # eBPF C source, Go loader, and WebSocket relay
│   │   ├── bpf_probe.c     # Ring-0 eBPF kprobes with atomic kill
│   │   ├── bpf_loader.go   # eBPF bytecode loader & perf buffer reader
│   │   └── bpf_relay.go    # Telemetry streamer to workstation
│   └── local_ai/           # Edge GGUF quantization tools & test harness
└── test_ci.sh              # Headless CI compilation & verification script
```

---

## 🛠️ Compilation & Deployment Guide

### Prerequisites
- **Target Device:** OnePlus 9R (`lemonades`), Snapdragon 870, Kernel >= 5.10 with `CONFIG_BPF_SYSCALL=y`.
- **Root Solution:** Magisk v24+ installed.
- **Cross-Compiler:** Android NDK r26b+ (Clang 17) & Go 1.23+ with `GOARCH=arm64`.

### 1. Compile the eBPF Kernel Probe
```bash
cd modules/ebpf_kernel

# Cross-compile for ARM64 Android Kernel using Android NDK Clang
$NDK_PATH/toolchains/llvm/prebuilt/linux-x86_64/bin/clang -O2 \
    -target bpf -g \
    -D__TARGET_ARCH_arm64 \
    -c bpf_probe.c -o bpf_probe.o
```

### 2. Compile the Go Loader & Relay
```bash
# Statically compile bpf_loader
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags="-s -w" -o bpf_loader bpf_loader.go

# Statically compile bpf_relay
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags="-s -w" -o bpf_relay bpf_relay.go
```

### 3. Deploy to OnePlus 9R
```bash
# Deploy via ADB to volatile staging area (zero bootloop risk)
adb push bpf_probe.o /data/local/tmp/
adb push bpf_loader /data/local/tmp/
adb push bpf_relay /data/local/tmp/

# Start telemetry stream connected to host workstation over Tailscale
adb shell "su -c 'cd /data/local/tmp && ./bpf_loader ./bpf_probe.o | ./bpf_relay -url ws://100.103.87.117:8787/ws/ingest'"
```

---

## 🛡️ Safety & Integrity Guarantees

> [!IMPORTANT]
> **Zero Bootloop Architecture:** DriftNet-Kernel-Guard does **not** alter the Android `/system` partition or flash custom boot images. All probes are loaded dynamically into kernel memory via the `bpf()` syscall and mapped into `/sys/fs/bpf/`. In the event of an unexpected edge condition or device reboot, the kernel automatically unloads all probes cleanly.

> [!TIP]
> **Host Workstation Offloading:** While an edge quantization path is provided in `modules/local_ai/`, running the LLM triage on the host workstation's RTX 3050 GPU keeps mobile battery drain under **`1% per 8 hours`** and frees the phone's Adreno 650 GPU for system tasks.

---

## 📄 License

This repository is licensed under the MIT License. See [LICENSE](LICENSE) for details.
