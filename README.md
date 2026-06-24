# syncsc - async tcp syn-scanner

Asynchronous TCP SYN port scanner (inspired by nmap -Ss behaviour) in pure C. It interacts directly with the network stack using raw sockets, implemented sliding window mechanism with timeout control using `epoll` combined with `timerfd` to avoid multi-threading.
This project was built to deeply understand low-level network programming, raw packet crafting, and asynchronous I/O in Linux.

## What was learned

This project was developed as a exploration of the Linux network stack, raw socket programming, and low-level I/O multiplexing. The primary goal was to move away from high-level abstractions (like standard `SOCK_STREAM` sockets) and understand how the operating system manages network states, packet lifecycles, and hardware-software boundaries.

#### Manual Packet Crafting and Serialization
Operating via `SOCK_RAW` (`IPPROTO_TCP`) requires bypassing the kernel's transport layer and building headers manually. Development involved:
* **Memory Layout & Byte Ordering:** Mapping raw byte buffers directly to kernel networking structures (`struct iphdr` and `struct tcphdr`). This required handling strict alignment and converting data between host and network byte orders (`htons`/`ntohs`).
* **Checksum Computation:** Implementing the Internet Checksum algorithm (RFC 1071) using bitwise operations over a dynamic TCP pseudo-header for packet validation.

#### Single-Threaded I/O Multiplexing via Epoll
To avoid multi-threading, the engine utilizes an asynchronous event loop:
* **Unified Event Interest List:** network events from the raw receive socket (`rx_fd`) and time-based events from a kernel timer (`timerfd`) are managed within a single `epoll` instance.
* **$O(1)$ Event Handling:** leveraging `epoll`'s readiness list mechanism to handle thousands of concurrent port states efficiently, maintaining stable performance regardless of the target port range.

#### Flow Control & State Tracking via Sliding Window
Blasting thousands of raw packets simultaneously causes network congestion and local socket buffer saturation; to mitigate this, a **sliding window** mechanism was implemented:
* **Resource Regulation:** The window strictly limits the maximum number of active packets "in flight" (`MAX_WINDOW`), preventing packet drops in local kernel ring buffers and intermediate routers.
* **Asynchronous Timeout Management:** Packet expiration is tracked using millisecond-accurate timestamps (`clock_gettime`). When the 20ms `timerfd` ticks, expired or firewalled ports are safely flagged as `FILTERED`, sliding the window boundaries forward to inject new packets without blocking the thread.

## Core Features

* **True Asynchrony** — scans all 65535 ports in a single thread.
* **Sliding Window (Flow Control)** — strictly controls the maximum number of active packets "in flight".
* **Timeouts** — integrates `timerfd` ticking every 20ms to catch firewalled/dropped ports, sliding the window smoothly.
* **Packet Filtering** — includes a parser that inspects raw packet flows and isolates responses belonging strictly to our scanner based on source ports and targets.

## Quick Start

### Requirements
Linux OS (kernel with `epoll` and `timerfd` support), `gcc` compiler, `make` utility

### Installation
```bash 
git clone https://github.com/s00inx/synsc
cd synsc
make
```

#### Usage example
```bash
# scan ip (scanme.nmap.org) with 8888 source port
sudo ./syncsc 45.33.32.156 -p 8888
```
