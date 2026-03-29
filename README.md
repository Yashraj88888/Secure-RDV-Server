# Secure Web-Based Remote Desktop Viewer (RDV) Server

A high-performance, multi-threaded C server for securely streaming real-time remote desktop frames over TLS-encrypted WebSockets. This project demonstrates advanced network programming capabilities including low-latency TCP optimization, concurrent client handling, binary payload framing, and thread-safe persistent logging.

---

## 🚀 Features
* **Zero-Latency TCP Optimization:** Custom socket tuning using `TCP_NODELAY`, `SO_SNDBUF`, and `SO_REUSEADDR` to prevent buffer bloating and bypass Nagle's algorithm for instant frame dispatch.
* **Concurrent Multi-Threading:** Utilizes POSIX threads (`pthreads`) to allow multiple authenticated clients to view the master stream simultaneously without blocking server I/O.
* **TLS Encrypted WebSockets:** Implements OpenSSL wrappers (`SSL_accept`) over raw sockets, parsing and hashing RFC 6455 standard WebSocket upgrade headers to securely emit binary frame payloads.
* **Robust Session Logging:** Features a completely thread-safe (`pthread_mutex_t`) file-logging architecture tracking precise incoming IP addresses, connection durations, and total encrypted byte-transit sizes upon automated network teardowns.
* **Application-layer Security:** Prevents unauthenticated binary transmission by enforcing a strict token handshake layer.

---

## 🛠️ Prerequisites & Dependencies
The server relies strictly on C standard libraries and OpenSSL.
* `gcc` or `clang` compiler
* `make`
* `openssl` toolkit & headers (For TLS context)

*(On macOS, install openssl via `brew install openssl`. The current `Makefile` automatically includes the homebrew Apple Silicon openssl paths).*

---

## ⚙️ Build and Run Instructions

### 1. Compile the Source Code
Clone this repository and run the Makefile to generate the executable.
```bash
make clean
make
```

### 2. Generate SSL/TLS Certificates
A valid certificate pair is required to run the `wss://` (WebSocket Secure) protocol.
```bash
openssl req -x509 -newkey rsa:2048 -nodes -keyout server.key -out server.crt -days 365
```
*(Press Enter to accept the defaults).*

### 3. Start the Server & Logging Monitor
Launch the server. It will immediately begin listening on TCP Port **8443**.
```bash
./rdv_server
```
We recommend opening a secondary terminal to watch the thread-safe session database logger in real-time:
```bash
tail -f rdv_sessions.log
```

### 4. Connect a Client
The server requires clients that understand secure websockets. You can simulate a connection using `wscat` (installable via `npm install -g wscat`).

Connect to the server (the `-n` flag bypasses self-signed cert checks):
```bash
wscat -c wss://127.0.0.1:8443/rdv -n
```

Once connected, you **must authenticate** to receive the stream. Type the following:
```text
AUTH:rdv-secret-2024
```
Upon successful authentication, the server will immediately begin spamming the terminal with raw encrypted binary video frame data.

---

## 📚 Project Architecture & Academic Documentation
For a deep dive into exactly how the network layers interact, why specific TCP states occur, how the OpenSSL wrapper translates bytes, and how our `pthread_mutex` locking mechanisms avoid race conditions:

📄 **[Read the Architecture Concepts Document](./README_Architecture_Concepts.md)**

## 🛡️ License
This project was developed for advanced network programming research. Open-sourced under the MIT License.