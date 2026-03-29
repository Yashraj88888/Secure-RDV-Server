# Secure Web-Based Remote Desktop Viewer (RDV)
## Architectural Analysis and Core Concepts

This document explains the advanced network programming mechanics, performance optimisations, and threading architecture used in the Secure RDV server implementation. The project successfully adheres to the requirements of socket lifecycle management, TLS encryption, WebSockets framing, concurrency models, and persistent logging.

---

### 1. TCP Connection & Socket Lifecycle Management

The foundation of our server rests upon standard POSIX TCP Sockets (stream-oriented). Because real-time video streaming requires extremely low latency, default OS socket behaviour is inappropriate for this application. To ensure optimal data flow, the server configures specific socket options (`setsockopt`):

*   **SO_REUSEADDR**: When a server crashes or shuts down, the TCP state machine enters a `TIME_WAIT` phase, essentially locking the port for up to 60 seconds. By applying `SO_REUSEADDR` to our listener in `server_core.c`, the OS permits us to immediately rebind to the port (`8443`), preventing restart delays during server maintenance.
*   **TCP_NODELAY**: By default, TCP uses Nagle's Algorithm. It buffers small packets and waits until it has a full payload (or receives an ACK) before dispatching the data to the network—reducing congestion but severely increasing latency. For a Remote Desktop Viewer, frame data needs to hit the wire immediately. We apply `TCP_NODELAY` to force instantaneous outbound flushing of our frame chunks.
*   **SO_SNDBUF & SO_RCVBUF**: Video frames can easily hit megabytes per second. We explicitly enlarge the OS send buffers (`SO_SNDBUF = 256KB`) so the TCP stack can hold multiple heavy payload fragments before the `SSL_write()` action hits a blocking state, smoothing out network jitters.

---

### 2. TLS-Based Encryption Workflow

Streaming desktop feeds over plain text is a severe security flaw. We circumvent this by wrapping the standard socket inside an OpenSSL `SSL_CTX` environment.

1.  **Certificate Initialization:** `server.key` and `server.crt` are loaded into memory.
2.  **Handshake Overlay:** When a standard TCP `accept()` triggers, the raw file descriptor is passed to `SSL_new()` and `SSL_accept()`.
3.  **Cypher Negotiation:** The server forces strong cipher preferences and negotiates a minimum of `TLSv1.2` with the client.
4.  **Overhead:** TLS naturally introduces encryption overhead and padding constraints; however, by pre-allocating contiguous memory chunks for the simulated frames and dispatching them with `TCP_NODELAY`, this mathematical overhead on throughput is minimised.

---

### 3. The WebSocket Protocol & Data Framing

Because the project communicates with a browser or standard CLI (`wscat`), it must upgrade the raw TCP/TLS connection into a persistent, bidirectional WebSocket (RFC 6455) stream.

1.  **Handshake:** The core C code parses HTTP headers sent by the client. It isolates the `Sec-WebSocket-Key`, appends the mandatory standard Magic String (`258EAFA5-E914-47DA-95CA-C5AB0DC85B11`), performs a high-speed SHA-1 hash (using OpenSSL's `EVP`), Base64-encodes the hash, and responds with a `101 Switching Protocols` header.
2.  **Authentication:** After the handshake, the WebSocket remains open, but the server enforces an application-layer lock. It halts frame transmission until it receives an explicit Text frame containing the token `AUTH:rdv-secret-2024`.
3.  **Binary Framing Payload:** Once authenticated, the server begins constructing binary WebSocket frames. It correctly constructs the first two bytes to indicate standard text (`0x81`) or binary (`0x82`), calculates mathematical payload lengths, applies a 4-byte unmasking routine for incoming text, and writes the chunk.

---

### 4. Concurrency Model: Handling Multiple Clients

A single-threaded C server would severely choke if one client had a slow network connection because the `write()` system call would block entirely, freezing all other viewers.

To resolve this, the system implements a robust **thread-per-client model** natively using POSIX threads (`pthreads`):
*   **Thread Spawning:** For every successful TCP accept, the global server thread creates a detached worker thread via `pthread_create`.
*   **Shared Memory Safety:** There is only one simulated screen being updated (the Capture Thread), which updates a global buffer array. To ensure no thread attempts to read a screen frame while it's currently being overwritten, memory scopes are protected heavily using mutex locks (`pthread_mutex_lock(&srv->frame_lock)`). 
*   **Thread Autonomy:** Because each connected instance lives dynamically inside its own decoupled thread context, one client's severe network latency or sudden disconnection has exactly a 0% impact on the performance of sibling clients.

---

### 5. Resiliency, Resource Cleanup, and Persistent Logging

**Handling Congestion & Sudden Disconnects:**
Network streams frequently tear down without sending polite `FIN` packets. The loop constantly checks the byte return output of `SSL_read` and `SSL_write`. If it drops below zero (`<= 0`), the connection is flagged as "Broken Pipe" or "Connection Reset by Peer."
The system executes a safe termination block (`goto cleanup`), safely liberating internal memory pointers (`free()`), executing an `SSL_free()`, and safely closing the file descriptor `close(fd)` ensuring there are no zombie sockets leaking server descriptors.

**Persistent Database Logging:**
The system uses `PTHREAD_MUTEX_INITIALIZER` to create a thread-safe barrier around standard C file I/O operations (`fopen`, `fprintf`). This ensures that if 30 connected users drop their connections simultaneously, the system queues up the write locks sequentially. As a result:
*   Session IDs, precise start/end timestamps, and exact byte counts are cleanly authored.
*   Data corruption inside the `rdv_sessions.log` target file is permanently eliminated.