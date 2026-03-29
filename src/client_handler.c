/*=============================================================================
 * client_handler.c — Per-client thread: WS handshake, auth, frame delivery
 *
 * KEY CONCEPTS DEMONSTRATED:
 *  • Full WebSocket HTTP upgrade handshake (RFC 6455)
 *  • Token-based authentication before entering stream
 *  • Partial send handling with retry loop (critical for large frames)
 *  • Concurrent client handling via one thread per client
 *  • Mutex-protected SSL_write to prevent data interleaving
 *  • Condition variable wait for new frame (avoids busy-polling)
 *  • Clean resource teardown on disconnect / auth failure
 *============================================================================*/

#include "rdv.h"
#include <sys/time.h>

/* Forward declaration — server pointer passed via thread argument wrapper */
typedef struct { Client *c; Server *srv; } ThreadArg;

/* Static pool of thread args to avoid heap allocation per connection */
static ThreadArg s_args[RDV_MAX_CLIENTS];
static pthread_mutex_t s_args_lock = PTHREAD_MUTEX_INITIALIZER;

ThreadArg *alloc_thread_arg(Client *c, Server *srv) {
    pthread_mutex_lock(&s_args_lock);
    for (int i = 0; i < RDV_MAX_CLIENTS; i++) {
        if (s_args[i].c == NULL) {
            s_args[i].c   = c;
            s_args[i].srv = srv;
            pthread_mutex_unlock(&s_args_lock);
            return &s_args[i];
        }
    }
    pthread_mutex_unlock(&s_args_lock);
    return NULL;
}

void free_thread_arg(ThreadArg *a) {
    pthread_mutex_lock(&s_args_lock);
    a->c = NULL;
    pthread_mutex_unlock(&s_args_lock);
}

/*──────────────────────────────────────────────────────────────────────────────
 * ws_send_frame_raw()
 *
 * Encodes a WebSocket frame (RFC 6455 §5) and writes it over TLS.
 *
 * PARTIAL SEND HANDLING:
 *   SSL_write() may return a short count if the kernel send buffer is full.
 *   We must retry with EXACTLY the same buffer pointer + remaining length
 *   (OpenSSL requires this for non-blocking sockets).  We track bytes_sent
 *   and loop until fully delivered or an error occurs.
 *
 * LOCKING:
 *   send_lock serialises concurrent calls from the main capture loop vs
 *   any ping/pong control-frame sends from the recv path.
 *─────────────────────────────────────────────────────────────────────────────*/
ssize_t ws_send_frame(Client *c, uint8_t opcode,
                       const uint8_t *data, size_t len) {
    /* ── Build frame header (up to 10 bytes + payload) ─────────────────── */
    uint8_t header[10];
    size_t  hdr_len;

    header[0] = 0x80 | (opcode & 0x0F);  /* FIN=1, opcode */

    if (len <= 125) {
        header[1] = (uint8_t)len;
        hdr_len = 2;
    } else if (len <= 65535) {
        header[1] = 126;
        header[2] = (len >> 8) & 0xFF;
        header[3] = len & 0xFF;
        hdr_len = 4;
    } else {
        header[1] = 127;
        for (int i = 0; i < 8; i++)
            header[2 + i] = (len >> (56 - 8*i)) & 0xFF;
        hdr_len = 10;
    }
    /* Server-to-client frames are NOT masked (RFC 6455 §5.1) */

    /* Assemble into a single contiguous buffer for one SSL_write call */
    size_t total = hdr_len + len;
    uint8_t *buf = malloc(total);
    if (!buf) return -1;
    memcpy(buf, header, hdr_len);
    memcpy(buf + hdr_len, data, len);

    pthread_mutex_lock(&c->send_lock);

    /*
     * PARTIAL SEND RETRY LOOP
     *
     * For TLS, SSL_write() returns:
     *   >0  : bytes written (may be less than total for non-blocking sockets)
     *   0   : connection closed
     *  <0   : SSL_ERROR_WANT_WRITE (retry) or fatal error
     *
     * We use a blocking socket, so SSL_write usually completes in one call
     * for payloads ≤ SO_SNDBUF.  The loop handles the edge case where the
     * kernel buffer was momentarily full (e.g., slow client or congestion).
     */
    size_t sent = 0;
    int    retries = 0;
    ssize_t result = 0;

    while (sent < total) {
        int n = SSL_write(c->ssl, buf + sent, (int)(total - sent));
        if (n > 0) {
            sent += (size_t)n;
            if (sent < total) {
                /* Partial write detected — log it */
                (void)c->frames_sent;  /* just to touch the field */
                db_log_event(NULL /* srv unavailable here; see note */,
                             c->session_id, LOG_PARTIAL,
                             "partial SSL_write");
                retries++;
            }
        } else {
            int err = SSL_get_error(c->ssl, n);
            if (err == SSL_ERROR_WANT_WRITE && retries < 10) {
                /* Transient; kernel buffer briefly full — wait 1 ms */
                usleep(1000);
                retries++;
                continue;
            }
            result = -1;  /* fatal */
            break;
        }
    }

    pthread_mutex_unlock(&c->send_lock);
    free(buf);

    if (result == 0) {
        c->bytes_sent += total;
    }
    return result == 0 ? (ssize_t)total : -1;
}

/*──────────────────────────────────────────────────────────────────────────────
 * ws_recv_frame() — read one WebSocket frame from client over TLS
 *─────────────────────────────────────────────────────────────────────────────*/
int ws_recv_frame(Client *c, WsFrame *frame, uint8_t *buf, size_t bufsz) {
    /* Read 2 mandatory header bytes */
    uint8_t h[2];
    int n = SSL_read(c->ssl, h, 2);
    if (n != 2) return -1;

    frame->fin     = (h[0] & 0x80) != 0;
    frame->opcode  = h[0] & 0x0F;
    frame->masked  = (h[1] & 0x80) != 0;
    uint64_t plen  = h[1] & 0x7F;

    if (plen == 126) {
        uint8_t ext[2];
        if (SSL_read(c->ssl, ext, 2) != 2) return -1;
        plen = ((uint64_t)ext[0] << 8) | ext[1];
    } else if (plen == 127) {
        uint8_t ext[8];
        if (SSL_read(c->ssl, ext, 8) != 8) return -1;
        plen = 0;
        for (int i = 0; i < 8; i++) plen = (plen << 8) | ext[i];
    }

    frame->payload_len = plen;

    if (frame->masked) {
        if (SSL_read(c->ssl, frame->mask_key, 4) != 4) return -1;
    }

    if (plen > bufsz) return -1;  /* payload too large */

    /* Read payload — may arrive in multiple SSL records */
    size_t recvd = 0;
    while (recvd < plen) {
        int r = SSL_read(c->ssl, buf + recvd, (int)(plen - recvd));
        if (r <= 0) return -1;
        recvd += r;
    }

    /* Unmask if needed (client→server frames are always masked per RFC 6455) */
    if (frame->masked) {
        for (size_t i = 0; i < plen; i++)
            buf[i] ^= frame->mask_key[i % 4];
    }

    frame->payload = buf;
    return 0;
}

/*──────────────────────────────────────────────────────────────────────────────
 * ws_handshake() — perform HTTP→WebSocket upgrade over TLS
 *
 * TCP Connection Establishment:
 *   1. Client sends TCP SYN
 *   2. Server responds SYN-ACK
 *   3. Client sends ACK  (3-way handshake complete)
 *
 * TLS Handshake (after TCP):
 *   4. Client → ClientHello
 *   5. Server → ServerHello, Certificate, ServerHelloDone
 *   6. Client → ClientKeyExchange, ChangeCipherSpec, Finished
 *   7. Server → ChangeCipherSpec, Finished
 *   (Application data now encrypted with negotiated session keys)
 *
 * WebSocket Upgrade (HTTP/1.1 over TLS):
 *   8. Client sends: GET /rdv HTTP/1.1\r\n
 *                    Upgrade: websocket\r\n
 *                    Sec-WebSocket-Key: <base64 nonce>\r\n
 *   9. Server responds: 101 Switching Protocols
 *                       Sec-WebSocket-Accept: <HMAC-SHA1 response>
 *─────────────────────────────────────────────────────────────────────────────*/
bool ws_handshake(Client *c, Server *srv) {
    /* ── Step 1: TLS accept ────────────────────────────────────────────── */
    int rc = SSL_accept(c->ssl);
    if (rc != 1) {
        unsigned long e = ERR_get_error();
        char ebuf[256];
        ERR_error_string_n(e, ebuf, sizeof(ebuf));
        fprintf(stderr, "[tls] SSL_accept failed for %s: %s\n", c->ip, ebuf);
        db_log_event(srv, c->session_id, LOG_ERROR, "TLS handshake failed");
        return false;
    }
    printf("[tls] TLS established with %s (cipher: %s)\n",
           c->ip, SSL_get_cipher(c->ssl));

    /* ── Step 2: Read HTTP upgrade request ─────────────────────────────── */
    char req[4096];
    int  req_len = SSL_read(c->ssl, req, sizeof(req) - 1);
    if (req_len <= 0) return false;
    req[req_len] = '\0';

    /* Parse Sec-WebSocket-Key header */
    char *key_start = strstr(req, "Sec-WebSocket-Key:");
    if (!key_start) {
        fprintf(stderr, "[ws] Missing Sec-WebSocket-Key from %s\n", c->ip);
        return false;
    }
    key_start += strlen("Sec-WebSocket-Key:");
    while (*key_start == ' ') key_start++;
    char ws_key[64] = {0};
    sscanf(key_start, "%63[^\r\n]", ws_key);

    /* Compute Sec-WebSocket-Accept */
    char accept_key[64];
    ws_compute_accept(ws_key, accept_key, sizeof(accept_key));

    /* ── Step 3: Send 101 Switching Protocols ───────────────────────────── */
    char response[512];
    int  resp_len = snprintf(response, sizeof(response),
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Accept: %s\r\n"
        "\r\n", accept_key);

    if (SSL_write(c->ssl, response, resp_len) != resp_len) {
        fprintf(stderr, "[ws] Failed to send 101 to %s\n", c->ip);
        return false;
    }

    printf("[ws] WebSocket handshake complete with %s\n", c->ip);
    return true;
}

/*──────────────────────────────────────────────────────────────────────────────
 * ws_authenticate() — receive and validate auth token from client
 *─────────────────────────────────────────────────────────────────────────────*/
bool ws_authenticate(Client *c, Server *srv) {
    uint8_t buf[256];
    WsFrame frame;

    /* Set recv timeout to prevent indefinite blocking */
    struct timeval tv = { .tv_sec = 10, .tv_usec = 0 };
    setsockopt(c->fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    if (ws_recv_frame(c, &frame, buf, sizeof(buf)) < 0) {
        db_log_event(srv, c->session_id, LOG_AUTH_FAIL, "recv timeout/error");
        return false;
    }

    if (frame.opcode != WS_OP_TEXT || frame.payload_len == 0) {
        db_log_event(srv, c->session_id, LOG_AUTH_FAIL, "bad auth frame");
        return false;
    }

    /* Null-terminate the token */
    buf[frame.payload_len] = '\0';
    char *token = (char *)buf;

    /* Strip optional "AUTH:" prefix */
    if (strncmp(token, "AUTH:", 5) == 0) token += 5;

    if (!token_verify(token)) {
        /* Inform client and log */
        const char *deny = "{\"error\":\"Unauthorized\"}";
        ws_send_frame(c, WS_OP_TEXT, (const uint8_t *)deny, strlen(deny));
        db_log_event(srv, c->session_id, LOG_AUTH_FAIL, token);
        fprintf(stderr, "[auth] REJECTED %s — bad token\n", c->ip);
        return false;
    }

    db_log_event(srv, c->session_id, LOG_AUTH_OK, "authenticated");
    printf("[auth] ACCEPTED %s\n", c->ip);

    /* Remove recv timeout now that we're in streaming mode */
    tv.tv_sec = 0; tv.tv_usec = 0;
    setsockopt(c->fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    /* Acknowledge auth success */
    const char *ok = "{\"status\":\"streaming\"}";
    ws_send_frame(c, WS_OP_TEXT, (const uint8_t *)ok, strlen(ok));
    return true;
}

/*──────────────────────────────────────────────────────────────────────────────
 * client_thread() — per-client main loop
 *
 * CONCURRENCY MODEL:
 *   Each client runs in its own POSIX thread (pthread).  The threads share:
 *     • frame_lock + frame_ready cond var — safe frame hand-off
 *     • db_lock    — serialised SQLite writes (WAL mode allows concurrent reads)
 *     • send_lock  — per-client TLS write serialisation
 *     • clients_lock — only held briefly to scan/modify the clients[] array
 *
 *   This model ensures:
 *     • A slow client cannot block other clients (independent threads)
 *     • Frame capture is never delayed by client I/O
 *     • Database writes are consistent (no partial rows)
 *─────────────────────────────────────────────────────────────────────────────*/
void *client_thread(void *arg) {
    /* arg is a pointer to a Client but we need Server too.
     * We use a global g_srv exposed from server_core.c. */
    extern Server *g_srv;
    Client *c   = (Client *)arg;
    Server *srv = g_srv;

    /* ── Open DB session ────────────────────────────────────────────────── */
    c->session_id = db_open_session(srv, c->ip, c->port);
    db_log_event(srv, c->session_id, LOG_CONNECT, "TCP accepted");

    /* ── WebSocket handshake ────────────────────────────────────────────── */
    c->state = CLIENT_STATE_HANDSHAKE;
    if (!ws_handshake(c, srv)) goto cleanup;

    /* ── Authentication ─────────────────────────────────────────────────── */
    c->state = CLIENT_STATE_AUTH;
    if (!ws_authenticate(c, srv)) goto cleanup;

    /* ── Streaming loop ─────────────────────────────────────────────────── */
    c->state = CLIENT_STATE_STREAMING;

    uint64_t last_seq = 0;  /* tracks which frame we last sent */

    while (c->active) {
        /* Wait for a NEW frame (condition variable avoids busy-polling) */
        pthread_mutex_lock(&srv->frame_lock);
        while (srv->frame_seq == last_seq && c->active) {
            /*
             * pthread_cond_timedwait prevents permanent block if capture dies.
             * We wake up every 2 s to check c->active.
             */
            struct timespec ts;
            clock_gettime(CLOCK_REALTIME, &ts);
            ts.tv_sec += 2;
            pthread_cond_timedwait(&srv->frame_ready, &srv->frame_lock, &ts);
        }

        if (!c->active) {
            pthread_mutex_unlock(&srv->frame_lock);
            break;
        }

        /* Copy frame metadata — hold lock as short as possible */
        size_t  flen   = srv->frame_len;
        uint8_t *fdata = srv->current_frame;
        last_seq       = srv->frame_seq;
        pthread_mutex_unlock(&srv->frame_lock);

        /* Send frame as binary WebSocket message */
        ssize_t sent = ws_send_frame(c, WS_OP_BINARY, fdata, flen);
        if (sent < 0) {
            fprintf(stderr, "[stream] Send failed to %s — disconnecting\n", c->ip);
            break;
        }

        c->frames_sent++;
        c->bytes_sent += (uint64_t)flen;

        /* Log every 100 frames to reduce DB write pressure */
        if (c->frames_sent % 100 == 0) {
            char detail[64];
            snprintf(detail, sizeof(detail),
                     "frames=%llu bytes=%llu",
                     (unsigned long long)c->frames_sent,
                     (unsigned long long)c->bytes_sent);
            db_log_event(srv, c->session_id, LOG_FRAME_TX, detail);
        }

        /*
         * CONGESTION HANDLING:
         * If the remote window is full (would block), ws_send_frame retries.
         * If retries are exhausted, it returns -1 and we disconnect the
         * slow client rather than letting it stall the whole server.
         * This prevents the frame lock from being held while writing to a
         * congested socket.
         */
    }

cleanup:
    /* ── Graceful WebSocket close ───────────────────────────────────────── */
    c->state = CLIENT_STATE_CLOSING;
    {
        uint8_t close_body[2] = { 0x03, 0xE8 }; /* status 1000 = normal */
        ws_send_frame(c, WS_OP_CLOSE, close_body, 2);
    }

    db_log_event(srv, c->session_id, LOG_DISCONNECT, "client disconnected");
    db_close_session(srv, c->session_id, c->frames_sent, c->bytes_sent);

    /* ── Resource cleanup ───────────────────────────────────────────────── */
    SSL_shutdown(c->ssl);
    SSL_free(c->ssl);
    close(c->fd);

    pthread_mutex_lock(&srv->clients_lock);
    c->state  = CLIENT_STATE_DEAD;
    c->active = false;
    pthread_mutex_unlock(&srv->clients_lock);

    printf("[client] Disconnected %s — sent %llu frames (%llu bytes)\n",
           c->ip,
           (unsigned long long)c->frames_sent,
           (unsigned long long)c->bytes_sent);

    return NULL;
}
