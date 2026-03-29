#!/usr/bin/env bash
# =============================================================================
# setup_and_run.sh — RDV Project: Place files, build, and run
#
# Usage:
#   chmod +x setup_and_run.sh
#   ./setup_and_run.sh              # build and run server
#   ./setup_and_run.sh --build-only # just build, don't run
#   ./setup_and_run.sh --clean      # remove build artifacts
# =============================================================================

set -euo pipefail

# ── Colour helpers ────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

info()    { echo -e "${CYAN}[info]${RESET}  $*"; }
success() { echo -e "${GREEN}[ok]${RESET}    $*"; }
warn()    { echo -e "${YELLOW}[warn]${RESET}  $*"; }
die()     { echo -e "${RED}[error]${RESET} $*" >&2; exit 1; }

# ── Project root = directory this script lives in ────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT="$SCRIPT_DIR"

# ── Parse args ────────────────────────────────────────────────────────────────
BUILD_ONLY=false
CLEAN=false
for arg in "$@"; do
  case "$arg" in
    --build-only) BUILD_ONLY=true ;;
    --clean)      CLEAN=true ;;
    --help|-h)
      echo "Usage: $0 [--build-only] [--clean]"
      exit 0 ;;
    *) die "Unknown argument: $arg" ;;
  esac
done

# ── Banner ────────────────────────────────────────────────────────────────────
echo -e "${BOLD}"
echo "╔══════════════════════════════════════════════════════╗"
echo "║   RDV — Secure Remote Desktop Viewer  (Setup Script) ║"
echo "╚══════════════════════════════════════════════════════╝"
echo -e "${RESET}"

# ── Clean mode ───────────────────────────────────────────────────────────────
if $CLEAN; then
  info "Cleaning build artefacts..."
  rm -f "$PROJECT/rdv_server" \
        "$PROJECT/server.crt" \
        "$PROJECT/server.key" \
        "$PROJECT/rdv_sessions.db"
  success "Clean done."
  exit 0
fi

# =============================================================================
# STEP 1 — Create directory structure
# =============================================================================
echo -e "\n${BOLD}Step 1 — Creating directory structure${RESET}"

for dir in "$PROJECT/src" "$PROJECT/include" "$PROJECT/docs"; do
  mkdir -p "$dir"
  success "Directory: $dir"
done

# =============================================================================
# STEP 2 — Write all source files in place
# =============================================================================
echo -e "\n${BOLD}Step 2 — Writing source files${RESET}"

write_file() {
  local path="$1"
  # Content comes from stdin (heredoc at call site)
  cat > "$path"
  success "Wrote: ${path#$PROJECT/}"
}

# ── include/rdv.h ─────────────────────────────────────────────────────────────
write_file "$PROJECT/include/rdv.h" << 'HEREDOC'
#ifndef RDV_H
#define RDV_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <sqlite3.h>

#define RDV_PORT            8443
#define RDV_MAX_CLIENTS     32
#define RDV_FRAME_BUF       (1 << 20)
#define RDV_SNDBUF_SIZE     (256 * 1024)
#define RDV_RCVBUF_SIZE     (64  * 1024)
#define RDV_FPS             15
#define RDV_FRAME_INTERVAL_US (1000000 / RDV_FPS)
#define RDV_TOKEN_LEN       32
#define RDV_DB_PATH         "rdv_sessions.db"
#define RDV_CERT_FILE       "server.crt"
#define RDV_KEY_FILE        "server.key"
#define RDV_WS_MAGIC        "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

#define WS_OP_CONTINUATION  0x0
#define WS_OP_TEXT          0x1
#define WS_OP_BINARY        0x2
#define WS_OP_CLOSE         0x8
#define WS_OP_PING          0x9
#define WS_OP_PONG          0xA

typedef enum {
    CLIENT_STATE_HANDSHAKE = 0,
    CLIENT_STATE_AUTH,
    CLIENT_STATE_STREAMING,
    CLIENT_STATE_CLOSING,
    CLIENT_STATE_DEAD
} ClientState;

typedef enum {
    LOG_CONNECT   = 1,
    LOG_AUTH_OK   = 2,
    LOG_AUTH_FAIL = 3,
    LOG_FRAME_TX  = 4,
    LOG_PARTIAL   = 5,
    LOG_DISCONNECT= 6,
    LOG_ERROR     = 7
} LogEvent;

typedef struct {
    int            fd;
    SSL           *ssl;
    ClientState    state;
    char           ip[INET_ADDRSTRLEN];
    uint16_t       port;
    int64_t        session_id;
    pthread_t      thread;
    pthread_mutex_t send_lock;
    volatile bool  active;
    uint64_t       frames_sent;
    uint64_t       bytes_sent;
    time_t         connected_at;
} Client;

typedef struct {
    int            listen_fd;
    SSL_CTX       *ssl_ctx;
    sqlite3       *db;
    pthread_mutex_t db_lock;
    pthread_mutex_t clients_lock;
    Client         clients[RDV_MAX_CLIENTS];
    volatile bool  running;
    uint8_t        frame_a[RDV_FRAME_BUF];
    uint8_t        frame_b[RDV_FRAME_BUF];
    size_t         frame_len;
    uint8_t       *current_frame;
    pthread_mutex_t frame_lock;
    pthread_cond_t  frame_ready;
    uint64_t        frame_seq;
} Server;

typedef struct {
    uint8_t  opcode;
    bool     fin;
    bool     masked;
    uint64_t payload_len;
    uint8_t  mask_key[4];
    uint8_t *payload;
} WsFrame;

/* server_core.c */
int  server_init(Server *srv);
void server_run(Server *srv);
void server_shutdown(Server *srv);
void apply_socket_options(int fd);

/* client_handler.c */
void *client_thread(void *arg);
bool  ws_handshake(Client *c, Server *srv);
bool  ws_authenticate(Client *c, Server *srv);
ssize_t ws_send_frame(Client *c, uint8_t opcode, const uint8_t *data, size_t len);
int   ws_recv_frame(Client *c, WsFrame *frame, uint8_t *buf, size_t bufsz);

/* screen_capture.c */
void *capture_thread(void *arg);
size_t capture_frame(uint8_t *out, size_t max);

/* db_logger.c */
bool    db_init(Server *srv);
int64_t db_open_session(Server *srv, const char *ip, uint16_t port);
void    db_close_session(Server *srv, int64_t session_id, uint64_t frames, uint64_t bytes);
void    db_log_event(Server *srv, int64_t session_id, LogEvent ev, const char *detail);
void    db_close(Server *srv);

/* crypto_utils.c */
SSL_CTX *tls_create_context(void);
void     ws_compute_accept(const char *key, char *out64, size_t outsz);
bool     token_verify(const char *token);

extern Server *g_srv;

#endif /* RDV_H */
HEREDOC

# ── src/main.c ────────────────────────────────────────────────────────────────
write_file "$PROJECT/src/main.c" << 'HEREDOC'
#include "rdv.h"

int main(int argc, char *argv[]) {
    (void)argc; (void)argv;

    printf("╔══════════════════════════════════════════════════╗\n");
    printf("║   Remote Desktop Viewer — Secure WebSocket Server  ║\n");
    printf("║   Assignment: Network Programming (10 marks)       ║\n");
    printf("╚══════════════════════════════════════════════════╝\n\n");

    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    Server srv;
    if (server_init(&srv) < 0) {
        fprintf(stderr, "[main] Server initialisation failed\n");
        return EXIT_FAILURE;
    }

    printf("[main] Server ready. Connect with: wss://localhost:%d/rdv\n", RDV_PORT);
    printf("[main] Auth token: rdv-secret-2024\n");
    printf("[main] Press Ctrl+C to stop.\n\n");

    server_run(&srv);
    server_shutdown(&srv);

    EVP_cleanup();
    ERR_free_strings();
    return EXIT_SUCCESS;
}
HEREDOC

# ── src/server_core.c ─────────────────────────────────────────────────────────
write_file "$PROJECT/src/server_core.c" << 'HEREDOC'
#include "rdv.h"

Server *g_srv = NULL;

static void sig_handler(int sig) {
    (void)sig;
    if (g_srv) g_srv->running = false;
    printf("\n[server] Caught signal %d — shutting down\n", sig);
}

void apply_socket_options(int fd) {
    int opt, rc;

    /* TCP_NODELAY: disable Nagle — flush each frame immediately */
    opt = 1;
    rc = setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));
    if (rc < 0) perror("[socket] TCP_NODELAY");

    /* SO_SNDBUF: larger send buffer — queue full frame before blocking */
    opt = RDV_SNDBUF_SIZE;
    rc = setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &opt, sizeof(opt));
    if (rc < 0) perror("[socket] SO_SNDBUF");

    /* SO_RCVBUF: modest recv buffer — server mostly sends */
    opt = RDV_RCVBUF_SIZE;
    rc = setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &opt, sizeof(opt));
    if (rc < 0) perror("[socket] SO_RCVBUF");

    printf("[socket] Options applied fd=%d (TCP_NODELAY, SNDBUF=%d, RCVBUF=%d)\n",
           fd, RDV_SNDBUF_SIZE, RDV_RCVBUF_SIZE);
}

int server_init(Server *srv) {
    memset(srv, 0, sizeof(Server));
    srv->current_frame = srv->frame_a;
    pthread_mutex_init(&srv->frame_lock, NULL);
    pthread_cond_init(&srv->frame_ready, NULL);
    pthread_mutex_init(&srv->clients_lock, NULL);
    pthread_mutex_init(&srv->db_lock, NULL);

    for (int i = 0; i < RDV_MAX_CLIENTS; i++) {
        srv->clients[i].state = CLIENT_STATE_DEAD;
        pthread_mutex_init(&srv->clients[i].send_lock, NULL);
    }

    srv->ssl_ctx = tls_create_context();
    if (!srv->ssl_ctx) { fprintf(stderr, "[init] TLS failed\n"); return -1; }

    if (!db_init(srv)) { fprintf(stderr, "[init] DB failed\n"); return -1; }

    srv->listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (srv->listen_fd < 0) { perror("[init] socket"); return -1; }

    /* SO_REUSEADDR: bind immediately after restart (avoid TIME_WAIT block) */
    int opt = 1;
    setsockopt(srv->listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr = {
        .sin_family      = AF_INET,
        .sin_addr.s_addr = INADDR_ANY,
        .sin_port        = htons(RDV_PORT)
    };
    if (bind(srv->listen_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("[init] bind"); return -1;
    }
    if (listen(srv->listen_fd, SOMAXCONN) < 0) {
        perror("[init] listen"); return -1;
    }

    printf("[server] Listening on port %d (TLS WebSocket)\n", RDV_PORT);
    return 0;
}

void server_run(Server *srv) {
    g_srv = srv;
    srv->running = true;

    signal(SIGINT,  sig_handler);
    signal(SIGTERM, sig_handler);
    signal(SIGPIPE, SIG_IGN);

    pthread_t cap_tid;
    pthread_create(&cap_tid, NULL, capture_thread, srv);

    printf("[server] Accepting connections (max %d clients)\n", RDV_MAX_CLIENTS);

    while (srv->running) {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(srv->listen_fd, &rfds);
        struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };

        if (select(srv->listen_fd + 1, &rfds, NULL, NULL, &tv) <= 0) continue;

        struct sockaddr_in cli_addr;
        socklen_t cli_len = sizeof(cli_addr);
        int cli_fd = accept(srv->listen_fd, (struct sockaddr*)&cli_addr, &cli_len);
        if (cli_fd < 0) { if (errno != EINTR) perror("[accept]"); continue; }

        apply_socket_options(cli_fd);

        pthread_mutex_lock(&srv->clients_lock);
        Client *c = NULL;
        for (int i = 0; i < RDV_MAX_CLIENTS; i++) {
            if (srv->clients[i].state == CLIENT_STATE_DEAD) {
                c = &srv->clients[i]; break;
            }
        }
        if (!c) {
            pthread_mutex_unlock(&srv->clients_lock);
            fprintf(stderr, "[server] Max clients reached — rejecting fd=%d\n", cli_fd);
            close(cli_fd); continue;
        }

        c->fd           = cli_fd;
        c->state        = CLIENT_STATE_HANDSHAKE;
        c->active       = true;
        c->frames_sent  = 0;
        c->bytes_sent   = 0;
        c->connected_at = time(NULL);
        c->session_id   = -1;
        inet_ntop(AF_INET, &cli_addr.sin_addr, c->ip, sizeof(c->ip));
        c->port = ntohs(cli_addr.sin_port);
        c->ssl  = SSL_new(srv->ssl_ctx);
        SSL_set_fd(c->ssl, cli_fd);
        pthread_mutex_unlock(&srv->clients_lock);

        printf("[accept] %s:%u (fd=%d)\n", c->ip, c->port, cli_fd);

        pthread_attr_t attr;
        pthread_attr_init(&attr);
        pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
        pthread_create(&c->thread, &attr, client_thread, c);
        pthread_attr_destroy(&attr);
    }

    pthread_join(cap_tid, NULL);
}

void server_shutdown(Server *srv) {
    printf("[server] Shutting down...\n");
    pthread_mutex_lock(&srv->clients_lock);
    for (int i = 0; i < RDV_MAX_CLIENTS; i++) {
        Client *c = &srv->clients[i];
        if (c->state != CLIENT_STATE_DEAD) {
            c->active = false;
            shutdown(c->fd, SHUT_RDWR);
        }
    }
    pthread_mutex_unlock(&srv->clients_lock);
    sleep(2);
    close(srv->listen_fd);
    SSL_CTX_free(srv->ssl_ctx);
    db_close(srv);
    pthread_mutex_destroy(&srv->frame_lock);
    pthread_mutex_destroy(&srv->clients_lock);
    pthread_mutex_destroy(&srv->db_lock);
    pthread_cond_destroy(&srv->frame_ready);
    printf("[server] Shutdown complete.\n");
}
HEREDOC

# ── src/client_handler.c ──────────────────────────────────────────────────────
write_file "$PROJECT/src/client_handler.c" << 'HEREDOC'
#include "rdv.h"

ssize_t ws_send_frame(Client *c, uint8_t opcode, const uint8_t *data, size_t len) {
    uint8_t header[10];
    size_t  hdr_len;

    header[0] = 0x80 | (opcode & 0x0F);
    if (len <= 125) {
        header[1] = (uint8_t)len; hdr_len = 2;
    } else if (len <= 65535) {
        header[1] = 126;
        header[2] = (len >> 8) & 0xFF; header[3] = len & 0xFF;
        hdr_len = 4;
    } else {
        header[1] = 127;
        for (int i = 0; i < 8; i++) header[2+i] = (len >> (56-8*i)) & 0xFF;
        hdr_len = 10;
    }

    size_t total = hdr_len + len;
    uint8_t *buf = malloc(total);
    if (!buf) return -1;
    memcpy(buf, header, hdr_len);
    memcpy(buf + hdr_len, data, len);

    pthread_mutex_lock(&c->send_lock);

    size_t  sent    = 0;
    int     retries = 0;
    ssize_t result  = 0;

    while (sent < total) {
        int n = SSL_write(c->ssl, buf + sent, (int)(total - sent));
        if (n > 0) {
            sent += (size_t)n;
            if (sent < total) retries++;
        } else {
            int err = SSL_get_error(c->ssl, n);
            if (err == SSL_ERROR_WANT_WRITE && retries < 10) {
                usleep(1000); retries++; continue;
            }
            result = -1; break;
        }
    }

    pthread_mutex_unlock(&c->send_lock);
    free(buf);
    if (result == 0) c->bytes_sent += total;
    return result == 0 ? (ssize_t)total : -1;
}

int ws_recv_frame(Client *c, WsFrame *frame, uint8_t *buf, size_t bufsz) {
    uint8_t h[2];
    if (SSL_read(c->ssl, h, 2) != 2) return -1;

    frame->fin    = (h[0] & 0x80) != 0;
    frame->opcode = h[0] & 0x0F;
    frame->masked = (h[1] & 0x80) != 0;
    uint64_t plen = h[1] & 0x7F;

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
    if (frame->masked && SSL_read(c->ssl, frame->mask_key, 4) != 4) return -1;
    if (plen > bufsz) return -1;

    size_t recvd = 0;
    while (recvd < plen) {
        int r = SSL_read(c->ssl, buf + recvd, (int)(plen - recvd));
        if (r <= 0) return -1;
        recvd += r;
    }
    if (frame->masked)
        for (size_t i = 0; i < plen; i++) buf[i] ^= frame->mask_key[i % 4];

    frame->payload = buf;
    return 0;
}

bool ws_handshake(Client *c, Server *srv) {
    if (SSL_accept(c->ssl) != 1) {
        fprintf(stderr, "[tls] SSL_accept failed for %s\n", c->ip);
        db_log_event(srv, c->session_id, LOG_ERROR, "TLS handshake failed");
        return false;
    }
    printf("[tls] TLS ok with %s (cipher: %s)\n", c->ip, SSL_get_cipher(c->ssl));

    char req[4096];
    int req_len = SSL_read(c->ssl, req, sizeof(req)-1);
    if (req_len <= 0) return false;
    req[req_len] = '\0';

    char *key_start = strstr(req, "Sec-WebSocket-Key:");
    if (!key_start) return false;
    key_start += strlen("Sec-WebSocket-Key:");
    while (*key_start == ' ') key_start++;
    char ws_key[64] = {0};
    sscanf(key_start, "%63[^\r\n]", ws_key);

    char accept_key[64];
    ws_compute_accept(ws_key, accept_key, sizeof(accept_key));

    char response[512];
    int resp_len = snprintf(response, sizeof(response),
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Accept: %s\r\n\r\n", accept_key);

    if (SSL_write(c->ssl, response, resp_len) != resp_len) return false;
    printf("[ws] Handshake complete with %s\n", c->ip);
    return true;
}

bool ws_authenticate(Client *c, Server *srv) {
    uint8_t buf[256];
    WsFrame frame;

    struct timeval tv = { .tv_sec = 10, .tv_usec = 0 };
    setsockopt(c->fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    if (ws_recv_frame(c, &frame, buf, sizeof(buf)) < 0) {
        db_log_event(srv, c->session_id, LOG_AUTH_FAIL, "recv timeout");
        return false;
    }
    if (frame.opcode != WS_OP_TEXT || frame.payload_len == 0) {
        db_log_event(srv, c->session_id, LOG_AUTH_FAIL, "bad auth frame");
        return false;
    }

    buf[frame.payload_len] = '\0';
    char *token = (char *)buf;
    if (strncmp(token, "AUTH:", 5) == 0) token += 5;

    if (!token_verify(token)) {
        const char *deny = "{\"error\":\"Unauthorized\"}";
        ws_send_frame(c, WS_OP_TEXT, (const uint8_t *)deny, strlen(deny));
        db_log_event(srv, c->session_id, LOG_AUTH_FAIL, token);
        fprintf(stderr, "[auth] REJECTED %s\n", c->ip);
        return false;
    }

    db_log_event(srv, c->session_id, LOG_AUTH_OK, "authenticated");
    printf("[auth] ACCEPTED %s\n", c->ip);

    tv.tv_sec = 0; tv.tv_usec = 0;
    setsockopt(c->fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    const char *ok = "{\"status\":\"streaming\"}";
    ws_send_frame(c, WS_OP_TEXT, (const uint8_t *)ok, strlen(ok));
    return true;
}

void *client_thread(void *arg) {
    Client *c   = (Client *)arg;
    Server *srv = g_srv;

    c->session_id = db_open_session(srv, c->ip, c->port);
    db_log_event(srv, c->session_id, LOG_CONNECT, "TCP accepted");

    c->state = CLIENT_STATE_HANDSHAKE;
    if (!ws_handshake(c, srv)) goto cleanup;

    c->state = CLIENT_STATE_AUTH;
    if (!ws_authenticate(c, srv)) goto cleanup;

    c->state = CLIENT_STATE_STREAMING;
    uint64_t last_seq = 0;

    while (c->active) {
        pthread_mutex_lock(&srv->frame_lock);
        while (srv->frame_seq == last_seq && c->active) {
            struct timespec ts;
            clock_gettime(CLOCK_REALTIME, &ts);
            ts.tv_sec += 2;
            pthread_cond_timedwait(&srv->frame_ready, &srv->frame_lock, &ts);
        }
        if (!c->active) { pthread_mutex_unlock(&srv->frame_lock); break; }

        size_t  flen   = srv->frame_len;
        uint8_t *fdata = srv->current_frame;
        last_seq       = srv->frame_seq;
        pthread_mutex_unlock(&srv->frame_lock);

        if (ws_send_frame(c, WS_OP_BINARY, fdata, flen) < 0) {
            fprintf(stderr, "[stream] Send failed to %s\n", c->ip);
            break;
        }

        c->frames_sent++;
        if (c->frames_sent % 100 == 0) {
            char detail[64];
            snprintf(detail, sizeof(detail), "frames=%llu bytes=%llu",
                     (unsigned long long)c->frames_sent,
                     (unsigned long long)c->bytes_sent);
            db_log_event(srv, c->session_id, LOG_FRAME_TX, detail);
        }
    }

cleanup:
    c->state = CLIENT_STATE_CLOSING;
    { uint8_t cb[2] = {0x03, 0xE8}; ws_send_frame(c, WS_OP_CLOSE, cb, 2); }

    db_log_event(srv, c->session_id, LOG_DISCONNECT, "client disconnected");
    db_close_session(srv, c->session_id, c->frames_sent, c->bytes_sent);

    SSL_shutdown(c->ssl); SSL_free(c->ssl); close(c->fd);

    pthread_mutex_lock(&srv->clients_lock);
    c->state = CLIENT_STATE_DEAD; c->active = false;
    pthread_mutex_unlock(&srv->clients_lock);

    printf("[client] Done %s — %llu frames %llu bytes\n", c->ip,
           (unsigned long long)c->frames_sent, (unsigned long long)c->bytes_sent);
    return NULL;
}
HEREDOC

# ── src/screen_capture.c ──────────────────────────────────────────────────────
write_file "$PROJECT/src/screen_capture.c" << 'HEREDOC'
#include "rdv.h"
#include <sys/time.h>

size_t capture_frame(uint8_t *out, size_t max) {
    struct __attribute__((packed)) {
        uint8_t  magic[4];
        uint64_t timestamp_us;
        uint32_t width, height, data_len;
    } hdr;

    memcpy(hdr.magic, "RDVF", 4);
    struct timeval tv; gettimeofday(&tv, NULL);
    hdr.timestamp_us = (uint64_t)tv.tv_sec * 1000000ULL + tv.tv_usec;
    hdr.width = 1920; hdr.height = 1080;

    size_t payload_sz = 65536;
    if (sizeof(hdr) + payload_sz > max) return 0;
    hdr.data_len = (uint32_t)payload_sz;
    memcpy(out, &hdr, sizeof(hdr));
    RAND_bytes(out + sizeof(hdr), (int)payload_sz);
    return sizeof(hdr) + payload_sz;
}

void *capture_thread(void *arg) {
    Server *srv = (Server *)arg;
    printf("[capture] Started (%d FPS target)\n", RDV_FPS);
    struct timeval t0, t1;

    while (srv->running) {
        gettimeofday(&t0, NULL);
        uint8_t *inactive = (srv->current_frame == srv->frame_a)
                            ? srv->frame_b : srv->frame_a;

        size_t len = capture_frame(inactive, RDV_FRAME_BUF);
        if (!len) { usleep(RDV_FRAME_INTERVAL_US); continue; }

        pthread_mutex_lock(&srv->frame_lock);
        srv->current_frame = inactive;
        srv->frame_len     = len;
        srv->frame_seq++;
        pthread_cond_broadcast(&srv->frame_ready);
        pthread_mutex_unlock(&srv->frame_lock);

        gettimeofday(&t1, NULL);
        long elapsed = (t1.tv_sec-t0.tv_sec)*1000000L + (t1.tv_usec-t0.tv_usec);
        long sleep   = RDV_FRAME_INTERVAL_US - elapsed;
        if (sleep > 0) usleep((useconds_t)sleep);

        if (srv->frame_seq % 100 == 0)
            printf("[capture] Frame #%llu (%zu bytes)\n",
                   (unsigned long long)srv->frame_seq, len);
    }
    printf("[capture] Exiting\n");
    return NULL;
}
HEREDOC

# ── src/db_logger.c ───────────────────────────────────────────────────────────
write_file "$PROJECT/src/db_logger.c" << 'HEREDOC'
#include "rdv.h"

static const char *SCHEMA =
    "CREATE TABLE IF NOT EXISTS sessions ("
    "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
    "  client_ip TEXT NOT NULL, client_port INTEGER NOT NULL,"
    "  connected_at DATETIME DEFAULT CURRENT_TIMESTAMP,"
    "  disconnected_at DATETIME, frames_sent INTEGER DEFAULT 0,"
    "  bytes_sent INTEGER DEFAULT 0, state TEXT DEFAULT 'active');"
    "CREATE TABLE IF NOT EXISTS events ("
    "  id INTEGER PRIMARY KEY AUTOINCREMENT, session_id INTEGER,"
    "  event_type INTEGER NOT NULL, event_name TEXT, detail TEXT,"
    "  ts DATETIME DEFAULT CURRENT_TIMESTAMP,"
    "  FOREIGN KEY (session_id) REFERENCES sessions(id));"
    "CREATE INDEX IF NOT EXISTS idx_events_session ON events(session_id);"
    "PRAGMA journal_mode=WAL;"
    "PRAGMA synchronous=NORMAL;";

static const char *EVENT_NAMES[] = {
    "", "CONNECT","AUTH_OK","AUTH_FAIL","FRAME_TX","PARTIAL_SEND","DISCONNECT","ERROR"
};

bool db_init(Server *srv) {
    if (sqlite3_open(RDV_DB_PATH, &srv->db) != SQLITE_OK) {
        fprintf(stderr, "[db] Open failed: %s\n", sqlite3_errmsg(srv->db));
        return false;
    }
    char *err = NULL;
    if (sqlite3_exec(srv->db, SCHEMA, NULL, NULL, &err) != SQLITE_OK) {
        fprintf(stderr, "[db] Schema: %s\n", err); sqlite3_free(err); return false;
    }
    sqlite3_busy_timeout(srv->db, 5000);
    printf("[db] Ready: %s (WAL mode)\n", RDV_DB_PATH);
    return true;
}

int64_t db_open_session(Server *srv, const char *ip, uint16_t port) {
    if (!srv || !srv->db) return -1;
    pthread_mutex_lock(&srv->db_lock);
    sqlite3_stmt *stmt;
    sqlite3_prepare_v2(srv->db,
        "INSERT INTO sessions (client_ip,client_port) VALUES(?,?);", -1, &stmt, NULL);
    sqlite3_bind_text(stmt, 1, ip, -1, SQLITE_STATIC);
    sqlite3_bind_int (stmt, 2, port);
    int64_t id = -1;
    if (sqlite3_step(stmt) == SQLITE_DONE) id = sqlite3_last_insert_rowid(srv->db);
    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&srv->db_lock);
    printf("[db] Session #%lld opened for %s:%u\n", (long long)id, ip, port);
    return id;
}

void db_close_session(Server *srv, int64_t sid, uint64_t frames, uint64_t bytes) {
    if (!srv || !srv->db || sid < 0) return;
    pthread_mutex_lock(&srv->db_lock);
    sqlite3_stmt *stmt;
    sqlite3_prepare_v2(srv->db,
        "UPDATE sessions SET disconnected_at=CURRENT_TIMESTAMP,"
        "frames_sent=?,bytes_sent=?,state='closed' WHERE id=?;", -1, &stmt, NULL);
    sqlite3_bind_int64(stmt, 1, (sqlite3_int64)frames);
    sqlite3_bind_int64(stmt, 2, (sqlite3_int64)bytes);
    sqlite3_bind_int64(stmt, 3, sid);
    sqlite3_step(stmt); sqlite3_finalize(stmt);
    pthread_mutex_unlock(&srv->db_lock);
    printf("[db] Session #%lld closed\n", (long long)sid);
}

void db_log_event(Server *srv, int64_t sid, LogEvent ev, const char *detail) {
    const char *name = (ev >= LOG_CONNECT && ev <= LOG_ERROR) ? EVENT_NAMES[ev] : "UNKNOWN";
    if (!srv || !srv->db) {
        fprintf(stderr, "[syslog] %s session=%lld %s\n", name, (long long)sid, detail?detail:"");
        return;
    }
    pthread_mutex_lock(&srv->db_lock);
    sqlite3_stmt *stmt;
    sqlite3_prepare_v2(srv->db,
        "INSERT INTO events(session_id,event_type,event_name,detail) VALUES(?,?,?,?);",
        -1, &stmt, NULL);
    sqlite3_bind_int64(stmt, 1, sid);
    sqlite3_bind_int  (stmt, 2, (int)ev);
    sqlite3_bind_text (stmt, 3, name,   -1, SQLITE_STATIC);
    sqlite3_bind_text (stmt, 4, detail, -1, SQLITE_TRANSIENT);
    sqlite3_step(stmt); sqlite3_finalize(stmt);
    pthread_mutex_unlock(&srv->db_lock);
    printf("[syslog] [%s] session=%lld %s\n", name, (long long)sid, detail?detail:"");
}

void db_close(Server *srv) {
    if (srv->db) { sqlite3_close(srv->db); srv->db = NULL; printf("[db] Closed.\n"); }
}
HEREDOC

# ── src/crypto_utils.c ────────────────────────────────────────────────────────
write_file "$PROJECT/src/crypto_utils.c" << 'HEREDOC'
#include "rdv.h"
#include <openssl/bio.h>
#include <openssl/buffer.h>

SSL_CTX *tls_create_context(void) {
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) { ERR_print_errors_fp(stderr); return NULL; }

    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_options(ctx, SSL_OP_CIPHER_SERVER_PREFERENCE | SSL_OP_NO_RENEGOTIATION);

    if (SSL_CTX_use_certificate_file(ctx, RDV_CERT_FILE, SSL_FILETYPE_PEM) <= 0) {
        fprintf(stderr, "[tls] Cannot load cert %s\n"
                        "[tls] Run: openssl req -x509 -newkey rsa:4096 "
                        "-keyout server.key -out server.crt -days 365 -nodes -subj '/CN=localhost'\n",
                RDV_CERT_FILE);
        SSL_CTX_free(ctx); return NULL;
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, RDV_KEY_FILE, SSL_FILETYPE_PEM) <= 0 ||
        !SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr, "[tls] Key error\n"); SSL_CTX_free(ctx); return NULL;
    }
    printf("[tls] Context ready (min TLS 1.2)\n");
    return ctx;
}

static void base64_encode(const uint8_t *in, size_t in_len, char *out, size_t out_sz) {
    BIO *b64 = BIO_new(BIO_f_base64());
    BIO *mem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, mem);
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(b64, in, (int)in_len);
    BIO_flush(b64);
    BUF_MEM *bptr; BIO_get_mem_ptr(b64, &bptr);
    size_t n = bptr->length < out_sz-1 ? bptr->length : out_sz-1;
    memcpy(out, bptr->data, n); out[n] = '\0';
    BIO_free_all(b64);
}

void ws_compute_accept(const char *key, char *out64, size_t outsz) {
    char buf[256];
    snprintf(buf, sizeof(buf), "%s%s", key, RDV_WS_MAGIC);
    uint8_t sha1[SHA_DIGEST_LENGTH];
    SHA1((const unsigned char *)buf, strlen(buf), sha1);
    base64_encode(sha1, SHA_DIGEST_LENGTH, out64, outsz);
}

static const char VALID_TOKEN[] = "rdv-secret-2024";

bool token_verify(const char *token) {
    size_t tlen = strlen(token), vlen = strlen(VALID_TOKEN);
    if (tlen != vlen) return false;
    return CRYPTO_memcmp(token, VALID_TOKEN, vlen) == 0;
}
HEREDOC

# ── Makefile ──────────────────────────────────────────────────────────────────
write_file "$PROJECT/Makefile" << 'HEREDOC'
CC      = gcc
CFLAGS  = -Wall -Wextra -O2 -g -pthread -Iinclude
LDFLAGS = -lssl -lcrypto -lsqlite3 -lpthread

SRCS = src/main.c src/server_core.c src/client_handler.c \
       src/screen_capture.c src/db_logger.c src/crypto_utils.c

TARGET = rdv_server

all: $(TARGET)

$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)
	@echo "Build successful: ./$(TARGET)"

clean:
	rm -f $(TARGET) rdv_sessions.db

distclean: clean
	rm -f server.crt server.key

.PHONY: all clean distclean
HEREDOC

# =============================================================================
# STEP 3 — Check / install dependencies
# =============================================================================
echo -e "\n${BOLD}Step 3 — Checking dependencies${RESET}"

check_dep() {
    local pkg="$1" header="$2"
    if ! pkg-config --exists "$pkg" 2>/dev/null && [ ! -f "$header" ]; then
        warn "$pkg not found — attempting install..."
        if command -v apt-get &>/dev/null; then
            sudo apt-get install -y "lib${pkg}-dev" 2>/dev/null \
                || warn "Could not install $pkg automatically. Install manually."
        elif command -v dnf &>/dev/null; then
            sudo dnf install -y "openssl-devel sqlite-devel" 2>/dev/null
        elif command -v pacman &>/dev/null; then
            sudo pacman -S --noconfirm openssl sqlite 2>/dev/null
        else
            warn "Install $pkg manually, then re-run this script."
        fi
    else
        success "$pkg found"
    fi
}

check_dep openssl  /usr/include/openssl/ssl.h
check_dep sqlite3  /usr/include/sqlite3.h

if ! command -v gcc &>/dev/null; then
    die "gcc not found. Install build-essential / gcc and re-run."
fi
success "gcc $(gcc --version | head -1 | awk '{print $NF}')"

if ! command -v openssl &>/dev/null; then
    die "openssl binary not found."
fi
success "openssl $(openssl version | awk '{print $2}')"

# =============================================================================
# STEP 4 — Generate TLS certificate (if missing)
# =============================================================================
echo -e "\n${BOLD}Step 4 — TLS certificate${RESET}"

if [ -f "$PROJECT/server.crt" ] && [ -f "$PROJECT/server.key" ]; then
    success "Certificate already exists (server.crt / server.key)"
else
    info "Generating self-signed RSA-4096 certificate..."
    openssl req -x509 -newkey rsa:4096 \
        -keyout "$PROJECT/server.key" \
        -out    "$PROJECT/server.crt" \
        -days   365 -nodes \
        -subj   "/C=IN/ST=KA/L=Udupi/O=RDV-Assignment/CN=localhost" 2>/dev/null
    success "Certificate generated (valid 365 days)"
fi

# =============================================================================
# STEP 5 — Build
# =============================================================================
echo -e "\n${BOLD}Step 5 — Building${RESET}"

cd "$PROJECT"
if make -j"$(nproc)"; then
    success "Build complete → $PROJECT/rdv_server"
else
    die "Build failed. Check compiler errors above."
fi

# =============================================================================
# STEP 6 — Run (unless --build-only)
# =============================================================================
if $BUILD_ONLY; then
    echo -e "\n${GREEN}${BOLD}Done (--build-only). Run with:${RESET}"
    echo -e "  cd $PROJECT && ./rdv_server"
    exit 0
fi

echo -e "\n${BOLD}Step 6 — Launching server${RESET}"
echo -e "${YELLOW}──────────────────────────────────────────────────${RESET}"
echo -e "  WebSocket URL : ${CYAN}wss://localhost:8443/rdv${RESET}"
echo -e "  Auth token    : ${CYAN}rdv-secret-2024${RESET}"
echo -e "  Session DB    : ${CYAN}$PROJECT/rdv_sessions.db${RESET}"
echo -e "  Stop          : ${CYAN}Ctrl+C${RESET}"
echo -e "${YELLOW}──────────────────────────────────────────────────${RESET}\n"

cd "$PROJECT"
exec ./rdv_server