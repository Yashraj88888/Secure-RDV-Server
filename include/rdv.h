#ifndef RDV_H
#define RDV_H

/*=============================================================================
 * rdv.h — Remote Desktop Viewer: Core Types & Declarations
 * 
 * Assignment: Secure Web-Based Remote Desktop Viewer
 * Language  : C (POSIX + Linux)
 * Authors   : Group of 4
 *============================================================================*/

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

/* Networking */
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sys/select.h>

/* Crypto (OpenSSL) */
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

/* SQLite */

/*─────────────────────────────── Constants ──────────────────────────────────*/

#define RDV_PORT            8443          /* TLS WebSocket port               */
#define RDV_MAX_CLIENTS     32            /* max simultaneous viewers         */
#define RDV_FRAME_BUF       (1 << 20)    /* 1 MB per frame buffer            */
#define RDV_SNDBUF_SIZE     (256 * 1024) /* SO_SNDBUF tuning                 */
#define RDV_RCVBUF_SIZE     (64  * 1024) /* SO_RCVBUF tuning                 */
#define RDV_FPS             15           /* target frames per second          */
#define RDV_FRAME_INTERVAL_US (1000000 / RDV_FPS)
#define RDV_TOKEN_LEN       32           /* auth token bytes                  */
#define RDV_DB_PATH         "rdv_sessions.log"
#define RDV_CERT_FILE       "server.crt"
#define RDV_KEY_FILE        "server.key"
#define RDV_WS_MAGIC        "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

/* WebSocket opcodes */
#define WS_OP_CONTINUATION  0x0
#define WS_OP_TEXT          0x1
#define WS_OP_BINARY        0x2
#define WS_OP_CLOSE         0x8
#define WS_OP_PING          0x9
#define WS_OP_PONG          0xA

/* Client state machine */
typedef enum {
    CLIENT_STATE_HANDSHAKE = 0,  /* TCP connected, awaiting HTTP upgrade      */
    CLIENT_STATE_AUTH,           /* WebSocket open, awaiting auth token        */
    CLIENT_STATE_STREAMING,      /* authenticated, receiving frames            */
    CLIENT_STATE_CLOSING,        /* close frame sent, draining                 */
    CLIENT_STATE_DEAD            /* connection closed, slot reusable           */
} ClientState;

/* Log event types stored in DB */
typedef enum {
    LOG_CONNECT   = 1,
    LOG_AUTH_OK   = 2,
    LOG_AUTH_FAIL = 3,
    LOG_FRAME_TX  = 4,
    LOG_PARTIAL   = 5,           /* partial send detected                      */
    LOG_DISCONNECT= 6,
    LOG_ERROR     = 7
} LogEvent;

/*──────────────────────────── Data Structures ───────────────────────────────*/

/* One connected client */
typedef struct {
    int            fd;                   /* raw TCP socket fd                  */
    SSL           *ssl;                  /* TLS context over fd                */
    ClientState    state;
    char           ip[INET_ADDRSTRLEN];
    uint16_t       port;
    int64_t        session_id;           /* DB row id of this session          */
    pthread_t      thread;
    pthread_mutex_t send_lock;           /* serialises SSL_write calls         */
    volatile bool  active;
    uint64_t       frames_sent;
    uint64_t       bytes_sent;
    time_t         connected_at;
} Client;

/* Shared server state */
typedef struct {
    int            listen_fd;
    SSL_CTX       *ssl_ctx;
    pthread_mutex_t db_lock;            /* serialises all DB writes            */
    pthread_mutex_t clients_lock;       /* guards clients[]                    */
    Client         clients[RDV_MAX_CLIENTS];
    volatile bool  running;

    /* Latest screen frame (double-buffered) */
    uint8_t        frame_a[RDV_FRAME_BUF];
    uint8_t        frame_b[RDV_FRAME_BUF];
    size_t         frame_len;
    uint8_t       *current_frame;       /* points to whichever buffer is live  */
    pthread_mutex_t frame_lock;
    pthread_cond_t  frame_ready;        /* broadcast when new frame captured   */
    uint64_t        frame_seq;          /* monotonically increasing            */
} Server;

/*──────────────────────────── WebSocket Frame ───────────────────────────────*/

typedef struct {
    uint8_t  opcode;
    bool     fin;
    bool     masked;
    uint64_t payload_len;
    uint8_t  mask_key[4];
    uint8_t *payload;                   /* points into recv buffer             */
} WsFrame;

/*──────────────────────────── Function Prototypes ───────────────────────────*/

/* server_core.c */
int  server_init(Server *srv);
void server_run(Server *srv);
void server_shutdown(Server *srv);

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
bool  db_init(Server *srv);
int64_t db_open_session(Server *srv, const char *ip, uint16_t port);
void  db_close_session(Server *srv, int64_t session_id, uint64_t frames, uint64_t bytes);
void  db_log_event(Server *srv, int64_t session_id, LogEvent ev, const char *detail);
void  db_close(Server *srv);

/* crypto_utils.c */
SSL_CTX *tls_create_context(void);
void     ws_compute_accept(const char *key, char *out64, size_t outsz);
bool     token_verify(const char *token);

/* socket_opts.c */
void apply_socket_options(int fd);

#endif /* RDV_H */
