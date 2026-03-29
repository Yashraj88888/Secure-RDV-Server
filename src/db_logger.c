/*=============================================================================
 * db_logger.c — Text-based session and syslog event persistence
 *============================================================================*/

#include "rdv.h"
#include <time.h>

static const char *EVENT_NAMES[] = {
    [LOG_CONNECT]    = "CONNECT",
    [LOG_AUTH_OK]    = "AUTH_OK",
    [LOG_AUTH_FAIL]  = "AUTH_FAIL",
    [LOG_FRAME_TX]   = "FRAME_TX",
    [LOG_PARTIAL]    = "PARTIAL_SEND",
    [LOG_DISCONNECT] = "DISCONNECT",
    [LOG_ERROR]      = "ERROR"
};

static FILE *log_file = NULL;

bool db_init(Server *srv) {
    (void)srv;
    /* Use the same RDV_DB_PATH but it's now meant to be a .log file */
    log_file = fopen(RDV_DB_PATH, "a");
    if (!log_file) {
        fprintf(stderr, "[logger] Cannot open %s: ", RDV_DB_PATH);
        perror("");
        return false;
    }
    
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    fprintf(log_file, "\n--- [%04d-%02d-%02d %02d:%02d:%02d] Logger Initialized ---\n",
            t->tm_year + 1900, t->tm_mon + 1, t->tm_mday, t->tm_hour, t->tm_min, t->tm_sec);
    fflush(log_file);

    printf("[logger] Text logging initialized: %s\n", RDV_DB_PATH);
    return true;
}

int64_t db_open_session(Server *srv, const char *ip, uint16_t port) {
    if (!srv) return -1;
    
    pthread_mutex_lock(&srv->db_lock);
    
    static int64_t next_id = 1;
    int64_t session_id = next_id++;

    if (log_file) {
        time_t now = time(NULL);
        struct tm *t = localtime(&now);
        fprintf(log_file, "[%04d-%02d-%02d %02d:%02d:%02d] [SESSION START] Session ID: %lld | IP: %s:%u\n",
            t->tm_year + 1900, t->tm_mon + 1, t->tm_mday, t->tm_hour, t->tm_min, t->tm_sec,
            (long long)session_id, ip, port);
        fflush(log_file);
    }
    
    pthread_mutex_unlock(&srv->db_lock);

    printf("[logger] Session #%lld opened for %s:%u\n", (long long)session_id, ip, port);
    return session_id;
}

void db_close_session(Server *srv, int64_t session_id, uint64_t frames, uint64_t bytes) {
    if (!srv || session_id < 0) return;

    pthread_mutex_lock(&srv->db_lock);
    
    if (log_file) {
        time_t now = time(NULL);
        struct tm *t = localtime(&now);
        fprintf(log_file, "[%04d-%02d-%02d %02d:%02d:%02d] [SESSION END] Session ID: %lld | Frames: %llu | Bytes: %llu\n",
            t->tm_year + 1900, t->tm_mon + 1, t->tm_mday, t->tm_hour, t->tm_min, t->tm_sec,
            (long long)session_id, (unsigned long long)frames, (unsigned long long)bytes);
        fflush(log_file);
    }
    
    pthread_mutex_unlock(&srv->db_lock);

    printf("[logger] Session #%lld closed (frames=%llu, bytes=%llu)\n",
           (long long)session_id, (unsigned long long)frames, (unsigned long long)bytes);
}

void db_log_event(Server *srv, int64_t session_id, LogEvent ev, const char *detail) {
    const char *ev_name = (ev >= LOG_CONNECT && ev <= LOG_ERROR) ? EVENT_NAMES[ev] : "UNKNOWN";
    
    if (srv) pthread_mutex_lock(&srv->db_lock);
    
    if (log_file) {
        time_t now = time(NULL);
        struct tm *t = localtime(&now);
        fprintf(log_file, "[%04d-%02d-%02d %02d:%02d:%02d] [EVENT] Session %lld | %s | %s\n",
            t->tm_year + 1900, t->tm_mon + 1, t->tm_mday, t->tm_hour, t->tm_min, t->tm_sec,
            (long long)session_id, ev_name, detail ? detail : "");
        fflush(log_file);
    }
    
    if (srv) pthread_mutex_unlock(&srv->db_lock);

    /* Also echo to console for observability */
    printf("[syslog] [%s] session=%lld %s\n", ev_name, (long long)session_id, detail ? detail : "");
}

void db_close(Server *srv) {
    (void)srv;
    if (log_file) {
        time_t now = time(NULL);
        struct tm *t = localtime(&now);
        fprintf(log_file, "--- [%04d-%02d-%02d %02d:%02d:%02d] Logger Closed ---\n\n",
            t->tm_year + 1900, t->tm_mon + 1, t->tm_mday, t->tm_hour, t->tm_min, t->tm_sec);
        fclose(log_file);
        log_file = NULL;
        printf("[logger] Text Logger closed.\n");
    }
}
