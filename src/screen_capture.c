/*=============================================================================
 * screen_capture.c — Screen capture thread with double-buffer frame swap
 *
 * KEY CONCEPTS:
 *  • Double buffering: capture thread writes to the INACTIVE buffer while
 *    client threads read from the ACTIVE buffer → no reader/writer conflict
 *  • pthread_cond_broadcast: wakes ALL waiting client threads simultaneously
 *    when a new frame is ready
 *  • Frame pacing: usleep() limits capture to RDV_FPS to avoid flooding
 *  • On Linux with X11: uses XGetImage; here we simulate with /dev/urandom
 *    so the code compiles without X11 headers in a headless environment
 *============================================================================*/

#include "rdv.h"
#include <sys/time.h>

/*──────────────────────────────────────────────────────────────────────────────
 * capture_frame()
 *
 * In a real deployment this would call:
 *   XImage *img = XGetImage(display, root, 0, 0, width, height, AllPlanes, ZPixmap);
 *   memcpy(out, img->data, img->bytes_per_line * img->height);
 *
 * Here we produce a valid PNG-like header + noise to simulate a frame.
 * The WebSocket binary frame structure and transmission path are identical.
 *─────────────────────────────────────────────────────────────────────────────*/
size_t capture_frame(uint8_t *out, size_t max) {
    /*
     * Simulated frame: 1920×1080 RGBA = 8,294,400 bytes raw.
     * We compress to ~60-120 KB here by writing a small synthetic payload.
     * In production: JPEG encode via libjpeg or H.264 via libx264.
     */

    /* Frame header: magic + timestamp + resolution */
    struct {
        uint8_t  magic[4];       /* "RDVF" */
        uint64_t timestamp_us;
        uint32_t width;
        uint32_t height;
        uint32_t data_len;
    } __attribute__((packed)) hdr;

    memcpy(hdr.magic, "RDVF", 4);

    struct timeval tv;
    gettimeofday(&tv, NULL);
    hdr.timestamp_us = (uint64_t)tv.tv_sec * 1000000ULL + tv.tv_usec;
    hdr.width  = 1920;
    hdr.height = 1080;

    /* Simulated compressed payload: 64 KB of pseudo-random data */
    size_t payload_sz = 65536;
    if (sizeof(hdr) + payload_sz > max) return 0;

    hdr.data_len = (uint32_t)payload_sz;
    memcpy(out, &hdr, sizeof(hdr));

    /* Fill with pseudo-random bytes (simulates compressed video data) */
    RAND_bytes(out + sizeof(hdr), (int)payload_sz);

    return sizeof(hdr) + payload_sz;
}

/*──────────────────────────────────────────────────────────────────────────────
 * capture_thread()
 *
 * DOUBLE-BUFFER SWAP PROTOCOL:
 *   1. Determine which buffer is NOT current (inactive buffer)
 *   2. Capture new frame INTO inactive buffer
 *   3. Lock frame_lock
 *   4. Swap current_frame pointer
 *   5. Update frame_len and frame_seq
 *   6. pthread_cond_broadcast → wake all client threads
 *   7. Unlock frame_lock
 *
 * This means client threads always read from a STABLE buffer that the
 * capture thread is not writing to.  Lock is held only for the pointer
 * swap (nanoseconds), not during the actual capture (milliseconds).
 *─────────────────────────────────────────────────────────────────────────────*/
void *capture_thread(void *arg) {
    Server *srv = (Server *)arg;

    printf("[capture] Frame capture thread started (%d FPS target)\n", RDV_FPS);

    struct timeval t_start, t_end;

    while (srv->running) {
        gettimeofday(&t_start, NULL);

        /* Determine INACTIVE buffer (the one we can safely write into) */
        uint8_t *inactive = (srv->current_frame == srv->frame_a)
                            ? srv->frame_b
                            : srv->frame_a;

        /* ── Capture into inactive buffer (NO lock held) ─────────────── */
        size_t len = capture_frame(inactive, RDV_FRAME_BUF);
        if (len == 0) {
            fprintf(stderr, "[capture] Frame capture failed\n");
            usleep(RDV_FRAME_INTERVAL_US);
            continue;
        }

        /* ── Atomic swap ─────────────────────────────────────────────── */
        pthread_mutex_lock(&srv->frame_lock);
        srv->current_frame = inactive;
        srv->frame_len     = len;
        srv->frame_seq++;
        pthread_cond_broadcast(&srv->frame_ready);  /* wake ALL clients */
        pthread_mutex_unlock(&srv->frame_lock);

        /* ── Frame pacing ────────────────────────────────────────────── */
        gettimeofday(&t_end, NULL);
        long elapsed_us = (t_end.tv_sec  - t_start.tv_sec)  * 1000000L
                        + (t_end.tv_usec - t_start.tv_usec);
        long sleep_us   = RDV_FRAME_INTERVAL_US - elapsed_us;
        if (sleep_us > 0) usleep((useconds_t)sleep_us);

        if (srv->frame_seq % 100 == 0) {
            printf("[capture] Frame #%llu captured (%zu bytes)\n",
                   (unsigned long long)srv->frame_seq, len);
        }
    }

    printf("[capture] Capture thread exiting\n");
    return NULL;
}
