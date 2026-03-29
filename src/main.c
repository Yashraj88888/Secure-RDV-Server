/*=============================================================================
 * main.c — Entry point for the RDV server
 *============================================================================*/

#include "rdv.h"

int main(int argc, char *argv[]) {
    (void)argc; (void)argv;

    printf("╔══════════════════════════════════════════════════╗\n");
    printf("║   Remote Desktop Viewer — Secure WebSocket Server  ║\n");
    printf("║   Assignment: Network Programming (10 marks)       ║\n");
    printf("╚══════════════════════════════════════════════════╝\n\n");

    /* Initialise OpenSSL */
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    Server srv;
    if (server_init(&srv) < 0) {
        fprintf(stderr, "[main] Server initialisation failed\n");
        return EXIT_FAILURE;
    }

    printf("[main] Server ready. Connect with: wss://localhost:%d/rdv\n"
           "[main] Auth token: rdv-secret-2024\n"
           "[main] Press Ctrl+C to stop.\n\n", RDV_PORT);

    server_run(&srv);
    server_shutdown(&srv);

    EVP_cleanup();
    ERR_free_strings();

    return EXIT_SUCCESS;
}
