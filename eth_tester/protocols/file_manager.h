#pragma once

#include <stdint.h>
#include <stdbool.h>

/* W5500 socket assignments for HTTP file manager */
#define FILEMGR_HTTP_SOCKET   6   /* TCP listen socket on port 80 */
#define FILEMGR_HTTP_PORT     80

/* Buffer sizes */
#define FILEMGR_PATH_MAX      256
#define FILEMGR_CHUNK_SIZE    1024

/* File manager state */
typedef struct {
    volatile bool running;
    uint32_t requests_served;
    uint32_t bytes_sent;
    uint32_t bytes_received;
    uint32_t errors;
    char current_path[FILEMGR_PATH_MAX]; /* path being browsed */
} FileManagerState;

/**
 * Open HTTP socket and start listening.
 * Returns true on success.
 */
bool file_manager_start(FileManagerState* state);

/**
 * Single poll cycle of the HTTP file manager.
 * Call repeatedly from the worker thread.
 * buf: shared buffer (>= FILEMGR_CHUNK_SIZE bytes)
 * buf_size: buffer size
 */
void file_manager_poll(FileManagerState* state, uint8_t* buf, uint16_t buf_size);

/**
 * Close sockets and clean up.
 */
void file_manager_stop(FileManagerState* state);
