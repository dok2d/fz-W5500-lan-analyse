#pragma once

#include <stdint.h>
#include <stdbool.h>

/* W5500 socket for HTTP client (sockets 6-7 are unused by other tools) */
#define HTTP_CLIENT_SOCKET 6
#define HTTP_PORT          80

typedef struct {
    bool success;
    uint32_t bytes_received;
    char error_msg[48];
} HttpDownloadResult;

/**
 * Download a file via HTTP GET and save to SD card.
 *
 * @param dns_socket   W5500 socket for DNS resolve (e.g. W5500_DNS_SOCKET)
 * @param http_socket  W5500 socket for TCP transfer (e.g. HTTP_CLIENT_SOCKET)
 * @param dns_server   DNS server IP (from DHCP)
 * @param hostname     HTTP server hostname (e.g. "boot.ipxe.org")
 * @param path         URL path (e.g. "/undionly.kpxe")
 * @param save_path    Full SD card path to save file
 * @param buf          Caller-provided recv buffer (use app->frame_buf)
 * @param buf_size     Size of buf (e.g. 1024)
 * @param result       Output result
 * @param running      Pointer to volatile bool (set false to cancel)
 * @return true if file downloaded and saved successfully
 */
bool http_download_file(
    uint8_t dns_socket,
    uint8_t http_socket,
    const uint8_t dns_server[4],
    const char* hostname,
    const char* path,
    const char* save_path,
    uint8_t* buf,
    uint16_t buf_size,
    HttpDownloadResult* result,
    volatile bool* running);
