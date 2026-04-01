#include "file_manager.h"

#include <furi.h>
#include <storage/storage.h>
#include <socket.h>
#include <wizchip_conf.h>
#include <w5500.h>

#include <string.h>
#include <stdio.h>

#define TAG "FILEMGR"

/* Max single file/folder name */
#define FM_NAME_MAX 64

/* Simple memmem implementation */
static void* filemgr_memmem(
    const void* haystack,
    size_t hlen,
    const void* needle,
    size_t nlen) {
    if(nlen == 0) return (void*)haystack;
    if(hlen < nlen) return NULL;
    const uint8_t* h = haystack;
    for(size_t i = 0; i <= hlen - nlen; i++) {
        if(memcmp(h + i, needle, nlen) == 0) return (void*)(h + i);
    }
    return NULL;
}

/* ==================== URL decoding ==================== */

static int hex_digit(char c) {
    if(c >= '0' && c <= '9') return c - '0';
    if(c >= 'a' && c <= 'f') return c - 'a' + 10;
    if(c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static void url_decode(char* dst, const char* src, size_t dst_size) {
    size_t di = 0;
    for(size_t i = 0; src[i] && di < dst_size - 1; i++) {
        if(src[i] == '%' && src[i + 1] && src[i + 2]) {
            int h = hex_digit(src[i + 1]);
            int l = hex_digit(src[i + 2]);
            if(h >= 0 && l >= 0) {
                dst[di++] = (char)((h << 4) | l);
                i += 2;
                continue;
            }
        } else if(src[i] == '+') {
            dst[di++] = ' ';
            continue;
        }
        dst[di++] = src[i];
    }
    dst[di] = '\0';
}

/* ==================== Reliable TCP send ==================== */

/*
 * Wait until WIZnet finishes transmitting the previous send.
 * The W5500 send() sets sock_is_sending; the next send() returns
 * SOCK_BUSY until SEND_OK interrupt fires. We poll the interrupt
 * register directly to wait.
 */
static bool http_wait_send_done(uint8_t sn) {
    uint32_t start = furi_get_tick();
    while(furi_get_tick() - start < 3000) {
        uint8_t ir = getSn_IR(sn);
        if(ir & Sn_IR_SENDOK) {
            setSn_IR(sn, Sn_IR_SENDOK);
            return true;
        }
        if(ir & Sn_IR_TIMEOUT) {
            setSn_IR(sn, Sn_IR_TIMEOUT);
            return false;
        }
        uint8_t sr = getSn_SR(sn);
        if(sr != SOCK_ESTABLISHED && sr != SOCK_CLOSE_WAIT) {
            return false;
        }
        furi_delay_ms(1);
    }
    return false;
}

/*
 * Send data reliably over TCP. Handles:
 * - Waiting for previous send to complete (SEND_OK)
 * - Splitting data into TX-buffer-sized chunks
 * - Proper error handling
 */
static bool http_send_buf(uint8_t sn, const uint8_t* data, uint16_t len) {
    uint16_t sent_total = 0;
    while(sent_total < len) {
        uint16_t to_send = len - sent_total;
        int32_t ret = send(sn, (uint8_t*)(data + sent_total), to_send);
        if(ret > 0) {
            sent_total += (uint16_t)ret;
            /* Wait for this chunk to be fully transmitted before sending more */
            if(sent_total < len) {
                if(!http_wait_send_done(sn)) return false;
            }
        } else if(ret == SOCK_BUSY) {
            /* Previous send still in flight — wait for it */
            if(!http_wait_send_done(sn)) return false;
        } else {
            /* Hard error */
            FURI_LOG_E(TAG, "send error: %ld", (long)ret);
            return false;
        }
    }
    return true;
}

static bool http_send_str(uint8_t sn, const char* str) {
    uint16_t len = strlen(str);
    if(len == 0) return true;
    return http_send_buf(sn, (const uint8_t*)str, len);
}

/*
 * Send a FuriString in chunks. For large responses built with furi_string.
 */
static bool http_send_fstr(uint8_t sn, FuriString* fstr) {
    const char* data = furi_string_get_cstr(fstr);
    size_t total = furi_string_size(fstr);
    size_t sent = 0;
    while(sent < total) {
        uint16_t chunk = (total - sent > 1024) ? 1024 : (uint16_t)(total - sent);
        if(!http_send_buf(sn, (const uint8_t*)(data + sent), chunk)) return false;
        sent += chunk;
    }
    return true;
}

/*
 * Wait for the last send to complete before closing connection.
 * Without this, disconnect() can cut off in-flight data.
 */
static void http_flush(uint8_t sn) {
    http_wait_send_done(sn);
}

/* ==================== HTML generation ==================== */

static const char css[] =
    "<style>"
    "body{font-family:monospace;background:#1a1a2e;color:#e0e0e0;margin:0;padding:16px}"
    "h1{color:#ff8c00;font-size:18px;margin:0 0 4px}"
    ".p{color:#888;font-size:13px;margin-bottom:12px;word-break:break-all}"
    "table{width:100%;border-collapse:collapse}"
    "th{text-align:left;padding:6px 8px;border-bottom:2px solid #ff8c00;color:#ff8c00;font-size:13px}"
    "td{padding:5px 8px;border-bottom:1px solid #333;font-size:13px}"
    "tr:hover{background:#2a2a4a}"
    "a{color:#5dade2;text-decoration:none}a:hover{text-decoration:underline}"
    ".d{color:#ff8c00;font-weight:bold}"
    ".s{color:#888;text-align:right}"
    ".a{white-space:nowrap}"
    ".a a{margin-left:8px;color:#e74c3c;font-size:12px}"
    ".b{display:inline-block;padding:6px 14px;background:#ff8c00;color:#1a1a2e;"
    "border:none;cursor:pointer;font-family:monospace;font-size:13px;font-weight:bold;"
    "text-decoration:none;margin:2px}"
    ".b:hover{background:#ffa500}"
    ".bs{padding:3px 8px;font-size:11px}"
    ".uf{margin:12px 0;padding:10px;background:#2a2a4a;border:1px solid #444}"
    ".mf{margin:8px 0}"
    "input[type=text]{background:#1a1a2e;color:#e0e0e0;border:1px solid #555;"
    "padding:4px 8px;font-family:monospace;font-size:13px}"
    "input[type=file]{color:#e0e0e0;font-size:12px}"
    ".ft{margin-top:16px;color:#555;font-size:11px}"
    "</style>";

/* Format file size human-readable */
static void format_size(uint64_t size, char* buf, size_t buf_size) {
    if(size < 1024) {
        snprintf(buf, buf_size, "%lu B", (unsigned long)size);
    } else if(size < 1024 * 1024) {
        snprintf(
            buf,
            buf_size,
            "%lu.%lu KB",
            (unsigned long)(size / 1024),
            (unsigned long)((size % 1024) * 10 / 1024));
    } else {
        snprintf(
            buf,
            buf_size,
            "%lu.%lu MB",
            (unsigned long)(size / (1024 * 1024)),
            (unsigned long)((size % (1024 * 1024)) * 10 / (1024 * 1024)));
    }
}

/* Build parent path from current path */
static void get_parent_path(const char* path, char* parent, size_t parent_size) {
    strncpy(parent, path, parent_size);
    parent[parent_size - 1] = '\0';
    size_t len = strlen(parent);
    if(len > 1 && parent[len - 1] == '/') {
        parent[len - 1] = '\0';
        len--;
    }
    char* last_slash = strrchr(parent, '/');
    if(last_slash && last_slash != parent) {
        *last_slash = '\0';
    } else {
        strncpy(parent, "/", parent_size);
    }
}

/* ==================== HTTP request handling ==================== */

/*
 * Build the entire directory listing page into a FuriString,
 * then send it in one go. This avoids dozens of tiny send() calls.
 */
static void handle_list_dir(uint8_t sn, const char* sd_path, const char* web_path) {
    Storage* storage = furi_record_open(RECORD_STORAGE);
    FuriString* page = furi_string_alloc();

    /* HTML start */
    furi_string_cat(page, "<!DOCTYPE html><html><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<title>Flipper File Manager</title>");
    furi_string_cat(page, css);
    furi_string_cat(page, "</head><body>");

    /* Title and path */
    furi_string_cat(page, "<h1>Flipper File Manager</h1><div class='p'>");
    furi_string_cat(page, web_path);
    furi_string_cat(page, "</div>");

    /* Parent link */
    if(strcmp(web_path, "/") != 0) {
        char parent[FILEMGR_PATH_MAX];
        get_parent_path(web_path, parent, sizeof(parent));
        furi_string_cat(page, "<a href='/browse");
        furi_string_cat(page, parent);
        furi_string_cat(page, "' class='b bs'>Up</a> ");
    }

    /* Upload form */
    furi_string_cat(page, "<div class='uf'>"
        "<form method='POST' action='/upload");
    furi_string_cat(page, web_path);
    furi_string_cat(page, "' enctype='multipart/form-data'>"
        "<input type='file' name='file'> "
        "<button type='submit' class='b bs'>Upload</button>"
        "</form></div>");

    /* Mkdir form */
    furi_string_cat(page, "<div class='mf'>"
        "<form method='POST' action='/mkdir");
    furi_string_cat(page, web_path);
    furi_string_cat(page, "'>"
        "<input type='text' name='name' placeholder='New folder' size='16'> "
        "<button type='submit' class='b bs'>Create</button>"
        "</form></div>");

    /* Table */
    furi_string_cat(page, "<table><tr><th>Name</th><th>Size</th><th></th></tr>");

    /* Directory entries */
    File* dir = storage_file_alloc(storage);
    if(storage_dir_open(dir, sd_path)) {
        FileInfo info;
        char name[FM_NAME_MAX];
        while(storage_dir_read(dir, &info, name, sizeof(name))) {
            bool is_dir = (info.flags & FSF_DIRECTORY);

            if(is_dir) {
                furi_string_cat(page, "<tr><td><a href='/browse");
                if(strcmp(web_path, "/") != 0) furi_string_cat(page, web_path);
                furi_string_cat(page, "/");
                furi_string_cat(page, name);
                furi_string_cat(page, "' class='d'>");
                furi_string_cat(page, name);
                furi_string_cat(page, "/</a></td><td class='s'>-</td><td class='a'>"
                    "<a href='/delete");
                if(strcmp(web_path, "/") != 0) furi_string_cat(page, web_path);
                furi_string_cat(page, "/");
                furi_string_cat(page, name);
                furi_string_cat(page, "' onclick=\"return confirm('Delete?')\">"
                    "Del</a></td></tr>");
            } else {
                char size_str[32];
                format_size(info.size, size_str, sizeof(size_str));
                furi_string_cat(page, "<tr><td>");
                furi_string_cat(page, name);
                furi_string_cat(page, "</td><td class='s'>");
                furi_string_cat(page, size_str);
                furi_string_cat(page, "</td><td class='a'>"
                    "<a href='/download");
                if(strcmp(web_path, "/") != 0) furi_string_cat(page, web_path);
                furi_string_cat(page, "/");
                furi_string_cat(page, name);
                furi_string_cat(page, "' class='b bs'>DL</a>"
                    "<a href='/delete");
                if(strcmp(web_path, "/") != 0) furi_string_cat(page, web_path);
                furi_string_cat(page, "/");
                furi_string_cat(page, name);
                furi_string_cat(page, "' onclick=\"return confirm('Delete?')\">"
                    "Del</a></td></tr>");
            }
        }
        storage_dir_close(dir);
    } else {
        furi_string_cat(page, "<tr><td colspan='3'>Failed to open directory</td></tr>");
    }
    storage_file_free(dir);
    furi_record_close(RECORD_STORAGE);

    furi_string_cat(page, "</table>"
        "<div class='ft'>Flipper Zero W5500 File Manager</div>"
        "</body></html>");

    /* Now send the complete page: HTTP headers + body */
    size_t body_len = furi_string_size(page);
    char hdr[128];
    snprintf(
        hdr,
        sizeof(hdr),
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/html;charset=utf-8\r\n"
        "Content-Length: %lu\r\n"
        "Connection: close\r\n\r\n",
        (unsigned long)body_len);

    http_send_str(sn, hdr);
    http_send_fstr(sn, page);
    http_flush(sn);

    furi_string_free(page);
}

/* Send file download */
static void handle_download(
    uint8_t sn,
    const char* sd_path,
    const char* filename,
    uint8_t* buf,
    uint16_t buf_size,
    FileManagerState* state) {
    Storage* storage = furi_record_open(RECORD_STORAGE);
    File* file = storage_file_alloc(storage);

    if(!storage_file_open(file, sd_path, FSAM_READ, FSOM_OPEN_EXISTING)) {
        http_send_str(sn, "HTTP/1.1 404 Not Found\r\nConnection: close\r\n"
            "Content-Length: 14\r\n\r\n404 Not Found\n");
        http_flush(sn);
        storage_file_free(file);
        furi_record_close(RECORD_STORAGE);
        return;
    }

    uint64_t file_size = storage_file_size(file);

    /* Send response headers */
    char hdr[192];
    snprintf(
        hdr,
        sizeof(hdr),
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: application/octet-stream\r\n"
        "Content-Disposition: attachment; filename=\"%.48s\"\r\n"
        "Content-Length: %lu\r\n"
        "Connection: close\r\n\r\n",
        filename,
        (unsigned long)file_size);
    http_send_str(sn, hdr);

    /* Stream file in chunks */
    while(!storage_file_eof(file) && state->running) {
        uint16_t chunk = buf_size;
        if(chunk > FILEMGR_CHUNK_SIZE) chunk = FILEMGR_CHUNK_SIZE;
        uint16_t read = storage_file_read(file, buf, chunk);
        if(read == 0) break;
        if(!http_send_buf(sn, buf, read)) {
            state->errors++;
            break;
        }
        state->bytes_sent += read;
    }

    http_flush(sn);
    storage_file_close(file);
    storage_file_free(file);
    furi_record_close(RECORD_STORAGE);
}

/* Handle file upload (multipart/form-data) */
static void handle_upload(
    uint8_t sn,
    const char* sd_dir_path,
    const char* web_dir_path,
    uint8_t* buf,
    uint16_t buf_size,
    FileManagerState* state) {
    int32_t total_read = 0;
    int32_t body_len = 0;

    uint16_t chunk = buf_size;
    if(chunk > FILEMGR_CHUNK_SIZE) chunk = FILEMGR_CHUNK_SIZE;

    uint32_t start = furi_get_tick();
    while(furi_get_tick() - start < 5000 && state->running) {
        int32_t len = recv(sn, buf + total_read, chunk - total_read);
        if(len > 0) {
            total_read += len;
            if(total_read >= (int32_t)chunk) break;
            start = furi_get_tick();
        } else {
            furi_delay_ms(10);
        }
        if(total_read > 4) {
            const char* end = filemgr_memmem(buf, total_read, "\r\n--", 4);
            if(end && end > (char*)buf + 100) {
                body_len = total_read;
                break;
            }
        }
    }

    if(total_read <= 0) {
        http_send_str(sn, "HTTP/1.1 400 Bad Request\r\nConnection: close\r\n"
            "Content-Length: 8\r\n\r\nNo data\n");
        http_flush(sn);
        return;
    }

    body_len = total_read;

    char* boundary_start = (char*)buf;
    char* boundary_end = strstr(boundary_start, "\r\n");
    if(!boundary_end) {
        http_send_str(sn, "HTTP/1.1 400 Bad Request\r\nConnection: close\r\n"
            "Content-Length: 12\r\n\r\nBad request\n");
        http_flush(sn);
        return;
    }

    size_t boundary_len = boundary_end - boundary_start;

    char* fn_ptr = strstr((char*)buf, "filename=\"");
    if(!fn_ptr) {
        http_send_str(sn, "HTTP/1.1 400 Bad Request\r\nConnection: close\r\n"
            "Content-Length: 12\r\n\r\nNo filename\n");
        http_flush(sn);
        return;
    }
    fn_ptr += 10;
    char* fn_end = strchr(fn_ptr, '"');
    if(!fn_end || fn_end == fn_ptr) {
        http_send_str(sn, "HTTP/1.1 400 Bad Request\r\nConnection: close\r\n"
            "Content-Length: 12\r\n\r\nNo filename\n");
        http_flush(sn);
        return;
    }

    char filename[FM_NAME_MAX];
    size_t fn_len = fn_end - fn_ptr;
    if(fn_len >= sizeof(filename)) fn_len = sizeof(filename) - 1;
    memcpy(filename, fn_ptr, fn_len);
    filename[fn_len] = '\0';

    char* data_start = strstr(fn_end, "\r\n\r\n");
    if(!data_start) {
        http_send_str(sn, "HTTP/1.1 400 Bad Request\r\nConnection: close\r\n"
            "Content-Length: 12\r\n\r\nBad request\n");
        http_flush(sn);
        return;
    }
    data_start += 4;

    char* data_end = NULL;
    for(char* p = data_start; p < (char*)buf + body_len - (int)boundary_len; p++) {
        if(p[0] == '\r' && p[1] == '\n' &&
           memcmp(p + 2, boundary_start, boundary_len) == 0) {
            data_end = p;
            break;
        }
    }
    if(!data_end) {
        data_end = (char*)buf + body_len;
    }

    size_t data_len = data_end - data_start;

    /* Build file path safely */
    char filepath[FILEMGR_PATH_MAX];
    size_t dir_len = strlen(sd_dir_path);
    size_t name_len = strlen(filename);
    if(dir_len + 1 + name_len >= sizeof(filepath)) {
        http_send_str(sn, "HTTP/1.1 400 Bad Request\r\nConnection: close\r\n"
            "Content-Length: 14\r\n\r\nPath too long\n");
        http_flush(sn);
        return;
    }
    memcpy(filepath, sd_dir_path, dir_len);
    filepath[dir_len] = '/';
    memcpy(filepath + dir_len + 1, filename, name_len + 1);

    Storage* storage = furi_record_open(RECORD_STORAGE);
    File* file = storage_file_alloc(storage);

    if(storage_file_open(file, filepath, FSAM_WRITE, FSOM_CREATE_ALWAYS)) {
        size_t written = storage_file_write(file, data_start, data_len);
        storage_file_close(file);
        state->bytes_received += written;
        FURI_LOG_I(TAG, "Uploaded: %s (%u bytes)", filename, (unsigned)written);

        /* Redirect back */
        FuriString* loc = furi_string_alloc_printf("/browse%s", web_dir_path);
        http_send_str(sn, "HTTP/1.1 303 See Other\r\nConnection: close\r\n"
            "Content-Length: 0\r\nLocation: ");
        http_send_str(sn, furi_string_get_cstr(loc));
        http_send_str(sn, "\r\n\r\n");
        http_flush(sn);
        furi_string_free(loc);
    } else {
        http_send_str(sn, "HTTP/1.1 500 Error\r\nConnection: close\r\n"
            "Content-Length: 12\r\n\r\nWrite error\n");
        http_flush(sn);
        state->errors++;
    }

    storage_file_free(file);
    furi_record_close(RECORD_STORAGE);
}

/* Handle mkdir */
static void handle_mkdir(
    uint8_t sn,
    const char* sd_dir_path,
    const char* web_dir_path,
    uint8_t* buf,
    uint16_t buf_size) {
    int32_t total_read = 0;
    uint16_t chunk = buf_size;
    if(chunk > 512) chunk = 512;

    uint32_t start = furi_get_tick();
    while(furi_get_tick() - start < 3000) {
        int32_t len = recv(sn, buf + total_read, chunk - total_read);
        if(len > 0) {
            total_read += len;
            if(total_read >= (int32_t)chunk) break;
            if(total_read > 5) break;
            start = furi_get_tick();
        } else {
            furi_delay_ms(10);
        }
    }

    char folder_name[FM_NAME_MAX] = {0};

    if(total_read > 0) {
        buf[total_read] = '\0';
        char* name_ptr = strstr((char*)buf, "name=");
        if(name_ptr) {
            name_ptr += 5;
            char* amp = strchr(name_ptr, '&');
            if(amp) *amp = '\0';
            url_decode(folder_name, name_ptr, sizeof(folder_name));
        }
    }

    if(strlen(folder_name) > 0) {
        char dirpath[FILEMGR_PATH_MAX];
        size_t dir_len = strlen(sd_dir_path);
        size_t name_len = strlen(folder_name);
        if(dir_len + 1 + name_len < sizeof(dirpath)) {
            memcpy(dirpath, sd_dir_path, dir_len);
            dirpath[dir_len] = '/';
            memcpy(dirpath + dir_len + 1, folder_name, name_len + 1);

            Storage* storage = furi_record_open(RECORD_STORAGE);
            storage_simply_mkdir(storage, dirpath);
            furi_record_close(RECORD_STORAGE);
            FURI_LOG_I(TAG, "Created dir: %s", dirpath);
        }
    }

    /* Redirect */
    FuriString* loc = furi_string_alloc_printf("/browse%s", web_dir_path);
    http_send_str(sn, "HTTP/1.1 303 See Other\r\nConnection: close\r\n"
        "Content-Length: 0\r\nLocation: ");
    http_send_str(sn, furi_string_get_cstr(loc));
    http_send_str(sn, "\r\n\r\n");
    http_flush(sn);
    furi_string_free(loc);
}

/* Handle delete */
static void handle_delete(uint8_t sn, const char* sd_path, const char* web_parent_path) {
    Storage* storage = furi_record_open(RECORD_STORAGE);
    storage_simply_remove(storage, sd_path);
    furi_record_close(RECORD_STORAGE);
    FURI_LOG_I(TAG, "Deleted: %s", sd_path);

    FuriString* loc = furi_string_alloc_printf("/browse%s", web_parent_path);
    http_send_str(sn, "HTTP/1.1 303 See Other\r\nConnection: close\r\n"
        "Content-Length: 0\r\nLocation: ");
    http_send_str(sn, furi_string_get_cstr(loc));
    http_send_str(sn, "\r\n\r\n");
    http_flush(sn);
    furi_string_free(loc);
}

/* ==================== Main request router ==================== */

static void web_to_sd_path(const char* web_path, char* sd_path, size_t sd_size) {
    if(web_path[0] == '\0' || strcmp(web_path, "/") == 0) {
        strncpy(sd_path, "/ext", sd_size);
    } else {
        snprintf(sd_path, sd_size, "/ext%s", web_path);
    }
    sd_path[sd_size - 1] = '\0';
}

static const char* path_filename(const char* path) {
    const char* last = strrchr(path, '/');
    return last ? last + 1 : path;
}

static void handle_request(
    uint8_t sn,
    const char* method,
    const char* raw_uri,
    uint8_t* buf,
    uint16_t buf_size,
    FileManagerState* state) {
    char uri[FILEMGR_PATH_MAX];
    url_decode(uri, raw_uri, sizeof(uri));

    char sd_path[FILEMGR_PATH_MAX];
    char web_path[FILEMGR_PATH_MAX];

    state->requests_served++;

    if(strcmp(uri, "/") == 0 || strcmp(uri, "") == 0) {
        http_send_str(sn, "HTTP/1.1 303 See Other\r\nConnection: close\r\n"
            "Content-Length: 0\r\nLocation: /browse/\r\n\r\n");
        http_flush(sn);
        return;
    }

    if(strncmp(uri, "/browse", 7) == 0) {
        const char* path = uri + 7;
        if(path[0] == '\0') path = "/";
        strncpy(web_path, path, sizeof(web_path));
        web_path[sizeof(web_path) - 1] = '\0';
        web_to_sd_path(web_path, sd_path, sizeof(sd_path));

        /* Check if directory can be opened (storage_dir_exists unreliable for /ext) */
        Storage* storage = furi_record_open(RECORD_STORAGE);
        File* dir_check = storage_file_alloc(storage);
        bool is_dir = storage_dir_open(dir_check, sd_path);
        if(is_dir) storage_dir_close(dir_check);
        storage_file_free(dir_check);
        furi_record_close(RECORD_STORAGE);

        if(is_dir) {
            handle_list_dir(sn, sd_path, web_path);
        } else {
            http_send_str(sn, "HTTP/1.1 404 Not Found\r\nConnection: close\r\n"
                "Content-Length: 10\r\n\r\nNot found\n");
            http_flush(sn);
        }
        return;
    }

    if(strncmp(uri, "/download", 9) == 0) {
        const char* path = uri + 9;
        strncpy(web_path, path, sizeof(web_path));
        web_path[sizeof(web_path) - 1] = '\0';
        web_to_sd_path(web_path, sd_path, sizeof(sd_path));
        handle_download(sn, sd_path, path_filename(web_path), buf, buf_size, state);
        return;
    }

    if(strncmp(uri, "/delete", 7) == 0) {
        const char* path = uri + 7;
        strncpy(web_path, path, sizeof(web_path));
        web_path[sizeof(web_path) - 1] = '\0';
        web_to_sd_path(web_path, sd_path, sizeof(sd_path));

        char parent[FILEMGR_PATH_MAX];
        get_parent_path(web_path, parent, sizeof(parent));
        handle_delete(sn, sd_path, parent);
        return;
    }

    if(strncmp(uri, "/upload", 7) == 0 && strcmp(method, "POST") == 0) {
        const char* path = uri + 7;
        if(path[0] == '\0') path = "/";
        strncpy(web_path, path, sizeof(web_path));
        web_path[sizeof(web_path) - 1] = '\0';
        web_to_sd_path(web_path, sd_path, sizeof(sd_path));
        handle_upload(sn, sd_path, web_path, buf, buf_size, state);
        return;
    }

    if(strncmp(uri, "/mkdir", 6) == 0 && strcmp(method, "POST") == 0) {
        const char* path = uri + 6;
        if(path[0] == '\0') path = "/";
        strncpy(web_path, path, sizeof(web_path));
        web_path[sizeof(web_path) - 1] = '\0';
        web_to_sd_path(web_path, sd_path, sizeof(sd_path));
        handle_mkdir(sn, sd_path, web_path, buf, buf_size);
        return;
    }

    /* 404 */
    http_send_str(sn, "HTTP/1.1 404 Not Found\r\nConnection: close\r\n"
        "Content-Length: 10\r\n\r\nNot found\n");
    http_flush(sn);
}

/* ==================== TCP connection handling ==================== */

static void handle_connection(
    uint8_t sn,
    uint8_t* buf,
    uint16_t buf_size,
    FileManagerState* state) {
    int32_t total_read = 0;
    uint32_t start = furi_get_tick();
    bool headers_complete = false;

    while(furi_get_tick() - start < 5000 && state->running && !headers_complete) {
        int32_t avail = buf_size - total_read - 1;
        if(avail <= 0) break;

        int32_t len = recv(sn, buf + total_read, avail);
        if(len > 0) {
            total_read += len;
            buf[total_read] = '\0';

            if(strstr((char*)buf, "\r\n\r\n")) {
                headers_complete = true;
            }
            start = furi_get_tick();
        } else {
            furi_delay_ms(5);
        }
    }

    if(total_read <= 0) return;
    buf[total_read] = '\0';

    char method[8] = {0};
    char uri[FILEMGR_PATH_MAX] = {0};

    char* space1 = strchr((char*)buf, ' ');
    if(!space1) return;

    size_t method_len = space1 - (char*)buf;
    if(method_len >= sizeof(method)) method_len = sizeof(method) - 1;
    memcpy(method, buf, method_len);
    method[method_len] = '\0';

    char* uri_start = space1 + 1;
    char* space2 = strchr(uri_start, ' ');
    if(!space2) return;

    size_t uri_len = space2 - uri_start;
    if(uri_len >= sizeof(uri)) uri_len = sizeof(uri) - 1;
    memcpy(uri, uri_start, uri_len);
    uri[uri_len] = '\0';

    char* query = strchr(uri, '?');
    if(query) *query = '\0';

    FURI_LOG_I(TAG, "%s %s", method, uri);

    /* For POST: shift body data to start of buf */
    if(strcmp(method, "POST") == 0) {
        char* body = strstr((char*)buf, "\r\n\r\n");
        if(body) {
            body += 4;
            int32_t body_already = total_read - (body - (char*)buf);
            if(body_already > 0) {
                memmove(buf, body, body_already);
            }
        }
    }

    handle_request(sn, method, uri, buf, buf_size, state);
}

/* ==================== Public API ==================== */

bool file_manager_start(FileManagerState* state) {
    memset(state, 0, sizeof(FileManagerState));
    strncpy(state->current_path, "/ext", sizeof(state->current_path));
    state->running = true;

    int8_t ret = socket(FILEMGR_HTTP_SOCKET, Sn_MR_TCP, FILEMGR_HTTP_PORT, 0);
    if(ret != FILEMGR_HTTP_SOCKET) {
        FURI_LOG_E(TAG, "Failed to open socket %d (ret=%d)", FILEMGR_HTTP_SOCKET, ret);
        return false;
    }

    ret = listen(FILEMGR_HTTP_SOCKET);
    if(ret != SOCK_OK) {
        FURI_LOG_E(TAG, "Failed to listen on socket %d", FILEMGR_HTTP_SOCKET);
        close(FILEMGR_HTTP_SOCKET);
        return false;
    }

    FURI_LOG_I(TAG, "HTTP server listening on port %d", FILEMGR_HTTP_PORT);
    return true;
}

void file_manager_poll(FileManagerState* state, uint8_t* buf, uint16_t buf_size) {
    uint8_t status = getSn_SR(FILEMGR_HTTP_SOCKET);

    switch(status) {
    case SOCK_ESTABLISHED:
        handle_connection(FILEMGR_HTTP_SOCKET, buf, buf_size, state);
        /* Data already flushed inside handlers. Now close gracefully. */
        disconnect(FILEMGR_HTTP_SOCKET);
        break;

    case SOCK_CLOSE_WAIT:
        disconnect(FILEMGR_HTTP_SOCKET);
        break;

    case SOCK_CLOSED:
        socket(FILEMGR_HTTP_SOCKET, Sn_MR_TCP, FILEMGR_HTTP_PORT, 0);
        listen(FILEMGR_HTTP_SOCKET);
        break;

    case SOCK_LISTEN:
        break;

    default:
        break;
    }

    furi_delay_ms(10);
}

void file_manager_stop(FileManagerState* state) {
    state->running = false;
    close(FILEMGR_HTTP_SOCKET);
    FURI_LOG_I(TAG, "HTTP server stopped");
}
