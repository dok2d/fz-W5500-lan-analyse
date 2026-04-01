#include "file_manager.h"

#include <furi.h>
#include <storage/storage.h>
#include <socket.h>
#include <wizchip_conf.h>

#include <string.h>
#include <stdio.h>

#define TAG "FILEMGR"

/* Max lengths for path components — kept short so concatenations fit in PATH_MAX */
#define FM_NAME_MAX   64   /* single file/folder name */
#define FM_PREFIX_MAX 16   /* "/browse", "/delete", "/ext" etc. */

/* Simple memmem implementation */
static void* filemgr_memmem(const void* haystack, size_t hlen,
                             const void* needle, size_t nlen) {
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

/* ==================== HTTP response helpers ==================== */

static void http_send_str(uint8_t sn, const char* str) {
    int32_t len = strlen(str);
    if(len > 0) {
        send(sn, (uint8_t*)str, len);
    }
}

static void http_send_headers(uint8_t sn, const char* status, const char* content_type) {
    char hdr[192];
    snprintf(hdr, sizeof(hdr),
        "HTTP/1.1 %s\r\n"
        "Content-Type: %s\r\n"
        "Connection: close\r\n"
        "\r\n",
        status, content_type);
    http_send_str(sn, hdr);
}

static void http_send_redirect(uint8_t sn, const char* location) {
    http_send_str(sn, "HTTP/1.1 303 See Other\r\nConnection: close\r\nContent-Length: 0\r\nLocation: ");
    http_send_str(sn, location);
    http_send_str(sn, "\r\n\r\n");
}

/* ==================== HTML generation ==================== */

static const char html_head[] =
    "<!DOCTYPE html><html><head><meta charset='utf-8'>"
    "<meta name='viewport' content='width=device-width,initial-scale=1'>"
    "<title>Flipper File Manager</title>"
    "<style>"
    "body{font-family:monospace;background:#1a1a2e;color:#e0e0e0;margin:0;padding:16px}"
    "h1{color:#ff8c00;font-size:18px;margin:0 0 4px}"
    ".path{color:#888;font-size:13px;margin-bottom:12px;word-break:break-all}"
    "table{width:100%;border-collapse:collapse}"
    "th{text-align:left;padding:6px 8px;border-bottom:2px solid #ff8c00;color:#ff8c00;font-size:13px}"
    "td{padding:5px 8px;border-bottom:1px solid #333;font-size:13px}"
    "tr:hover{background:#2a2a4a}"
    "a{color:#5dade2;text-decoration:none}a:hover{text-decoration:underline}"
    ".dir{color:#ff8c00;font-weight:bold}"
    ".sz{color:#888;text-align:right}"
    ".acts{white-space:nowrap}"
    ".acts a{margin-left:8px;color:#e74c3c;font-size:12px}"
    ".btn{display:inline-block;padding:6px 14px;background:#ff8c00;color:#1a1a2e;"
    "border:none;cursor:pointer;font-family:monospace;font-size:13px;font-weight:bold;"
    "text-decoration:none;margin:2px}"
    ".btn:hover{background:#ffa500}"
    ".btn-sm{padding:3px 8px;font-size:11px}"
    ".upload-form{margin:12px 0;padding:10px;background:#2a2a4a;border:1px solid #444}"
    ".mkdir-form{margin:8px 0}"
    "input[type=text]{background:#1a1a2e;color:#e0e0e0;border:1px solid #555;"
    "padding:4px 8px;font-family:monospace;font-size:13px}"
    "input[type=file]{color:#e0e0e0;font-size:12px}"
    ".footer{margin-top:16px;color:#555;font-size:11px}"
    "</style></head><body>";

static const char html_tail[] =
    "<div class='footer'>Flipper Zero W5500 File Manager</div>"
    "</body></html>";

/* Format file size human-readable */
static void format_size(uint64_t size, char* buf, size_t buf_size) {
    if(size < 1024) {
        snprintf(buf, buf_size, "%lu B", (unsigned long)size);
    } else if(size < 1024 * 1024) {
        snprintf(buf, buf_size, "%lu.%lu KB",
            (unsigned long)(size / 1024),
            (unsigned long)((size % 1024) * 10 / 1024));
    } else {
        snprintf(buf, buf_size, "%lu.%lu MB",
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

/* Send directory listing page — sends HTML in many small writes to avoid large buffers */
static void handle_list_dir(uint8_t sn, const char* sd_path, const char* web_path) {
    Storage* storage = furi_record_open(RECORD_STORAGE);

    http_send_headers(sn, "200 OK", "text/html; charset=utf-8");
    http_send_str(sn, html_head);

    /* Title and path — send in parts to avoid large snprintf */
    http_send_str(sn, "<h1>&#128190; Flipper File Manager</h1><div class='path'>");
    http_send_str(sn, web_path);
    http_send_str(sn, "</div>");

    /* Parent link (if not at root) */
    if(strcmp(web_path, "/") != 0) {
        char parent[FILEMGR_PATH_MAX];
        get_parent_path(web_path, parent, sizeof(parent));
        http_send_str(sn, "<a href='/browse");
        http_send_str(sn, parent);
        http_send_str(sn, "' class='btn btn-sm'>&uarr; Up</a> ");
    }

    /* Upload form */
    http_send_str(sn, "<div class='upload-form'>"
        "<form method='POST' action='/upload");
    http_send_str(sn, web_path);
    http_send_str(sn, "' enctype='multipart/form-data'>"
        "<input type='file' name='file'> "
        "<button type='submit' class='btn btn-sm'>Upload</button>"
        "</form></div>");

    /* Mkdir form */
    http_send_str(sn, "<div class='mkdir-form'>"
        "<form method='POST' action='/mkdir");
    http_send_str(sn, web_path);
    http_send_str(sn, "'>"
        "<input type='text' name='name' placeholder='New folder name' size='20'> "
        "<button type='submit' class='btn btn-sm'>Create Folder</button>"
        "</form></div>");

    /* Table header */
    http_send_str(sn,
        "<table><tr><th>Name</th><th>Size</th><th>Actions</th></tr>");

    /* List directory */
    File* dir = storage_file_alloc(storage);
    if(storage_dir_open(dir, sd_path)) {
        FileInfo info;
        char name[FM_NAME_MAX];
        while(storage_dir_read(dir, &info, name, sizeof(name))) {
            bool is_dir = (info.flags & FSF_DIRECTORY);
            char size_str[32] = "";
            if(!is_dir) {
                format_size(info.size, size_str, sizeof(size_str));
            }

            /* Build entry web path by concatenating parts directly */
            /* Send each table row using multiple http_send_str calls */
            if(is_dir) {
                http_send_str(sn, "<tr><td><a href='/browse");
                if(strcmp(web_path, "/") != 0) http_send_str(sn, web_path);
                http_send_str(sn, "/");
                http_send_str(sn, name);
                http_send_str(sn, "' class='dir'>&#128193; ");
                http_send_str(sn, name);
                http_send_str(sn, "/</a></td><td class='sz'>-</td><td class='acts'>"
                    "<a href='/delete");
                if(strcmp(web_path, "/") != 0) http_send_str(sn, web_path);
                http_send_str(sn, "/");
                http_send_str(sn, name);
                http_send_str(sn, "' onclick=\"return confirm('Delete folder?')\">"
                    "&#128465; Del</a></td></tr>");
            } else {
                http_send_str(sn, "<tr><td>&#128196; ");
                http_send_str(sn, name);
                http_send_str(sn, "</td><td class='sz'>");
                http_send_str(sn, size_str);
                http_send_str(sn, "</td><td class='acts'>"
                    "<a href='/download");
                if(strcmp(web_path, "/") != 0) http_send_str(sn, web_path);
                http_send_str(sn, "/");
                http_send_str(sn, name);
                http_send_str(sn, "' class='btn btn-sm'>&#11015; DL</a>"
                    "<a href='/delete");
                if(strcmp(web_path, "/") != 0) http_send_str(sn, web_path);
                http_send_str(sn, "/");
                http_send_str(sn, name);
                http_send_str(sn, "' onclick=\"return confirm('Delete file?')\">"
                    "&#128465; Del</a></td></tr>");
            }
        }
        storage_dir_close(dir);
    } else {
        http_send_str(sn, "<tr><td colspan='3'>Failed to open directory</td></tr>");
    }
    storage_file_free(dir);

    http_send_str(sn, "</table>");
    http_send_str(sn, html_tail);

    furi_record_close(RECORD_STORAGE);
}

/* Send file download */
static void handle_download(uint8_t sn, const char* sd_path, const char* filename,
                            uint8_t* buf, uint16_t buf_size, FileManagerState* state) {
    Storage* storage = furi_record_open(RECORD_STORAGE);
    File* file = storage_file_alloc(storage);

    if(!storage_file_open(file, sd_path, FSAM_READ, FSOM_OPEN_EXISTING)) {
        http_send_headers(sn, "404 Not Found", "text/html; charset=utf-8");
        http_send_str(sn, html_head);
        http_send_str(sn, "<h1>404 - File Not Found</h1>");
        http_send_str(sn, html_tail);
        storage_file_free(file);
        furi_record_close(RECORD_STORAGE);
        return;
    }

    uint64_t file_size = storage_file_size(file);

    /* Send headers in parts to avoid large buffer */
    char len_str[16];
    snprintf(len_str, sizeof(len_str), "%lu", (unsigned long)file_size);

    http_send_str(sn, "HTTP/1.1 200 OK\r\n"
        "Content-Type: application/octet-stream\r\n"
        "Connection: close\r\n"
        "Content-Disposition: attachment; filename=\"");
    http_send_str(sn, filename);
    http_send_str(sn, "\"\r\nContent-Length: ");
    http_send_str(sn, len_str);
    http_send_str(sn, "\r\n\r\n");

    /* Stream file in chunks */
    while(!storage_file_eof(file) && state->running) {
        uint16_t chunk = buf_size;
        if(chunk > FILEMGR_CHUNK_SIZE) chunk = FILEMGR_CHUNK_SIZE;
        uint16_t read = storage_file_read(file, buf, chunk);
        if(read == 0) break;
        int32_t sent = send(sn, buf, read);
        if(sent <= 0) {
            state->errors++;
            break;
        }
        state->bytes_sent += read;
        furi_delay_ms(1);
    }

    storage_file_close(file);
    storage_file_free(file);
    furi_record_close(RECORD_STORAGE);
}

/* Handle file upload (multipart/form-data) */
static void handle_upload(uint8_t sn, const char* sd_dir_path, const char* web_dir_path,
                          uint8_t* buf, uint16_t buf_size, FileManagerState* state) {
    int32_t total_read = 0;
    int32_t body_len = 0;

    uint16_t chunk = buf_size;
    if(chunk > FILEMGR_CHUNK_SIZE) chunk = FILEMGR_CHUNK_SIZE;

    /* Wait for data with timeout */
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
        http_send_headers(sn, "400 Bad Request", "text/html; charset=utf-8");
        http_send_str(sn, html_head);
        http_send_str(sn, "<h1>400 - No data received</h1>");
        http_send_str(sn, html_tail);
        return;
    }

    body_len = total_read;

    /* Find the boundary line (starts with --) */
    char* boundary_start = (char*)buf;
    char* boundary_end = strstr(boundary_start, "\r\n");
    if(!boundary_end) {
        http_send_headers(sn, "400 Bad Request", "text/html; charset=utf-8");
        http_send_str(sn, html_head);
        http_send_str(sn, "<h1>400 - Invalid multipart data</h1>");
        http_send_str(sn, html_tail);
        return;
    }

    size_t boundary_len = boundary_end - boundary_start;

    /* Find filename in Content-Disposition */
    char* fn_ptr = strstr((char*)buf, "filename=\"");
    if(!fn_ptr) {
        http_send_headers(sn, "400 Bad Request", "text/html; charset=utf-8");
        http_send_str(sn, html_head);
        http_send_str(sn, "<h1>400 - No filename found</h1>");
        http_send_str(sn, html_tail);
        return;
    }
    fn_ptr += 10;
    char* fn_end = strchr(fn_ptr, '"');
    if(!fn_end || fn_end == fn_ptr) {
        http_send_headers(sn, "400 Bad Request", "text/html; charset=utf-8");
        http_send_str(sn, html_head);
        http_send_str(sn, "<h1>400 - Empty filename</h1>");
        http_send_str(sn, html_tail);
        return;
    }

    char filename[FM_NAME_MAX];
    size_t fn_len = fn_end - fn_ptr;
    if(fn_len >= sizeof(filename)) fn_len = sizeof(filename) - 1;
    memcpy(filename, fn_ptr, fn_len);
    filename[fn_len] = '\0';

    /* Find end of part headers (\r\n\r\n) */
    char* data_start = strstr(fn_end, "\r\n\r\n");
    if(!data_start) {
        http_send_headers(sn, "400 Bad Request", "text/html; charset=utf-8");
        http_send_str(sn, html_head);
        http_send_str(sn, "<h1>400 - Malformed multipart</h1>");
        http_send_str(sn, html_tail);
        return;
    }
    data_start += 4;

    /* Find the closing boundary */
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

    /* Write file to SD card — build path safely */
    char filepath[FILEMGR_PATH_MAX];
    size_t dir_len = strlen(sd_dir_path);
    size_t name_len = strlen(filename);
    if(dir_len + 1 + name_len >= sizeof(filepath)) {
        http_send_headers(sn, "400 Bad Request", "text/html; charset=utf-8");
        http_send_str(sn, html_head);
        http_send_str(sn, "<h1>400 - Path too long</h1>");
        http_send_str(sn, html_tail);
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

        /* Redirect back to directory listing */
        http_send_str(sn, "HTTP/1.1 303 See Other\r\nConnection: close\r\n"
            "Content-Length: 0\r\nLocation: /browse");
        http_send_str(sn, web_dir_path);
        http_send_str(sn, "\r\n\r\n");
    } else {
        http_send_headers(sn, "500 Internal Server Error", "text/html; charset=utf-8");
        http_send_str(sn, html_head);
        http_send_str(sn, "<h1>500 - Failed to write file</h1>");
        http_send_str(sn, html_tail);
        state->errors++;
    }

    storage_file_free(file);
    furi_record_close(RECORD_STORAGE);
}

/* Handle mkdir */
static void handle_mkdir(uint8_t sn, const char* sd_dir_path, const char* web_dir_path,
                         uint8_t* buf, uint16_t buf_size) {
    /* Read POST body to get folder name */
    int32_t total_read = 0;
    uint16_t chunk = buf_size;
    if(chunk > 512) chunk = 512;

    uint32_t start = furi_get_tick();
    while(furi_get_tick() - start < 3000) {
        int32_t len = recv(sn, buf + total_read, chunk - total_read);
        if(len > 0) {
            total_read += len;
            if(total_read >= (int32_t)chunk) break;
            if(memchr(buf, '\0', total_read) || total_read > 5) break;
            start = furi_get_tick();
        } else {
            furi_delay_ms(10);
        }
    }

    if(total_read <= 0) {
        http_send_redirect(sn, "/browse/");
        return;
    }

    buf[total_read] = '\0';

    /* Parse "name=foldername" from URL-encoded body */
    char* name_ptr = strstr((char*)buf, "name=");
    if(!name_ptr) {
        http_send_redirect(sn, "/browse/");
        return;
    }
    name_ptr += 5;

    char folder_name[FM_NAME_MAX];
    char* amp = strchr(name_ptr, '&');
    if(amp) *amp = '\0';
    url_decode(folder_name, name_ptr, sizeof(folder_name));

    if(strlen(folder_name) == 0) {
        http_send_redirect(sn, "/browse/");
        return;
    }

    /* Create directory — build path safely */
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

    /* Redirect back */
    http_send_str(sn, "HTTP/1.1 303 See Other\r\nConnection: close\r\n"
        "Content-Length: 0\r\nLocation: /browse");
    http_send_str(sn, web_dir_path);
    http_send_str(sn, "\r\n\r\n");
}

/* Handle delete */
static void handle_delete(uint8_t sn, const char* sd_path, const char* web_parent_path) {
    Storage* storage = furi_record_open(RECORD_STORAGE);
    storage_simply_remove(storage, sd_path);
    furi_record_close(RECORD_STORAGE);

    FURI_LOG_I(TAG, "Deleted: %s", sd_path);

    http_send_str(sn, "HTTP/1.1 303 See Other\r\nConnection: close\r\n"
        "Content-Length: 0\r\nLocation: /browse");
    http_send_str(sn, web_parent_path);
    http_send_str(sn, "\r\n\r\n");
}

/* ==================== Main request router ==================== */

/* Convert web path to SD card path */
static void web_to_sd_path(const char* web_path, char* sd_path, size_t sd_size) {
    if(web_path[0] == '\0' || strcmp(web_path, "/") == 0) {
        strncpy(sd_path, "/ext", sd_size);
    } else {
        snprintf(sd_path, sd_size, "/ext%s", web_path);
    }
    sd_path[sd_size - 1] = '\0';
}

/* Extract the last component of a path as filename */
static const char* path_filename(const char* path) {
    const char* last = strrchr(path, '/');
    return last ? last + 1 : path;
}

static void handle_request(uint8_t sn, const char* method, const char* raw_uri,
                           uint8_t* buf, uint16_t buf_size, FileManagerState* state) {
    /* URL-decode the URI */
    char uri[FILEMGR_PATH_MAX];
    url_decode(uri, raw_uri, sizeof(uri));

    char sd_path[FILEMGR_PATH_MAX];
    char web_path[FILEMGR_PATH_MAX];

    state->requests_served++;

    if(strcmp(uri, "/") == 0 || strcmp(uri, "") == 0) {
        http_send_redirect(sn, "/browse/");
        return;
    }

    if(strncmp(uri, "/browse", 7) == 0) {
        const char* path = uri + 7;
        if(path[0] == '\0') path = "/";
        strncpy(web_path, path, sizeof(web_path));
        web_path[sizeof(web_path) - 1] = '\0';
        web_to_sd_path(web_path, sd_path, sizeof(sd_path));

        Storage* storage = furi_record_open(RECORD_STORAGE);
        bool is_dir = storage_dir_exists(storage, sd_path);
        furi_record_close(RECORD_STORAGE);

        if(is_dir) {
            handle_list_dir(sn, sd_path, web_path);
        } else {
            http_send_headers(sn, "404 Not Found", "text/html; charset=utf-8");
            http_send_str(sn, html_head);
            http_send_str(sn, "<h1>404 - Directory not found</h1>"
                "<p><a href='/browse/'>Go to root</a></p>");
            http_send_str(sn, html_tail);
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

    /* Unknown route */
    http_send_headers(sn, "404 Not Found", "text/html; charset=utf-8");
    http_send_str(sn, html_head);
    http_send_str(sn, "<h1>404 - Not Found</h1>"
        "<p><a href='/browse/'>Go to File Manager</a></p>");
    http_send_str(sn, html_tail);
}

/* ==================== TCP connection handling ==================== */

static void handle_connection(uint8_t sn, uint8_t* buf, uint16_t buf_size,
                              FileManagerState* state) {
    /* Read HTTP request headers */
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

    /* Parse request line: "METHOD /uri HTTP/1.x\r\n" */
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

    /* Strip query string */
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
    disconnect(FILEMGR_HTTP_SOCKET);
    close(FILEMGR_HTTP_SOCKET);
    FURI_LOG_I(TAG, "HTTP server stopped");
}
