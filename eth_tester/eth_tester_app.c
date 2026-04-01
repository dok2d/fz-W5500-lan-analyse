#include "eth_tester_app.h"
#include "hal/w5500_hal.h"
#include "protocols/lldp.h"
#include "protocols/cdp.h"
#include "protocols/arp_scan.h"
#include "protocols/dhcp_discover.h"
#include "protocols/icmp.h"
#include "protocols/dns_lookup.h"
#include "protocols/wol.h"
#include "protocols/ping_graph.h"
#include "protocols/port_scan.h"
#include "protocols/mac_changer.h"
#include "protocols/traceroute.h"
#include "protocols/discovery.h"
#include "protocols/stp_vlan.h"
#include "protocols/history.h"
#include "bridge/eth_bridge.h"
#include "usb_eth/usb_eth.h"
#include "utils/packet_utils.h"
#include "utils/oui_lookup.h"

#include <furi.h>
#include <furi_hal.h>
#include <furi_hal_random.h>
#include <gui/gui.h>
#include <gui/view_dispatcher.h>
#include <gui/modules/submenu.h>
#include <gui/modules/text_box.h>
#include <notification/notification_messages.h>
#include <storage/storage.h>

#include <socket.h>
#include <dhcp.h>
#include <wizchip_conf.h>

#include <string.h>
#include <stdio.h>

#define TAG "ETH"

/* Internal worker operations (beyond EthTesterMenuItem range) */
#define WORKER_OP_PING_SWEEP_DETECT 100

/* Custom events sent from worker to main thread */
#define CUSTOM_EVENT_PING_SWEEP_READY 1
#define CUSTOM_EVENT_HISTORY_DELETE 2

/* Global app pointer for navigation callbacks (single-instance app) */
static EthTesterApp* g_app = NULL;

/* ==================== WIZnet library compatibility stubs ==================== */

/*
 * eth_printf: called by WIZnet DHCP/ICMP library for debug output.
 * We forward it to Flipper's FURI_LOG system.
 */
void eth_printf(const char* format, ...) {
    va_list args;
    va_start(args, format);
    FuriString* fstr = furi_string_alloc_vprintf(format, args);
    va_end(args);
    FURI_LOG_D(TAG, "%s", furi_string_get_cstr(fstr));
    furi_string_free(fstr);
}

/*
 * ping_wait_ms: called by WIZnet ping/traceroute library.
 */
void ping_wait_ms(int ms) {
    furi_delay_ms(ms);
}

/*
 * DHCP timer callback for FuriTimer (1 second periodic).
 */
static void dhcp_timer_callback(void* context) {
    UNUSED(context);
    DHCP_time_handler();
}

/* Default MAC address (WIZnet OUI range) */
#define DEFAULT_MAC \
    { 0x00, 0x08, 0xDC, 0x47, 0x47, 0x54 }

/* Frame receive buffer size */
#define FRAME_BUF_SIZE 1600

/* Settings file path */
#define SETTINGS_PATH APP_DATA_PATH("settings.conf")

/* ==================== Settings persistence ==================== */

static void eth_tester_settings_load(EthTesterApp* app) {
    /* Defaults: both enabled */
    app->setting_autosave = true;
    app->setting_sound = true;

    Storage* storage = furi_record_open(RECORD_STORAGE);
    File* file = storage_file_alloc(storage);
    if(storage_file_open(file, SETTINGS_PATH, FSAM_READ, FSOM_OPEN_EXISTING)) {
        char buf[32];
        uint16_t read = storage_file_read(file, buf, sizeof(buf) - 1);
        buf[read] = '\0';
        storage_file_close(file);
        /* Simple format: "autosave=X\nsound=X\n" */
        if(strstr(buf, "autosave=0")) app->setting_autosave = false;
        if(strstr(buf, "sound=0")) app->setting_sound = false;
    }
    storage_file_free(file);
    furi_record_close(RECORD_STORAGE);
}

static void eth_tester_settings_save(EthTesterApp* app) {
    Storage* storage = furi_record_open(RECORD_STORAGE);
    storage_simply_mkdir(storage, APP_DATA_PATH(""));
    File* file = storage_file_alloc(storage);
    if(storage_file_open(file, SETTINGS_PATH, FSAM_WRITE, FSOM_CREATE_ALWAYS)) {
        char buf[32];
        snprintf(buf, sizeof(buf), "autosave=%d\nsound=%d\n",
            app->setting_autosave ? 1 : 0,
            app->setting_sound ? 1 : 0);
        storage_file_write(file, buf, strlen(buf));
        storage_file_close(file);
    }
    storage_file_free(file);
    furi_record_close(RECORD_STORAGE);
}

/* ==================== Forward declarations ==================== */

static void eth_tester_submenu_callback(void* context, uint32_t index);
static uint32_t eth_tester_navigation_exit_callback(void* context);
static uint32_t eth_tester_navigation_submenu_callback(void* context);
static uint32_t eth_tester_navigation_history_callback(void* context);
static uint32_t eth_tester_nav_back_netinfo(void* context);
static uint32_t eth_tester_nav_back_discovery(void* context);
static uint32_t eth_tester_nav_back_diag(void* context);
static uint32_t eth_tester_nav_back_tools(void* context);
static bool eth_tester_nav_event_cb(void* context);
static bool eth_tester_custom_event_cb(void* context, uint32_t event);
static void eth_tester_worker_stop(EthTesterApp* app);
static void eth_tester_update_view(TextBox* tb, FuriString* text);
static void eth_tester_show_view(EthTesterApp* app, TextBox* tb, EthTesterView view, FuriString* text, const char* initial);

static void eth_tester_do_link_info(EthTesterApp* app);
static void eth_tester_do_lldp_cdp(EthTesterApp* app);
static void eth_tester_do_arp_scan(EthTesterApp* app);
static void eth_tester_do_dhcp_analyze(EthTesterApp* app);
static void eth_tester_do_ping(EthTesterApp* app);
static void eth_tester_do_stats(EthTesterApp* app);
static void eth_tester_do_dns_lookup(EthTesterApp* app);
static void eth_tester_do_wol(EthTesterApp* app);
static void eth_tester_do_cont_ping(EthTesterApp* app);
static void eth_tester_do_port_scan(EthTesterApp* app);
static void eth_tester_do_mac_changer(EthTesterApp* app);
static void eth_tester_do_traceroute(EthTesterApp* app);
static void eth_tester_do_discovery(EthTesterApp* app);
static void eth_tester_do_ping_sweep(EthTesterApp* app);
static void eth_tester_do_ping_sweep_detect(EthTesterApp* app);
static void eth_tester_do_stp_vlan(EthTesterApp* app);
static void eth_tester_do_eth_bridge(EthTesterApp* app);
static void eth_tester_history_populate(EthTesterApp* app);
static void eth_tester_history_file_callback(void* context, uint32_t index);
static void eth_tester_history_delete_callback(void* context, uint32_t index);
static void eth_tester_count_frame(EthTesterApp* app, const uint8_t* frame, uint16_t len);
static bool eth_tester_save_results(const char* filename, const char* content);
static void eth_tester_save_and_notify(EthTesterApp* app, const char* type, FuriString* text);

/* ==================== ETH Bridge view model & callbacks ==================== */

typedef struct {
    EthTesterApp* app;
    bool active;          /* bridge is running */
    bool usb_connected;
    bool lan_link_up;
    uint8_t lan_speed;    /* 0=10M, 1=100M */
    uint8_t lan_duplex;   /* 0=half, 1=full */
    uint32_t frames_to_eth;
    uint32_t frames_to_usb;
    uint32_t errors;
    const char* status_line; /* "Starting...", "Running", "Stopped" */
} BridgeViewModel;

static void bridge_draw_callback(Canvas* canvas, void* model) {
    BridgeViewModel* vm = model;
    canvas_clear(canvas);

    /* Title */
    canvas_set_font(canvas, FontPrimary);
    canvas_draw_str_aligned(canvas, 64, 2, AlignCenter, AlignTop, "ETH Bridge");

    canvas_set_font(canvas, FontSecondary);
    char buf[40];

    if(!vm->active) {
        /* Show status message when not active (init/error/stopped) */
        canvas_draw_str(canvas, 2, 24, vm->status_line ? vm->status_line : "");
        return;
    }

    /* USB status */
    snprintf(buf, sizeof(buf), "USB: %s", vm->usb_connected ? "Connected" : "Waiting...");
    canvas_draw_str(canvas, 2, 16, buf);

    /* LAN status */
    snprintf(buf, sizeof(buf), "LAN: %s %s/%s",
        vm->lan_link_up ? "Up" : "Down",
        vm->lan_speed ? "100M" : "10M",
        vm->lan_duplex ? "FD" : "HD");
    canvas_draw_str(canvas, 2, 26, buf);

    /* Frame counters */
    snprintf(buf, sizeof(buf), "> LAN: %lu", (unsigned long)vm->frames_to_eth);
    canvas_draw_str(canvas, 2, 38, buf);

    snprintf(buf, sizeof(buf), "< LAN: %lu", (unsigned long)vm->frames_to_usb);
    canvas_draw_str(canvas, 2, 48, buf);

    if(vm->errors > 0) {
        snprintf(buf, sizeof(buf), "Err: %lu", (unsigned long)vm->errors);
        canvas_draw_str(canvas, 80, 48, buf);
    }

    /* Footer */
    canvas_draw_str_aligned(canvas, 64, 62, AlignCenter, AlignBottom, "[Back] Stop");
}

static bool bridge_input_callback(InputEvent* event, void* context) {
    EthTesterApp* app = context;
    if(event->type == InputTypeShort && event->key == InputKeyBack) {
        if(app->worker_running) {
            /* Bridge is active — signal it to stop */
            if(app->bridge_state) {
                app->bridge_state->running = false;
            }
            app->worker_running = false;
            return true; /* consumed — worker will clean up */
        }
        /* Bridge already stopped — let the default previous_callback
         * handle Back navigation (return to Tools menu) */
        return false;
    }
    return false;
}

/* ==================== Continuous Ping view model & callbacks ==================== */

typedef struct {
    EthTesterApp* app;
} ContPingViewModel;

static void cont_ping_draw_callback(Canvas* canvas, void* model) {
    ContPingViewModel* vm = model;
    EthTesterApp* app = vm->app;
    PingGraphState* pg = app->ping_graph;

    canvas_clear(canvas);

    if(!pg) {
        canvas_set_font(canvas, FontPrimary);
        canvas_draw_str(canvas, 2, 12, "Initializing...");
        return;
    }

    canvas_set_font(canvas, FontSecondary);

    char buf[64];

    /* Show target IP */
    snprintf(buf, sizeof(buf), "Ping %d.%d.%d.%d",
        app->cont_ping_target[0], app->cont_ping_target[1],
        app->cont_ping_target[2], app->cont_ping_target[3]);
    canvas_draw_str(canvas, 0, 7, buf);

    uint32_t cur = 0;
    if(pg->sample_count > 0) {
        uint32_t last = ping_graph_get_sample(pg, pg->sample_count - 1);
        cur = (last == PING_RTT_TIMEOUT) ? 0 : last;
    }
    uint32_t avg = ping_graph_avg_rtt(pg);
    uint8_t loss = ping_graph_loss_percent(pg);

    snprintf(buf, sizeof(buf), "%lums avg:%lu loss:%d%%",
        (unsigned long)cur, (unsigned long)avg, loss);
    canvas_draw_str(canvas, 0, 16, buf);

    uint8_t graph_top = 22;
    uint8_t graph_bottom = 63;
    uint8_t graph_height = graph_bottom - graph_top;
    uint8_t graph_width = 128;

    canvas_draw_line(canvas, 0, graph_top, 0, graph_bottom);
    canvas_draw_line(canvas, 0, graph_bottom, graph_width - 1, graph_bottom);

    uint16_t count = ping_graph_visible_count(pg);
    if(count == 0) return;

    uint32_t max_rtt = 1;
    for(uint16_t i = 0; i < count; i++) {
        uint32_t s = ping_graph_get_sample(pg, i);
        if(s != PING_RTT_TIMEOUT && s > max_rtt) max_rtt = s;
    }
    max_rtt = max_rtt + max_rtt / 10 + 1;

    uint16_t start_x = (count < graph_width) ? (graph_width - count) : 0;
    uint16_t start_sample = (count > graph_width) ? (count - graph_width) : 0;

    int16_t prev_y = -1;
    for(uint16_t i = 0; i < count && (start_x + i - start_sample) < graph_width; i++) {
        uint16_t si = start_sample + i;
        if(si >= count) break;

        uint32_t rtt = ping_graph_get_sample(pg, si);
        uint8_t x = (uint8_t)(start_x + i - start_sample);

        if(rtt == PING_RTT_TIMEOUT) {
            canvas_draw_dot(canvas, x, graph_top + 1);
            canvas_draw_dot(canvas, x, graph_top + 2);
            prev_y = -1;
        } else {
            uint32_t scaled = (rtt * graph_height) / max_rtt;
            if(scaled > graph_height) scaled = graph_height;
            int16_t y = (int16_t)(graph_bottom - scaled);

            if(prev_y >= 0) {
                canvas_draw_line(canvas, x - 1, (uint8_t)prev_y, x, (uint8_t)y);
            } else {
                canvas_draw_dot(canvas, x, (uint8_t)y);
            }
            prev_y = y;
        }
    }
}

static bool cont_ping_input_callback(InputEvent* event, void* context) {
    EthTesterApp* app = context;

    if(event->type == InputTypeShort && event->key == InputKeyBack) {
        if(app->ping_graph) {
            app->ping_graph->running = false;
        }
        return true;
    }

    return false;
}

/* ==================== App alloc / free ==================== */

/* ==================== Settings view callbacks ==================== */

static const char* const setting_onoff[] = {"OFF", "ON"};

static void settings_autosave_changed(VariableItem* item) {
    uint8_t idx = variable_item_get_current_value_index(item);
    variable_item_set_current_value_text(item, setting_onoff[idx]);
    if(g_app) {
        g_app->setting_autosave = (idx == 1);
        eth_tester_settings_save(g_app);
    }
}

static void settings_sound_changed(VariableItem* item) {
    uint8_t idx = variable_item_get_current_value_index(item);
    variable_item_set_current_value_text(item, setting_onoff[idx]);
    if(g_app) {
        g_app->setting_sound = (idx == 1);
        eth_tester_settings_save(g_app);
    }
}

static void settings_enter_callback(void* context, uint32_t index) {
    EthTesterApp* app = context;
    if(index == 2) { /* "Clear History" is the 3rd item (index 2) */
        /* Delete all history files */
        HistoryState* hs = malloc(sizeof(HistoryState));
        if(hs) {
            uint16_t count = history_list(hs);
            for(uint16_t i = 0; i < count; i++) {
                history_delete_file(hs->files[i].filename);
            }
            free(hs);
        }
        if(app->setting_sound) {
            notification_message(app->notifications, &sequence_success);
        }
    }
}

static EthTesterApp* eth_tester_app_alloc(void) {
    EthTesterApp* app = malloc(sizeof(EthTesterApp));
    memset(app, 0, sizeof(EthTesterApp));
    g_app = app;

    /* Allocate frame buffer on heap */
    app->frame_buf = malloc(FRAME_BUF_SIZE);
    furi_assert(app->frame_buf);

    /* Set default MAC */
    uint8_t default_mac[6] = DEFAULT_MAC;
    memcpy(app->mac_addr, default_mac, 6);

    /* DHCP timer: 1 second periodic, needed by WIZnet DHCP_run() */
    app->dhcp_timer = furi_timer_alloc(dhcp_timer_callback, FuriTimerTypePeriodic, NULL);
    furi_timer_start(app->dhcp_timer, 1000);

    /* Allocate text buffers */
    app->link_info_text = furi_string_alloc();
    app->lldp_text = furi_string_alloc();
    app->arp_text = furi_string_alloc();
    app->dhcp_text = furi_string_alloc();
    app->ping_text = furi_string_alloc();
    app->stats_text = furi_string_alloc();
    app->dns_text = furi_string_alloc();
    app->wol_text = furi_string_alloc();
    app->port_scan_text = furi_string_alloc();
    app->mac_changer_text = furi_string_alloc();
    app->traceroute_text = furi_string_alloc();
    app->ping_sweep_text = furi_string_alloc();
    app->discovery_text = furi_string_alloc();
    app->stp_vlan_text = furi_string_alloc();
    /* history_text removed — history now uses submenu */
    app->history_file_text = furi_string_alloc();

    /* Set initial text */
    furi_string_set(app->link_info_text, "Press OK to read\nlink status...\n");
    furi_string_set(app->lldp_text, "Listening for\nLLDP/CDP...\n");
    furi_string_set(app->arp_text, "ARP Scan ready.\nPress Back to return.\n");
    furi_string_set(app->dhcp_text, "DHCP Analyze ready.\nPress Back to return.\n");
    furi_string_set(app->ping_text, "Ping ready.\nPress Back to return.\n");
    furi_string_set(app->stats_text, "No statistics yet.\nRun LLDP/CDP or ARP\nto collect data.\n");
    furi_string_set(app->dns_text, "DNS Lookup ready.\n");
    furi_string_set(app->wol_text, "Wake-on-LAN ready.\n");
    furi_string_set(app->port_scan_text, "Port Scanner ready.\n");
    furi_string_set(app->mac_changer_text, "MAC Changer ready.\n");
    furi_string_set(app->traceroute_text, "Traceroute ready.\n");
    furi_string_set(app->ping_sweep_text, "Ping Sweep ready.\n");

    /* Open GUI */
    app->gui = furi_record_open(RECORD_GUI);
    app->notifications = furi_record_open(RECORD_NOTIFICATION);

    /* ViewDispatcher */
    app->view_dispatcher = view_dispatcher_alloc();
    view_dispatcher_attach_to_gui(app->view_dispatcher, app->gui, ViewDispatcherTypeFullscreen);
    view_dispatcher_set_event_callback_context(app->view_dispatcher, app);
    view_dispatcher_set_navigation_event_callback(app->view_dispatcher, eth_tester_nav_event_cb);
    view_dispatcher_set_custom_event_callback(app->view_dispatcher, eth_tester_custom_event_cb);

    /* Main menu (Submenu view) */
    app->submenu = submenu_alloc();
    /* Main menu: grouped categories */
    submenu_add_item(app->submenu, "Network Info", 100, eth_tester_submenu_callback, app);
    submenu_add_item(app->submenu, "Discovery", 101, eth_tester_submenu_callback, app);
    submenu_add_item(app->submenu, "Diagnostics", 102, eth_tester_submenu_callback, app);
    submenu_add_item(app->submenu, "Tools", 103, eth_tester_submenu_callback, app);
    submenu_add_item(app->submenu, "History", EthTesterMenuItemHistory, eth_tester_submenu_callback, app);
    submenu_add_item(app->submenu, "Settings", 104, eth_tester_submenu_callback, app);
    submenu_add_item(app->submenu, "About", EthTesterMenuItemAbout, eth_tester_submenu_callback, app);
    view_set_previous_callback(submenu_get_view(app->submenu), eth_tester_navigation_exit_callback);
    view_dispatcher_add_view(app->view_dispatcher, EthTesterViewMainMenu, submenu_get_view(app->submenu));

    /* Category: Network Info */
    app->submenu_cat_netinfo = submenu_alloc();
    submenu_add_item(app->submenu_cat_netinfo, "Link Info", EthTesterMenuItemLinkInfo, eth_tester_submenu_callback, app);
    submenu_add_item(app->submenu_cat_netinfo, "DHCP Analyze", EthTesterMenuItemDhcpAnalyze, eth_tester_submenu_callback, app);
    submenu_add_item(app->submenu_cat_netinfo, "Statistics", EthTesterMenuItemStats, eth_tester_submenu_callback, app);
    view_set_previous_callback(submenu_get_view(app->submenu_cat_netinfo), eth_tester_navigation_submenu_callback);
    view_dispatcher_add_view(app->view_dispatcher, EthTesterViewCatNetInfo, submenu_get_view(app->submenu_cat_netinfo));

    /* Category: Discovery */
    app->submenu_cat_discovery = submenu_alloc();
    submenu_add_item(app->submenu_cat_discovery, "ARP Scan", EthTesterMenuItemArpScan, eth_tester_submenu_callback, app);
    submenu_add_item(app->submenu_cat_discovery, "Ping Sweep", EthTesterMenuItemPingSweep, eth_tester_submenu_callback, app);
    submenu_add_item(app->submenu_cat_discovery, "LLDP/CDP", EthTesterMenuItemLldpCdp, eth_tester_submenu_callback, app);
    submenu_add_item(app->submenu_cat_discovery, "mDNS/SSDP", EthTesterMenuItemDiscovery, eth_tester_submenu_callback, app);
    submenu_add_item(app->submenu_cat_discovery, "STP/VLAN", EthTesterMenuItemStpVlan, eth_tester_submenu_callback, app);
    view_set_previous_callback(submenu_get_view(app->submenu_cat_discovery), eth_tester_navigation_submenu_callback);
    view_dispatcher_add_view(app->view_dispatcher, EthTesterViewCatDiscovery, submenu_get_view(app->submenu_cat_discovery));

    /* Category: Diagnostics */
    app->submenu_cat_diag = submenu_alloc();
    submenu_add_item(app->submenu_cat_diag, "Ping", EthTesterMenuItemPing, eth_tester_submenu_callback, app);
    submenu_add_item(app->submenu_cat_diag, "Continuous Ping", EthTesterMenuItemContPing, eth_tester_submenu_callback, app);
    submenu_add_item(app->submenu_cat_diag, "DNS Lookup", EthTesterMenuItemDnsLookup, eth_tester_submenu_callback, app);
    submenu_add_item(app->submenu_cat_diag, "Traceroute", EthTesterMenuItemTraceroute, eth_tester_submenu_callback, app);
    submenu_add_item(app->submenu_cat_diag, "Port Scan (Top 20)", EthTesterMenuItemPortScan, eth_tester_submenu_callback, app);
    submenu_add_item(app->submenu_cat_diag, "Port Scan (Top 100)", EthTesterMenuItemPortScanFull, eth_tester_submenu_callback, app);
    view_set_previous_callback(submenu_get_view(app->submenu_cat_diag), eth_tester_navigation_submenu_callback);
    view_dispatcher_add_view(app->view_dispatcher, EthTesterViewCatDiag, submenu_get_view(app->submenu_cat_diag));

    /* Category: Tools */
    app->submenu_cat_tools = submenu_alloc();
    submenu_add_item(app->submenu_cat_tools, "Wake-on-LAN", EthTesterMenuItemWol, eth_tester_submenu_callback, app);
    submenu_add_item(app->submenu_cat_tools, "MAC Changer", EthTesterMenuItemMacChanger, eth_tester_submenu_callback, app);
    submenu_add_item(app->submenu_cat_tools, "ETH Bridge", EthTesterMenuItemEthBridge, eth_tester_submenu_callback, app);
    view_set_previous_callback(submenu_get_view(app->submenu_cat_tools), eth_tester_navigation_submenu_callback);
    view_dispatcher_add_view(app->view_dispatcher, EthTesterViewCatTools, submenu_get_view(app->submenu_cat_tools));

    /* TextBox views for each feature */
    app->text_box_link = text_box_alloc();
    text_box_set_font(app->text_box_link, TextBoxFontText);
    view_set_previous_callback(text_box_get_view(app->text_box_link), eth_tester_nav_back_netinfo);
    view_dispatcher_add_view(app->view_dispatcher, EthTesterViewLinkInfo, text_box_get_view(app->text_box_link));

    app->text_box_lldp = text_box_alloc();
    text_box_set_font(app->text_box_lldp, TextBoxFontText);
    view_set_previous_callback(text_box_get_view(app->text_box_lldp), eth_tester_nav_back_discovery);
    view_dispatcher_add_view(app->view_dispatcher, EthTesterViewLldp, text_box_get_view(app->text_box_lldp));

    app->text_box_arp = text_box_alloc();
    text_box_set_font(app->text_box_arp, TextBoxFontText);
    view_set_previous_callback(text_box_get_view(app->text_box_arp), eth_tester_nav_back_discovery);
    view_dispatcher_add_view(app->view_dispatcher, EthTesterViewArpScan, text_box_get_view(app->text_box_arp));

    app->text_box_dhcp = text_box_alloc();
    text_box_set_font(app->text_box_dhcp, TextBoxFontText);
    view_set_previous_callback(text_box_get_view(app->text_box_dhcp), eth_tester_nav_back_netinfo);
    view_dispatcher_add_view(app->view_dispatcher, EthTesterViewDhcpAnalyze, text_box_get_view(app->text_box_dhcp));

    app->text_box_ping = text_box_alloc();
    text_box_set_font(app->text_box_ping, TextBoxFontText);
    view_set_previous_callback(text_box_get_view(app->text_box_ping), eth_tester_nav_back_diag);
    view_dispatcher_add_view(app->view_dispatcher, EthTesterViewPing, text_box_get_view(app->text_box_ping));

    app->text_box_stats = text_box_alloc();
    text_box_set_font(app->text_box_stats, TextBoxFontText);
    view_set_previous_callback(text_box_get_view(app->text_box_stats), eth_tester_nav_back_netinfo);
    view_dispatcher_add_view(app->view_dispatcher, EthTesterViewStats, text_box_get_view(app->text_box_stats));

    /* IP Keyboard (shared custom view for all IP address inputs) */
    app->ip_keyboard = ip_keyboard_alloc();
    view_dispatcher_add_view(app->view_dispatcher, EthTesterViewIpKeyboard, ip_keyboard_get_view(app->ip_keyboard));

    /* Default ping target */
    strncpy(app->ping_ip_input, "8.8.8.8", sizeof(app->ping_ip_input));

    /* DNS Lookup views */
    app->text_box_dns = text_box_alloc();
    text_box_set_font(app->text_box_dns, TextBoxFontText);
    view_set_previous_callback(text_box_get_view(app->text_box_dns), eth_tester_nav_back_diag);
    view_dispatcher_add_view(app->view_dispatcher, EthTesterViewDnsLookup, text_box_get_view(app->text_box_dns));

    app->text_input_dns = text_input_alloc();
    view_set_previous_callback(text_input_get_view(app->text_input_dns), eth_tester_nav_back_diag);
    view_dispatcher_add_view(app->view_dispatcher, EthTesterViewDnsInput, text_input_get_view(app->text_input_dns));

    /* Default DNS hostname */
    strncpy(app->dns_hostname_input, "google.com", sizeof(app->dns_hostname_input));

    /* Wake-on-LAN views */
    app->text_box_wol = text_box_alloc();
    text_box_set_font(app->text_box_wol, TextBoxFontText);
    view_set_previous_callback(text_box_get_view(app->text_box_wol), eth_tester_nav_back_tools);
    view_dispatcher_add_view(app->view_dispatcher, EthTesterViewWol, text_box_get_view(app->text_box_wol));

    app->byte_input_wol = byte_input_alloc();
    view_set_previous_callback(byte_input_get_view(app->byte_input_wol), eth_tester_nav_back_tools);
    view_dispatcher_add_view(app->view_dispatcher, EthTesterViewWolInput, byte_input_get_view(app->byte_input_wol));

    /* Continuous Ping views */
    app->view_cont_ping = view_alloc();
    view_allocate_model(app->view_cont_ping, ViewModelTypeLocking, sizeof(ContPingViewModel));
    view_set_draw_callback(app->view_cont_ping, cont_ping_draw_callback);
    view_set_input_callback(app->view_cont_ping, cont_ping_input_callback);
    view_set_context(app->view_cont_ping, app);
    with_view_model(
        app->view_cont_ping,
        ContPingViewModel* vm,
        { vm->app = app; },
        false);
    view_dispatcher_add_view(app->view_dispatcher, EthTesterViewContPing, app->view_cont_ping);

    /* Default continuous ping target */
    strncpy(app->cont_ping_ip_input, "8.8.8.8", sizeof(app->cont_ping_ip_input));

    /* Port Scanner views */
    app->text_box_port_scan = text_box_alloc();
    text_box_set_font(app->text_box_port_scan, TextBoxFontText);
    view_set_previous_callback(text_box_get_view(app->text_box_port_scan), eth_tester_nav_back_diag);
    view_dispatcher_add_view(app->view_dispatcher, EthTesterViewPortScan, text_box_get_view(app->text_box_port_scan));

    /* Port scan target defaults to empty — filled from DHCP gateway when available */
    app->port_scan_ip_input[0] = '\0';

    /* MAC Changer views */
    app->text_box_mac_changer = text_box_alloc();
    text_box_set_font(app->text_box_mac_changer, TextBoxFontText);
    view_set_previous_callback(text_box_get_view(app->text_box_mac_changer), eth_tester_nav_back_tools);
    view_dispatcher_add_view(app->view_dispatcher, EthTesterViewMacChanger, text_box_get_view(app->text_box_mac_changer));

    app->byte_input_mac_changer = byte_input_alloc();
    view_set_previous_callback(byte_input_get_view(app->byte_input_mac_changer), eth_tester_nav_back_tools);
    view_dispatcher_add_view(app->view_dispatcher, EthTesterViewMacChangerInput, byte_input_get_view(app->byte_input_mac_changer));

    /* ETH Bridge view (custom View with draw_callback, no TextBox) */
    app->view_bridge = view_alloc();
    view_allocate_model(app->view_bridge, ViewModelTypeLocking, sizeof(BridgeViewModel));
    view_set_draw_callback(app->view_bridge, bridge_draw_callback);
    view_set_input_callback(app->view_bridge, bridge_input_callback);
    view_set_context(app->view_bridge, app);
    view_set_previous_callback(app->view_bridge, eth_tester_nav_back_tools);
    with_view_model(
        app->view_bridge,
        BridgeViewModel* vm,
        {
            vm->app = app;
            vm->status_line = "Starting...";
        },
        false);
    view_dispatcher_add_view(app->view_dispatcher, EthTesterViewEthBridge, app->view_bridge);
    app->bridge_state = malloc(sizeof(EthBridgeState));

    /* Traceroute views */
    app->text_box_traceroute = text_box_alloc();
    text_box_set_font(app->text_box_traceroute, TextBoxFontText);
    view_set_previous_callback(text_box_get_view(app->text_box_traceroute), eth_tester_nav_back_diag);
    view_dispatcher_add_view(app->view_dispatcher, EthTesterViewTraceroute, text_box_get_view(app->text_box_traceroute));

    /* Default traceroute target */
    strncpy(app->traceroute_ip_input, "8.8.8.8", sizeof(app->traceroute_ip_input));

    /* Ping Sweep views */
    app->text_box_ping_sweep = text_box_alloc();
    text_box_set_font(app->text_box_ping_sweep, TextBoxFontText);
    view_set_previous_callback(text_box_get_view(app->text_box_ping_sweep), eth_tester_nav_back_discovery);
    view_dispatcher_add_view(app->view_dispatcher, EthTesterViewPingSweep, text_box_get_view(app->text_box_ping_sweep));

    /* Ping sweep defaults to empty — auto-detected from DHCP at scan time */
    app->ping_sweep_ip_input[0] = '\0';

    /* mDNS/SSDP Discovery view */
    app->text_box_discovery = text_box_alloc();
    text_box_set_font(app->text_box_discovery, TextBoxFontText);
    view_set_previous_callback(text_box_get_view(app->text_box_discovery), eth_tester_nav_back_discovery);
    view_dispatcher_add_view(app->view_dispatcher, EthTesterViewDiscovery, text_box_get_view(app->text_box_discovery));

    /* History views */
    app->submenu_history = submenu_alloc();
    view_set_previous_callback(submenu_get_view(app->submenu_history), eth_tester_navigation_submenu_callback);
    view_dispatcher_add_view(app->view_dispatcher, EthTesterViewHistory, submenu_get_view(app->submenu_history));
    app->history_state = NULL;

    app->text_box_history_file = text_box_alloc();
    text_box_set_font(app->text_box_history_file, TextBoxFontText);
    view_set_previous_callback(text_box_get_view(app->text_box_history_file), eth_tester_navigation_history_callback);
    view_dispatcher_add_view(app->view_dispatcher, EthTesterViewHistoryFile, text_box_get_view(app->text_box_history_file));

    /* STP/VLAN Detection view */
    app->text_box_stp_vlan = text_box_alloc();
    text_box_set_font(app->text_box_stp_vlan, TextBoxFontText);
    view_set_previous_callback(text_box_get_view(app->text_box_stp_vlan), eth_tester_nav_back_discovery);
    view_dispatcher_add_view(app->view_dispatcher, EthTesterViewStpVlan, text_box_get_view(app->text_box_stp_vlan));

    /* About view */
    app->text_box_about = text_box_alloc();
    text_box_set_font(app->text_box_about, TextBoxFontText);
    text_box_set_text(app->text_box_about,
        "[LAN Analyzer]\n\n"
        "Ethernet network analysis\n"
        "tool for Flipper Zero\n"
        "using W5500 SPI module.\n\n"
        "Scan, ping, trace,\n"
        "discover devices,\n"
        "analyze DHCP/LLDP/CDP,\n"
        "detect VLANs and STP.\n\n"
        "v0.9 | by dok2d\n"
        "github.com/dok2d/\n"
        "fz-W5500-lan-analyse\n");
    view_set_previous_callback(text_box_get_view(app->text_box_about), eth_tester_navigation_submenu_callback);
    view_dispatcher_add_view(app->view_dispatcher, EthTesterViewAbout, text_box_get_view(app->text_box_about));

    /* Settings view (VariableItemList) */
    app->settings_list = variable_item_list_alloc();
    view_set_previous_callback(
        variable_item_list_get_view(app->settings_list),
        eth_tester_navigation_submenu_callback);
    view_dispatcher_add_view(
        app->view_dispatcher, EthTesterViewSettings,
        variable_item_list_get_view(app->settings_list));

    VariableItem* item_autosave = variable_item_list_add(
        app->settings_list, "Auto-save results", 2, settings_autosave_changed, app);
    VariableItem* item_sound = variable_item_list_add(
        app->settings_list, "Sound & vibro", 2, settings_sound_changed, app);

    /* "Clear History" — no value cycling, action on OK press */
    VariableItem* item_clear = variable_item_list_add(
        app->settings_list, "Clear History", 0, NULL, app);
    variable_item_set_current_value_text(item_clear, "Press OK");
    variable_item_list_set_enter_callback(
        app->settings_list, settings_enter_callback, app);

    /* Load settings from SD */
    eth_tester_settings_load(app);
    variable_item_set_current_value_index(item_autosave, app->setting_autosave ? 1 : 0);
    variable_item_set_current_value_text(item_autosave, setting_onoff[app->setting_autosave ? 1 : 0]);
    variable_item_set_current_value_index(item_sound, app->setting_sound ? 1 : 0);
    variable_item_set_current_value_text(item_sound, setting_onoff[app->setting_sound ? 1 : 0]);

    /* Load saved MAC from SD card if available */
    if(mac_changer_load(app->mac_addr)) {
        FURI_LOG_I(TAG, "Loaded custom MAC from SD");
    }

    return app;
}

static void eth_tester_app_free(EthTesterApp* app) {
    furi_assert(app);

    /* Stop worker thread */
    eth_tester_worker_stop(app);

    /* Remove and free views */
    view_dispatcher_remove_view(app->view_dispatcher, EthTesterViewMainMenu);
    view_dispatcher_remove_view(app->view_dispatcher, EthTesterViewLinkInfo);
    view_dispatcher_remove_view(app->view_dispatcher, EthTesterViewLldp);
    view_dispatcher_remove_view(app->view_dispatcher, EthTesterViewArpScan);
    view_dispatcher_remove_view(app->view_dispatcher, EthTesterViewDhcpAnalyze);
    view_dispatcher_remove_view(app->view_dispatcher, EthTesterViewPing);
    view_dispatcher_remove_view(app->view_dispatcher, EthTesterViewStats);
    view_dispatcher_remove_view(app->view_dispatcher, EthTesterViewDnsLookup);
    view_dispatcher_remove_view(app->view_dispatcher, EthTesterViewDnsInput);
    view_dispatcher_remove_view(app->view_dispatcher, EthTesterViewWol);
    view_dispatcher_remove_view(app->view_dispatcher, EthTesterViewWolInput);
    view_dispatcher_remove_view(app->view_dispatcher, EthTesterViewContPing);
    view_dispatcher_remove_view(app->view_dispatcher, EthTesterViewPortScan);
    view_dispatcher_remove_view(app->view_dispatcher, EthTesterViewMacChanger);
    view_dispatcher_remove_view(app->view_dispatcher, EthTesterViewMacChangerInput);
    view_dispatcher_remove_view(app->view_dispatcher, EthTesterViewTraceroute);
    view_dispatcher_remove_view(app->view_dispatcher, EthTesterViewPingSweep);
    view_dispatcher_remove_view(app->view_dispatcher, EthTesterViewIpKeyboard);
    view_dispatcher_remove_view(app->view_dispatcher, EthTesterViewDiscovery);
    view_dispatcher_remove_view(app->view_dispatcher, EthTesterViewStpVlan);
    view_dispatcher_remove_view(app->view_dispatcher, EthTesterViewHistory);
    view_dispatcher_remove_view(app->view_dispatcher, EthTesterViewHistoryFile);
    view_dispatcher_remove_view(app->view_dispatcher, EthTesterViewAbout);
    view_dispatcher_remove_view(app->view_dispatcher, EthTesterViewCatNetInfo);
    view_dispatcher_remove_view(app->view_dispatcher, EthTesterViewCatDiscovery);
    view_dispatcher_remove_view(app->view_dispatcher, EthTesterViewCatDiag);
    view_dispatcher_remove_view(app->view_dispatcher, EthTesterViewCatTools);
    view_dispatcher_remove_view(app->view_dispatcher, EthTesterViewSettings);
    view_dispatcher_remove_view(app->view_dispatcher, EthTesterViewEthBridge);

    submenu_free(app->submenu);
    submenu_free(app->submenu_cat_netinfo);
    submenu_free(app->submenu_cat_discovery);
    submenu_free(app->submenu_cat_diag);
    submenu_free(app->submenu_cat_tools);
    variable_item_list_free(app->settings_list);
    text_box_free(app->text_box_link);
    text_box_free(app->text_box_lldp);
    text_box_free(app->text_box_arp);
    text_box_free(app->text_box_dhcp);
    text_box_free(app->text_box_ping);
    text_box_free(app->text_box_stats);
    text_box_free(app->text_box_dns);
    text_input_free(app->text_input_dns);
    text_box_free(app->text_box_wol);
    byte_input_free(app->byte_input_wol);
    view_free(app->view_cont_ping);
    text_box_free(app->text_box_port_scan);
    text_box_free(app->text_box_mac_changer);
    byte_input_free(app->byte_input_mac_changer);
    view_free(app->view_bridge);
    if(app->bridge_state) free(app->bridge_state);
    text_box_free(app->text_box_traceroute);
    text_box_free(app->text_box_ping_sweep);
    ip_keyboard_free(app->ip_keyboard);
    text_box_free(app->text_box_discovery);
    text_box_free(app->text_box_stp_vlan);
    submenu_free(app->submenu_history);
    text_box_free(app->text_box_history_file);
    if(app->history_state) free(app->history_state);
    text_box_free(app->text_box_about);

    view_dispatcher_free(app->view_dispatcher);

    /* Free text buffers */
    furi_string_free(app->link_info_text);
    furi_string_free(app->lldp_text);
    furi_string_free(app->arp_text);
    furi_string_free(app->dhcp_text);
    furi_string_free(app->ping_text);
    furi_string_free(app->stats_text);
    furi_string_free(app->dns_text);
    furi_string_free(app->wol_text);
    furi_string_free(app->port_scan_text);
    furi_string_free(app->mac_changer_text);
    furi_string_free(app->traceroute_text);
    furi_string_free(app->ping_sweep_text);
    furi_string_free(app->discovery_text);
    furi_string_free(app->stp_vlan_text);
    /* history_text removed — history now uses submenu */
    furi_string_free(app->history_file_text);

    /* Stop and free DHCP timer */
    furi_timer_stop(app->dhcp_timer);
    furi_timer_free(app->dhcp_timer);

    /* Deinit W5500 if initialized */
    if(app->w5500_initialized) {
        w5500_hal_deinit();
    }

    furi_record_close(RECORD_GUI);
    furi_record_close(RECORD_NOTIFICATION);

    free(app->frame_buf);
    g_app = NULL;
    free(app);
}

/* ==================== Navigation callbacks ==================== */

/* Update main menu header with link status */
static void eth_tester_update_menu_header(EthTesterApp* app) {
    if(app->w5500_initialized) {
        bool link = w5500_hal_get_link_status();
        if(link) {
            uint8_t speed = 0, duplex = 0;
            bool up = false;
            w5500_hal_get_phy_info(&up, &speed, &duplex);
            submenu_set_header(app->submenu,
                speed ? (duplex ? "LAN [UP 100M FD]" : "LAN [UP 100M HD]")
                      : (duplex ? "LAN [UP 10M FD]" : "LAN [UP 10M HD]"));
        } else {
            submenu_set_header(app->submenu, "LAN [NO LINK]");
        }
    } else {
        submenu_set_header(app->submenu, "LAN Tester");
    }
}

static uint32_t eth_tester_navigation_exit_callback(void* context) {
    UNUSED(context);
    return VIEW_NONE;
}

/* Stop worker helper used by all back-navigation callbacks */
static void eth_tester_stop_worker_on_back(void) {
    if(g_app) {
        if(g_app->worker_thread &&
           furi_thread_get_state(g_app->worker_thread) != FuriThreadStateStopped) {
            submenu_set_header(g_app->submenu, "Stopping...");
        }
        g_app->worker_running = false;
        eth_tester_update_menu_header(g_app);
    }
}

static uint32_t eth_tester_navigation_submenu_callback(void* context) {
    UNUSED(context);
    eth_tester_stop_worker_on_back();
    return EthTesterViewMainMenu;
}

static uint32_t eth_tester_nav_back_netinfo(void* context) {
    UNUSED(context);
    eth_tester_stop_worker_on_back();
    return EthTesterViewCatNetInfo;
}

static uint32_t eth_tester_nav_back_discovery(void* context) {
    UNUSED(context);
    eth_tester_stop_worker_on_back();
    return EthTesterViewCatDiscovery;
}

static uint32_t eth_tester_nav_back_diag(void* context) {
    UNUSED(context);
    eth_tester_stop_worker_on_back();
    return EthTesterViewCatDiag;
}

static uint32_t eth_tester_nav_back_tools(void* context) {
    UNUSED(context);
    eth_tester_stop_worker_on_back();
    return EthTesterViewCatTools;
}

static uint32_t eth_tester_navigation_history_callback(void* context) {
    UNUSED(context);
    return EthTesterViewHistory;
}

/* ==================== Worker thread ==================== */

/* Navigation event callback: stop worker on app exit */
static bool eth_tester_nav_event_cb(void* context) {
    EthTesterApp* app = context;
    /* Stop any running worker before exiting */
    eth_tester_worker_stop(app);
    return false; /* Allow app to exit */
}

static void eth_tester_ping_sweep_input_callback(void* context);

static bool eth_tester_custom_event_cb(void* context, uint32_t event) {
    EthTesterApp* app = context;

    if(event == CUSTOM_EVENT_PING_SWEEP_READY) {
        /* DHCP detection done — show input with pre-filled CIDR */
        ip_keyboard_setup(
            app->ip_keyboard,
            "Scan range (CIDR):",
            app->ping_sweep_ip_input,
            true,
            eth_tester_ping_sweep_input_callback,
            app,
            app->ping_sweep_ip_input,
            sizeof(app->ping_sweep_ip_input),
            eth_tester_nav_back_discovery);
        view_dispatcher_switch_to_view(app->view_dispatcher, EthTesterViewIpKeyboard);
        return true;
    }

    return false;
}

static int32_t eth_tester_worker_fn(void* context) {
    EthTesterApp* app = context;

    /* Dispatch to the appropriate operation */
    switch(app->worker_op) {
    case EthTesterMenuItemLinkInfo:
        eth_tester_do_link_info(app);
        eth_tester_update_view(app->text_box_link, app->link_info_text);
        break;
    case EthTesterMenuItemLldpCdp:
        eth_tester_do_lldp_cdp(app);
        eth_tester_update_view(app->text_box_lldp, app->lldp_text);
        break;
    case EthTesterMenuItemArpScan:
        eth_tester_do_arp_scan(app);
        eth_tester_update_view(app->text_box_arp, app->arp_text);
        break;
    case EthTesterMenuItemDhcpAnalyze:
        eth_tester_do_dhcp_analyze(app);
        eth_tester_update_view(app->text_box_dhcp, app->dhcp_text);
        break;
    case EthTesterMenuItemPing:
        eth_tester_do_ping(app);
        eth_tester_update_view(app->text_box_ping, app->ping_text);
        break;
    case EthTesterMenuItemStats:
        eth_tester_do_stats(app);
        eth_tester_update_view(app->text_box_stats, app->stats_text);
        break;
    case EthTesterMenuItemDnsLookup:
        eth_tester_do_dns_lookup(app);
        eth_tester_update_view(app->text_box_dns, app->dns_text);
        break;
    case EthTesterMenuItemWol:
        eth_tester_do_wol(app);
        eth_tester_update_view(app->text_box_wol, app->wol_text);
        break;
    case EthTesterMenuItemContPing:
        eth_tester_do_cont_ping(app);
        break; /* Uses custom view, not TextBox */
    case EthTesterMenuItemPortScan:
        eth_tester_do_port_scan(app);
        eth_tester_update_view(app->text_box_port_scan, app->port_scan_text);
        break;
    case EthTesterMenuItemMacChanger:
        eth_tester_do_mac_changer(app);
        eth_tester_update_view(app->text_box_mac_changer, app->mac_changer_text);
        break;
    case EthTesterMenuItemTraceroute:
        eth_tester_do_traceroute(app);
        eth_tester_update_view(app->text_box_traceroute, app->traceroute_text);
        break;
    case EthTesterMenuItemPingSweep:
        eth_tester_do_ping_sweep(app);
        eth_tester_update_view(app->text_box_ping_sweep, app->ping_sweep_text);
        break;
    case EthTesterMenuItemDiscovery:
        eth_tester_do_discovery(app);
        eth_tester_update_view(app->text_box_discovery, app->discovery_text);
        break;
    case EthTesterMenuItemStpVlan:
        eth_tester_do_stp_vlan(app);
        eth_tester_update_view(app->text_box_stp_vlan, app->stp_vlan_text);
        break;
    case EthTesterMenuItemEthBridge:
        eth_tester_do_eth_bridge(app);
        break; /* Uses custom view, not TextBox */
    case EthTesterMenuItemHistory:
        break; /* History uses synchronous submenu, no worker needed */
    case WORKER_OP_PING_SWEEP_DETECT:
        eth_tester_do_ping_sweep_detect(app);
        break;
    default:
        break;
    }
    return 0;
}

static void eth_tester_worker_stop(EthTesterApp* app) {
    if(app->worker_thread) {
        app->worker_running = false;
        furi_thread_join(app->worker_thread);
        furi_thread_free(app->worker_thread);
        app->worker_thread = NULL;
    }
}

static void eth_tester_worker_start(EthTesterApp* app, uint32_t op, EthTesterView result_view) {
    /* If old worker is done, clean it up (non-blocking) */
    if(app->worker_thread) {
        app->worker_running = false;
        if(furi_thread_get_state(app->worker_thread) == FuriThreadStateStopped) {
            furi_thread_join(app->worker_thread);
            furi_thread_free(app->worker_thread);
            app->worker_thread = NULL;
        } else {
            /* Old worker still running — force stop and wait (brief) */
            furi_thread_join(app->worker_thread);
            furi_thread_free(app->worker_thread);
            app->worker_thread = NULL;
        }
    }

    app->worker_op = op;
    app->worker_running = true;

    /* Switch to result view BEFORE starting thread */
    view_dispatcher_switch_to_view(app->view_dispatcher, result_view);

    app->worker_thread = furi_thread_alloc_ex("EthWorker", 8 * 1024,
        eth_tester_worker_fn, app);
    furi_thread_start(app->worker_thread);
}

/* ==================== W5500 initialization helper ==================== */

static bool eth_tester_ensure_w5500(EthTesterApp* app) {
    if(app->w5500_initialized) return true;

    FURI_LOG_I(TAG, "Initializing W5500...");

    if(!w5500_hal_init()) {
        FURI_LOG_E(TAG, "W5500 HAL init failed");
        return false;
    }

    w5500_hal_hw_reset();

    if(!w5500_hal_chip_init()) {
        FURI_LOG_E(TAG, "W5500 chip init failed");
        w5500_hal_deinit();
        return false;
    }

    if(!w5500_hal_check_version()) {
        FURI_LOG_E(TAG, "W5500 not found (bad VERSIONR)");
        w5500_hal_deinit();
        return false;
    }

    w5500_hal_set_mac(app->mac_addr);
    app->w5500_initialized = true;

    FURI_LOG_I(TAG, "W5500 initialized successfully");
    return true;
}

/* ==================== Shared DHCP helper ==================== */

/**
 * Ensure we have a valid DHCP lease. Returns true if dhcp_valid.
 * Uses cached result if available; only runs DHCP once per session
 * (or after link state change).
 */
static bool eth_tester_ensure_dhcp(EthTesterApp* app) {
    if(!eth_tester_ensure_w5500(app)) {
        if(app->setting_sound) notification_message(app->notifications, &sequence_error);
        return false;
    }

    if(!w5500_hal_get_link_status()) {
        if(app->setting_sound) notification_message(app->notifications, &sequence_error);
        return false;
    }

    /* Use cached DHCP if available */
    if(app->dhcp_valid) {
        /* Re-apply cached network config to W5500 */
        wiz_NetInfo net_info;
        wizchip_getnetinfo(&net_info);
        memcpy(net_info.ip, app->dhcp_ip, 4);
        memcpy(net_info.sn, app->dhcp_mask, 4);
        memcpy(net_info.gw, app->dhcp_gw, 4);
        memcpy(net_info.dns, app->dhcp_dns, 4);
        net_info.dhcp = NETINFO_DHCP;
        wizchip_setnetinfo(&net_info);
        return true;
    }

    /* Run DHCP */
    uint8_t* dhcp_buffer = malloc(1024);
    if(!dhcp_buffer) return false;

    wiz_NetInfo net_info;
    wizchip_getnetinfo(&net_info);
    net_info.dhcp = NETINFO_DHCP;
    memset(net_info.ip, 0, 4);
    memset(net_info.sn, 0, 4);
    memset(net_info.gw, 0, 4);
    wizchip_setnetinfo(&net_info);

    DHCP_init(W5500_DHCP_SOCKET, dhcp_buffer);

    bool got_ip = false;
    uint32_t dhcp_start = furi_get_tick();
    while(furi_get_tick() - dhcp_start < 15000 && app->worker_running) {
        uint8_t dhcp_ret = DHCP_run();
        if(dhcp_ret == DHCP_IP_LEASED || dhcp_ret == DHCP_IP_ASSIGN ||
           dhcp_ret == DHCP_IP_CHANGED) {
            getIPfromDHCP(net_info.ip);
            getSNfromDHCP(net_info.sn);
            getGWfromDHCP(net_info.gw);
            getDNSfromDHCP(net_info.dns);
            net_info.dhcp = NETINFO_DHCP;
            wizchip_setnetinfo(&net_info);
            got_ip = true;

            memcpy(app->dhcp_ip, net_info.ip, 4);
            memcpy(app->dhcp_mask, net_info.sn, 4);
            memcpy(app->dhcp_gw, net_info.gw, 4);
            memcpy(app->dhcp_dns, net_info.dns, 4);
            app->dhcp_valid = true;
            break;
        }
        if(dhcp_ret == DHCP_FAILED) break;
        furi_delay_ms(10);
    }
    DHCP_stop();
    free(dhcp_buffer);

    if(!got_ip && app->setting_sound) {
        notification_message(app->notifications, &sequence_error);
    }

    return got_ip;
}

/* ==================== ASCII progress bar ==================== */

/**
 * Generate an ASCII progress bar like "[=========>    ] 75%"
 * buf must be at least 28 bytes.
 */
static void eth_tester_progress_bar(char* buf, size_t buf_size, uint16_t current, uint16_t total) {
    if(total == 0) total = 1;
    uint8_t pct = (uint8_t)((current * 100) / total);
    uint8_t filled = (uint8_t)((current * 16) / total);
    if(filled > 16) filled = 16;
    char bar[18];
    for(uint8_t i = 0; i < 16; i++) {
        bar[i] = (i < filled) ? '#' : '.';
    }
    bar[16] = '\0';
    snprintf(buf, buf_size, "[%s] %d%%", bar, pct);
}

/* ==================== View update helpers ==================== */

static void eth_tester_show_view(EthTesterApp* app, TextBox* tb, EthTesterView view, FuriString* text, const char* initial) {
    furi_string_set(text, initial);
    text_box_set_text(tb, furi_string_get_cstr(text));
    view_dispatcher_switch_to_view(app->view_dispatcher, view);
    furi_delay_ms(1);
}

static void eth_tester_update_view(TextBox* tb, FuriString* text) {
    text_box_set_text(tb, furi_string_get_cstr(text));
    furi_delay_ms(1);
}

/* ==================== Ping IP input callback ==================== */

static bool eth_tester_parse_ip(const char* str, uint8_t ip[4]) {
    unsigned int a, b, c, d;
    if(sscanf(str, "%u.%u.%u.%u", &a, &b, &c, &d) != 4) return false;
    if(a > 255 || b > 255 || c > 255 || d > 255) return false;
    ip[0] = (uint8_t)a;
    ip[1] = (uint8_t)b;
    ip[2] = (uint8_t)c;
    ip[3] = (uint8_t)d;
    return true;
}

static void eth_tester_ping_ip_input_callback(void* context) {
    EthTesterApp* app = context;
    furi_assert(app);

    if(eth_tester_parse_ip(app->ping_ip_input, app->ping_ip_custom)) {
        furi_string_set(app->ping_text, "Initializing...\n");
        text_box_set_text(app->text_box_ping, furi_string_get_cstr(app->ping_text));
        eth_tester_worker_start(app, EthTesterMenuItemPing, EthTesterViewPing);
    } else {
        furi_string_set(app->ping_text, "Invalid IP address!\n");
        text_box_set_text(app->text_box_ping, furi_string_get_cstr(app->ping_text));
        view_dispatcher_switch_to_view(app->view_dispatcher, EthTesterViewPing);
    }
}

/* ==================== Continuous Ping IP input callback ==================== */

static void eth_tester_cont_ping_ip_input_callback(void* context) {
    EthTesterApp* app = context;
    furi_assert(app);

    if(!eth_tester_parse_ip(app->cont_ping_ip_input, app->cont_ping_target)) {
        view_dispatcher_switch_to_view(app->view_dispatcher, EthTesterViewMainMenu);
        return;
    }

    eth_tester_worker_start(app, EthTesterMenuItemContPing, EthTesterViewContPing);
}


/* ==================== Traceroute IP input callback ==================== */

static void eth_tester_traceroute_ip_input_callback(void* context) {
    EthTesterApp* app = context;
    furi_assert(app);

    if(!eth_tester_parse_ip(app->traceroute_ip_input, app->traceroute_target)) {
        furi_string_set(app->traceroute_text, "Invalid IP address!\n");
        text_box_set_text(app->text_box_traceroute, furi_string_get_cstr(app->traceroute_text));
        view_dispatcher_switch_to_view(app->view_dispatcher, EthTesterViewTraceroute);
        return;
    }

    furi_string_set(app->traceroute_text, "Initializing...\n");
    text_box_set_text(app->text_box_traceroute, furi_string_get_cstr(app->traceroute_text));
    eth_tester_worker_start(app, EthTesterMenuItemTraceroute, EthTesterViewTraceroute);
}

/* ==================== Port scan IP input callback ==================== */

static void eth_tester_port_scan_ip_input_callback(void* context) {
    EthTesterApp* app = context;
    furi_assert(app);

    if(!eth_tester_parse_ip(app->port_scan_ip_input, app->port_scan_target)) {
        furi_string_set(app->port_scan_text, "Invalid IP address!\n");
        text_box_set_text(app->text_box_port_scan, furi_string_get_cstr(app->port_scan_text));
        view_dispatcher_switch_to_view(app->view_dispatcher, EthTesterViewPortScan);
        return;
    }

    furi_string_set(app->port_scan_text, "Initializing...\n");
    text_box_set_text(app->text_box_port_scan, furi_string_get_cstr(app->port_scan_text));
    eth_tester_worker_start(app, EthTesterMenuItemPortScan, EthTesterViewPortScan);
}

/* ==================== Ping sweep CIDR input callback ==================== */

static void eth_tester_ping_sweep_input_callback(void* context) {
    EthTesterApp* app = context;
    furi_assert(app);

    furi_string_set(app->ping_sweep_text, "Starting ping sweep...\n");
    text_box_set_text(app->text_box_ping_sweep, furi_string_get_cstr(app->ping_sweep_text));
    eth_tester_worker_start(app, EthTesterMenuItemPingSweep, EthTesterViewPingSweep);
}

/* ==================== DNS hostname input callback ==================== */

static void eth_tester_dns_input_callback(void* context) {
    EthTesterApp* app = context;
    furi_assert(app);

    furi_string_set(app->dns_text, "Initializing...\n");
    text_box_set_text(app->text_box_dns, furi_string_get_cstr(app->dns_text));
    eth_tester_worker_start(app, EthTesterMenuItemDnsLookup, EthTesterViewDnsLookup);
}

/* ==================== MAC Changer input callback ==================== */

static void eth_tester_mac_changer_input_callback(void* context) {
    EthTesterApp* app = context;
    furi_assert(app);

    /* Apply the MAC from byte input */
    memcpy(app->mac_addr, app->mac_changer_input, 6);
    if(app->w5500_initialized) {
        w5500_hal_set_mac(app->mac_addr);
    }
    mac_changer_save(app->mac_addr);

    /* Invalidate DHCP cache since MAC changed */
    app->dhcp_valid = false;

    char new_mac_str[18];
    pkt_format_mac(app->mac_addr, new_mac_str);

    furi_string_printf(
        app->mac_changer_text,
        "MAC changed to:\n"
        "%s\n\n"
        "Saved to SD card.\n"
        "Full effect on next\n"
        "DHCP/reconnect.\n",
        new_mac_str);
    text_box_set_text(app->text_box_mac_changer, furi_string_get_cstr(app->mac_changer_text));
    view_dispatcher_switch_to_view(app->view_dispatcher, EthTesterViewMacChanger);
    if(app->setting_sound) notification_message(app->notifications, &sequence_success);
}

/* ==================== WoL MAC input callback ==================== */

static void eth_tester_wol_input_callback(void* context) {
    EthTesterApp* app = context;
    furi_assert(app);

    furi_string_set(app->wol_text, "Sending WoL...\n");
    text_box_set_text(app->text_box_wol, furi_string_get_cstr(app->wol_text));
    eth_tester_worker_start(app, EthTesterMenuItemWol, EthTesterViewWol);
}

/* ==================== Submenu callback ==================== */

static void eth_tester_submenu_callback(void* context, uint32_t index) {
    EthTesterApp* app = context;
    furi_assert(app);

    switch(index) {
    case EthTesterMenuItemLinkInfo:
        eth_tester_show_view(app, app->text_box_link, EthTesterViewLinkInfo, app->link_info_text, "Reading link status...\n");
        eth_tester_worker_start(app, EthTesterMenuItemLinkInfo, EthTesterViewLinkInfo);
        break;

    case EthTesterMenuItemLldpCdp:
        eth_tester_show_view(app, app->text_box_lldp, EthTesterViewLldp, app->lldp_text, "Listening for LLDP/CDP...\n");
        eth_tester_worker_start(app, EthTesterMenuItemLldpCdp, EthTesterViewLldp);
        break;

    case EthTesterMenuItemArpScan:
        eth_tester_show_view(app, app->text_box_arp, EthTesterViewArpScan, app->arp_text, "Initializing W5500...\n");
        eth_tester_worker_start(app, EthTesterMenuItemArpScan, EthTesterViewArpScan);
        break;

    case EthTesterMenuItemDhcpAnalyze:
        eth_tester_show_view(app, app->text_box_dhcp, EthTesterViewDhcpAnalyze, app->dhcp_text, "Initializing W5500...\n");
        eth_tester_worker_start(app, EthTesterMenuItemDhcpAnalyze, EthTesterViewDhcpAnalyze);
        break;

    case EthTesterMenuItemPing:
        /* Pre-populate with gateway if DHCP available and no custom target set */
        if(app->dhcp_valid && strcmp(app->ping_ip_input, "8.8.8.8") == 0) {
            snprintf(app->ping_ip_input, sizeof(app->ping_ip_input),
                "%d.%d.%d.%d", app->dhcp_gw[0], app->dhcp_gw[1], app->dhcp_gw[2], app->dhcp_gw[3]);
        }
        ip_keyboard_setup(
            app->ip_keyboard,
            "Ping target IP:",
            app->ping_ip_input,
            false,
            eth_tester_ping_ip_input_callback,
            app,
            app->ping_ip_input,
            sizeof(app->ping_ip_input),
            eth_tester_nav_back_diag);
        view_dispatcher_switch_to_view(app->view_dispatcher, EthTesterViewIpKeyboard);
        break;

    case EthTesterMenuItemStats:
        eth_tester_show_view(app, app->text_box_stats, EthTesterViewStats, app->stats_text, "Initializing W5500...\n");
        eth_tester_worker_start(app, EthTesterMenuItemStats, EthTesterViewStats);
        break;

    case EthTesterMenuItemDnsLookup:
        text_input_reset(app->text_input_dns);
        text_input_set_header_text(app->text_input_dns, "Hostname to resolve:");
        text_input_set_result_callback(
            app->text_input_dns,
            eth_tester_dns_input_callback,
            app,
            app->dns_hostname_input,
            sizeof(app->dns_hostname_input),
            false);
        view_dispatcher_switch_to_view(app->view_dispatcher, EthTesterViewDnsInput);
        break;

    case EthTesterMenuItemWol:
        byte_input_set_header_text(app->byte_input_wol, "Target MAC address:");
        byte_input_set_result_callback(
            app->byte_input_wol,
            eth_tester_wol_input_callback,
            NULL,
            app,
            app->wol_mac_input,
            6);
        view_dispatcher_switch_to_view(app->view_dispatcher, EthTesterViewWolInput);
        break;

    case EthTesterMenuItemHistory:
        eth_tester_history_populate(app);
        view_dispatcher_switch_to_view(app->view_dispatcher, EthTesterViewHistory);
        break;

    case EthTesterMenuItemStpVlan:
        eth_tester_show_view(app, app->text_box_stp_vlan, EthTesterViewStpVlan, app->stp_vlan_text, "Listening...\n");
        eth_tester_worker_start(app, EthTesterMenuItemStpVlan, EthTesterViewStpVlan);
        break;

    case EthTesterMenuItemDiscovery:
        eth_tester_show_view(app, app->text_box_discovery, EthTesterViewDiscovery, app->discovery_text, "Scanning...\n");
        eth_tester_worker_start(app, EthTesterMenuItemDiscovery, EthTesterViewDiscovery);
        break;

    case EthTesterMenuItemPingSweep:
        if(app->dhcp_valid) {
            /* Already have DHCP — go straight to input */
            uint8_t net[4];
            for(int i = 0; i < 4; i++) net[i] = app->dhcp_ip[i] & app->dhcp_mask[i];
            uint8_t pfx = arp_mask_to_prefix(app->dhcp_mask);
            snprintf(app->ping_sweep_ip_input, sizeof(app->ping_sweep_ip_input),
                "%d.%d.%d.%d/%d", net[0], net[1], net[2], net[3], pfx);
            ip_keyboard_setup(
                app->ip_keyboard,
                "Scan range (CIDR):",
                app->ping_sweep_ip_input,
                true,
                eth_tester_ping_sweep_input_callback,
                app,
                app->ping_sweep_ip_input,
                sizeof(app->ping_sweep_ip_input),
                eth_tester_nav_back_discovery);
            view_dispatcher_switch_to_view(app->view_dispatcher, EthTesterViewIpKeyboard);
        } else {
            /* No DHCP yet — detect network first, then show input */
            eth_tester_show_view(app, app->text_box_ping_sweep, EthTesterViewPingSweep, app->ping_sweep_text, "Detecting network...\n");
            eth_tester_worker_start(app, WORKER_OP_PING_SWEEP_DETECT, EthTesterViewPingSweep);
        }
        break;

    case EthTesterMenuItemTraceroute:
        if(app->dhcp_valid && strcmp(app->traceroute_ip_input, "8.8.8.8") == 0) {
            snprintf(app->traceroute_ip_input, sizeof(app->traceroute_ip_input),
                "%d.%d.%d.%d", app->dhcp_gw[0], app->dhcp_gw[1], app->dhcp_gw[2], app->dhcp_gw[3]);
        }
        ip_keyboard_setup(
            app->ip_keyboard,
            "Traceroute target:",
            app->traceroute_ip_input,
            false,
            eth_tester_traceroute_ip_input_callback,
            app,
            app->traceroute_ip_input,
            sizeof(app->traceroute_ip_input),
            eth_tester_nav_back_diag);
        view_dispatcher_switch_to_view(app->view_dispatcher, EthTesterViewIpKeyboard);
        break;

    case EthTesterMenuItemMacChanger:
        /* Pre-fill with random MAC, user can edit before confirming */
        mac_changer_generate_random(app->mac_changer_input);
        byte_input_set_header_text(app->byte_input_mac_changer, "New MAC (edit or OK):");
        byte_input_set_result_callback(
            app->byte_input_mac_changer,
            eth_tester_mac_changer_input_callback,
            NULL,
            app,
            app->mac_changer_input,
            6);
        view_dispatcher_switch_to_view(app->view_dispatcher, EthTesterViewMacChangerInput);
        break;

    case EthTesterMenuItemPortScanFull:
        app->port_scan_top100 = true;
        /* fall through */
    case EthTesterMenuItemPortScan:
        if(index == EthTesterMenuItemPortScan) app->port_scan_top100 = false;
        /* Pre-populate target with DHCP gateway if available */
        if(app->dhcp_valid && (app->dhcp_gw[0] | app->dhcp_gw[1] | app->dhcp_gw[2] | app->dhcp_gw[3])) {
            snprintf(app->port_scan_ip_input, sizeof(app->port_scan_ip_input),
                "%d.%d.%d.%d", app->dhcp_gw[0], app->dhcp_gw[1], app->dhcp_gw[2], app->dhcp_gw[3]);
        }
        ip_keyboard_setup(
            app->ip_keyboard,
            app->port_scan_top100 ? "Target IP (Top 100):" : "Target IP (Top 20):",
            app->port_scan_ip_input,
            false,
            eth_tester_port_scan_ip_input_callback,
            app,
            app->port_scan_ip_input,
            sizeof(app->port_scan_ip_input),
            eth_tester_nav_back_diag);
        view_dispatcher_switch_to_view(app->view_dispatcher, EthTesterViewIpKeyboard);
        break;

    case EthTesterMenuItemContPing:
        if(app->dhcp_valid && strcmp(app->cont_ping_ip_input, "8.8.8.8") == 0) {
            snprintf(app->cont_ping_ip_input, sizeof(app->cont_ping_ip_input),
                "%d.%d.%d.%d", app->dhcp_gw[0], app->dhcp_gw[1], app->dhcp_gw[2], app->dhcp_gw[3]);
        }
        ip_keyboard_setup(
            app->ip_keyboard,
            "Ping target IP:",
            app->cont_ping_ip_input,
            false,
            eth_tester_cont_ping_ip_input_callback,
            app,
            app->cont_ping_ip_input,
            sizeof(app->cont_ping_ip_input),
            eth_tester_nav_back_diag);
        view_dispatcher_switch_to_view(app->view_dispatcher, EthTesterViewIpKeyboard);
        break;

    case EthTesterMenuItemEthBridge:
        with_view_model(
            app->view_bridge,
            BridgeViewModel* vm,
            {
                vm->active = false;
                vm->status_line = "Starting ETH Bridge...";
            },
            true);
        eth_tester_worker_start(app, EthTesterMenuItemEthBridge, EthTesterViewEthBridge);
        break;

    case EthTesterMenuItemAbout:
        view_dispatcher_switch_to_view(app->view_dispatcher, EthTesterViewAbout);
        break;

    case 100: /* Network Info category */
        view_dispatcher_switch_to_view(app->view_dispatcher, EthTesterViewCatNetInfo);
        break;
    case 101: /* Discovery category */
        view_dispatcher_switch_to_view(app->view_dispatcher, EthTesterViewCatDiscovery);
        break;
    case 102: /* Diagnostics category */
        view_dispatcher_switch_to_view(app->view_dispatcher, EthTesterViewCatDiag);
        break;
    case 103: /* Tools category */
        view_dispatcher_switch_to_view(app->view_dispatcher, EthTesterViewCatTools);
        break;
    case 104: /* Settings */
        view_dispatcher_switch_to_view(app->view_dispatcher, EthTesterViewSettings);
        break;

    default:
        break;
    }
}

/* ==================== Feature implementations ==================== */

static void eth_tester_do_link_info(EthTesterApp* app) {
    furi_string_reset(app->link_info_text);

    if(!eth_tester_ensure_w5500(app)) {
        furi_string_set(app->link_info_text, "W5500 Not Found!\nCheck SPI wiring.\n");
        return;
    }

    /* Read PHY info */
    bool link_up = false;
    uint8_t speed = 0, duplex = 0;
    w5500_hal_get_phy_info(&link_up, &speed, &duplex);
    app->link_up = link_up;
    app->link_speed = speed;
    app->link_duplex = duplex;

    /* Read current MAC */
    uint8_t mac[6];
    w5500_hal_get_mac(mac);

    char mac_str[18];
    pkt_format_mac(mac, mac_str);

    furi_string_printf(
        app->link_info_text,
        "[Link Info]\n"
        "Link: %s\n"
        "Speed: %s\n"
        "Duplex: %s\n"
        "MAC: %s\n"
        "W5500: OK (v0x04)\n",
        link_up ? "UP" : "DOWN",
        speed ? "100 Mbps" : "10 Mbps",
        duplex ? "Full" : "Half",
        mac_str);
}

static void eth_tester_do_lldp_cdp(EthTesterApp* app) {
    furi_string_reset(app->lldp_text);

    if(!eth_tester_ensure_w5500(app)) {
        furi_string_set(app->lldp_text, "W5500 Not Found!\n");
        return;
    }

    if(!w5500_hal_get_link_status()) {
        furi_string_set(app->lldp_text, "No Link!\nConnect cable.\n");
        return;
    }

    furi_string_set(app->lldp_text, "Listening for\nLLDP/CDP...\n(up to 60 sec)\n");
    eth_tester_update_view(app->text_box_lldp, app->lldp_text);

    /* Open MACRAW socket */
    if(!w5500_hal_open_macraw()) {
        furi_string_set(app->lldp_text, "Failed to open\nMACRAW socket!\n");
        return;
    }

    LldpNeighbor lldp_neighbor;
    CdpNeighbor cdp_neighbor;
    memset(&lldp_neighbor, 0, sizeof(lldp_neighbor));
    memset(&cdp_neighbor, 0, sizeof(cdp_neighbor));

    uint32_t start_tick = furi_get_tick();
    uint32_t timeout_ms = 60000; /* 60 seconds */
    bool found = false;
    uint32_t last_countdown = 0;

    while(furi_get_tick() - start_tick < timeout_ms && app->worker_running) {
        /* Update countdown every second */
        uint32_t elapsed_sec = (furi_get_tick() - start_tick) / 1000;
        if(elapsed_sec != last_countdown) {
            last_countdown = elapsed_sec;
            uint32_t remaining = 60 - elapsed_sec;
            furi_string_printf(app->lldp_text,
                "Listening for\nLLDP/CDP...\n(%lus remaining)\n", (unsigned long)remaining);
            eth_tester_update_view(app->text_box_lldp, app->lldp_text);
        }

        uint16_t recv_len = w5500_hal_macraw_recv(app->frame_buf, FRAME_BUF_SIZE);
        if(recv_len >= ETH_HEADER_SIZE) {
            /* Count frame for statistics */
            eth_tester_count_frame(app, app->frame_buf, recv_len);

            uint16_t ethertype = pkt_get_ethertype(app->frame_buf);

            /* Check for LLDP */
            if(ethertype == ETHERTYPE_LLDP && !lldp_neighbor.valid) {
                FURI_LOG_I(TAG, "LLDP frame received (%d bytes)", recv_len);
                if(lldp_parse(app->frame_buf + ETH_HEADER_SIZE, recv_len - ETH_HEADER_SIZE, &lldp_neighbor)) {
                    lldp_neighbor.last_seen_tick = furi_get_tick();
                    found = true;
                }
            }

            /* Check for CDP (LLC/SNAP) */
            if(!cdp_neighbor.valid) {
                uint16_t cdp_offset = cdp_check_frame(app->frame_buf, recv_len);
                if(cdp_offset > 0) {
                    FURI_LOG_I(TAG, "CDP frame received (%d bytes)", recv_len);
                    if(cdp_parse(app->frame_buf + cdp_offset, recv_len - cdp_offset, &cdp_neighbor)) {
                        cdp_neighbor.last_seen_tick = furi_get_tick();
                        found = true;
                    }
                }
            }

            /* Stop early if we have both */
            if(lldp_neighbor.valid && cdp_neighbor.valid) break;
        }

        furi_delay_ms(100);
    }

    w5500_hal_close_macraw();

    /* Format results */
    furi_string_reset(app->lldp_text);

    if(lldp_neighbor.valid) {
        char lldp_buf[512];
        lldp_format_neighbor(&lldp_neighbor, lldp_buf, sizeof(lldp_buf));
        furi_string_cat_str(app->lldp_text, lldp_buf);
    }

    if(cdp_neighbor.valid) {
        char cdp_buf[512];
        cdp_format_neighbor(&cdp_neighbor, cdp_buf, sizeof(cdp_buf));
        if(lldp_neighbor.valid) furi_string_cat_str(app->lldp_text, "\n");
        furi_string_cat_str(app->lldp_text, cdp_buf);
    }

    if(!found) {
        furi_string_set(app->lldp_text, "No LLDP/CDP neighbors\ndetected (waited 60s)\n");
    }

    /* Save results to SD card */
    eth_tester_save_and_notify(app, "lldp_cdp.txt", app->lldp_text);
}

static void eth_tester_do_arp_scan(EthTesterApp* app) {
    furi_string_reset(app->arp_text);

    furi_string_set(app->arp_text, "Getting IP via DHCP...\n");
    eth_tester_update_view(app->text_box_arp, app->arp_text);

    if(!eth_tester_ensure_dhcp(app)) {
        furi_string_set(app->arp_text,
            !app->w5500_initialized ? "W5500 Not Found!\n" :
            !w5500_hal_get_link_status() ? "No Link!\nConnect cable.\n" :
            "DHCP failed.\nCannot determine\nsubnet for ARP scan.\n");
        return;
    }

    wiz_NetInfo net_info;
    wizchip_getnetinfo(&net_info);

    FURI_LOG_I(TAG, "Got IP: %d.%d.%d.%d", net_info.ip[0], net_info.ip[1], net_info.ip[2], net_info.ip[3]);

    /* Calculate scan range */
    uint8_t start_ip[4], end_ip[4];
    uint16_t num_hosts = arp_calc_scan_range(net_info.ip, net_info.sn, start_ip, end_ip);
    uint8_t prefix = arp_mask_to_prefix(net_info.sn);

    if(num_hosts == 0) {
        furi_string_set(app->arp_text, "No hosts to scan\n(point-to-point link?)\n");
        return;
    }

    /* Cap discoverable hosts to ARP_MAX_HOSTS_CAP for RAM safety */
    uint16_t max_hosts = (num_hosts < ARP_MAX_HOSTS_CAP) ? num_hosts : ARP_MAX_HOSTS_CAP;

    char ip_str[16];
    pkt_format_ip(net_info.ip, ip_str);
    furi_string_printf(
        app->arp_text, "My IP: %s/%d\nScanning %d hosts...\n", ip_str, prefix, num_hosts);
    eth_tester_update_view(app->text_box_arp, app->arp_text);

    /* Open MACRAW for sending ARP requests and receiving replies */
    if(!w5500_hal_open_macraw()) {
        furi_string_set(app->arp_text, "Failed to open\nMACRAW!\n");
        return;
    }

    /* Allocate scan state + hosts array on heap */
    ArpScanState* scan = malloc(sizeof(ArpScanState));
    if(!scan) {
        furi_string_set(app->arp_text, "Memory alloc failed!\n");
        w5500_hal_close_macraw();
        return;
    }
    memset(scan, 0, sizeof(ArpScanState));
    scan->hosts = malloc(sizeof(ArpHost) * max_hosts);
    if(!scan->hosts) {
        furi_string_set(app->arp_text, "Memory alloc failed!\n");
        free(scan);
        w5500_hal_close_macraw();
        return;
    }
    memset(scan->hosts, 0, sizeof(ArpHost) * max_hosts);
    scan->max_hosts = max_hosts;
    scan->scanning = true;
    scan->start_tick = furi_get_tick();

    /* Send ARP requests in batches */
    uint8_t arp_frame[42];
    uint32_t current_ip = pkt_read_u32_be(start_ip);
    uint32_t last_ip = pkt_read_u32_be(end_ip);
    uint16_t batch_count = 0;

    while(current_ip <= last_ip && app->worker_running) {
        /* Build and send ARP request */
        uint8_t target[4];
        pkt_write_u32_be(target, current_ip);
        arp_build_request(arp_frame, net_info.mac, net_info.ip, target);
        w5500_hal_macraw_send(arp_frame, 42);
        scan->total_sent++;
        current_ip++;
        batch_count++;

        /* After each batch, pause and collect replies */
        if(batch_count >= ARP_BATCH_SIZE) {
            batch_count = 0;
            furi_delay_ms(ARP_BATCH_DELAY_MS);

            /* Update progress */
            furi_string_printf(
                app->arp_text,
                "My IP: %s/%d\nScanning: %d/%d sent\nFound: %d hosts\n",
                ip_str, prefix, scan->total_sent, num_hosts, scan->count);
            eth_tester_update_view(app->text_box_arp, app->arp_text);

            /* Collect any pending replies */
            for(uint8_t i = 0; i < 20; i++) {
                uint16_t recv_len = w5500_hal_macraw_recv(app->frame_buf, FRAME_BUF_SIZE);
                if(recv_len == 0) break;

                uint8_t sender_mac[6], sender_ip[4];
                if(arp_parse_reply(app->frame_buf, recv_len, sender_mac, sender_ip)) {
                    if(scan->count < scan->max_hosts) {
                        ArpHost* host = &scan->hosts[scan->count];
                        memcpy(host->ip, sender_ip, 4);
                        memcpy(host->mac, sender_mac, 6);
                        const char* vendor = oui_lookup(sender_mac);
                        strncpy(host->vendor, vendor, sizeof(host->vendor) - 1);
                        host->responded = true;
                        scan->count++;
                    }
                }
            }
        }
    }

    /* Wait for late replies */
    furi_string_printf(
        app->arp_text,
        "My IP: %s/%d\nAll %d sent, waiting\nfor replies... (%d found)\n",
        ip_str, prefix, num_hosts, scan->count);
    eth_tester_update_view(app->text_box_arp, app->arp_text);
    uint32_t tail_start = furi_get_tick();
    while(furi_get_tick() - tail_start < ARP_TAIL_WAIT_MS && app->worker_running) {
        uint16_t recv_len = w5500_hal_macraw_recv(app->frame_buf, FRAME_BUF_SIZE);
        if(recv_len > 0) {
            uint8_t sender_mac[6], sender_ip[4];
            if(arp_parse_reply(app->frame_buf, recv_len, sender_mac, sender_ip)) {
                /* Check for duplicate */
                bool duplicate = false;
                for(uint16_t j = 0; j < scan->count; j++) {
                    if(memcmp(scan->hosts[j].ip, sender_ip, 4) == 0) {
                        duplicate = true;
                        break;
                    }
                }
                if(!duplicate && scan->count < scan->max_hosts) {
                    ArpHost* host = &scan->hosts[scan->count];
                    memcpy(host->ip, sender_ip, 4);
                    memcpy(host->mac, sender_mac, 6);
                    const char* vendor = oui_lookup(sender_mac);
                    strncpy(host->vendor, vendor, sizeof(host->vendor) - 1);
                    host->responded = true;
                    scan->count++;
                }
            }
        }
        furi_delay_ms(50);
    }

    w5500_hal_close_macraw();

    scan->elapsed_ms = furi_get_tick() - scan->start_tick;
    scan->scanning = false;
    scan->complete = true;

    /* Format results */
    furi_string_reset(app->arp_text);
    furi_string_printf(
        app->arp_text,
        "Found %d hosts in %lu.%lus\n\n",
        scan->count,
        (unsigned long)(scan->elapsed_ms / 1000),
        (unsigned long)((scan->elapsed_ms % 1000) / 100));

    for(uint16_t i = 0; i < scan->count; i++) {
        ArpHost* h = &scan->hosts[i];
        char ip_buf[16];
        pkt_format_ip(h->ip, ip_buf);
        furi_string_cat_printf(app->arp_text, "%s ..%02X:%02X:%02X\n %s\n",
            ip_buf, h->mac[3], h->mac[4], h->mac[5], h->vendor);
    }

    if(scan->count == 0) {
        furi_string_cat_str(app->arp_text, "No hosts found.\n");
    }

    free(scan->hosts);
    free(scan);

    /* Save results to SD card */
    eth_tester_save_and_notify(app, "arp_scan.txt", app->arp_text);
}

static void eth_tester_do_dhcp_analyze(EthTesterApp* app) {
    furi_string_reset(app->dhcp_text);

    if(!eth_tester_ensure_w5500(app)) {
        furi_string_set(app->dhcp_text, "W5500 Not Found!\n");
        return;
    }

    if(!w5500_hal_get_link_status()) {
        furi_string_set(app->dhcp_text, "No Link!\nConnect cable.\n");
        return;
    }

    furi_string_set(app->dhcp_text, "Sending DHCP\nDiscover...\n");
    eth_tester_update_view(app->text_box_dhcp, app->dhcp_text);

    /*
     * Use UDP socket directly to send DHCP Discover and receive Offer
     * without going through the full DHCP state machine.
     * We do NOT send DHCP Request - just analyze the Offer.
     */
    uint8_t dhcp_socket = W5500_DHCP_SOCKET;

    /* Set our IP to 0.0.0.0 for DHCP discovery */
    wiz_NetInfo net_info;
    wizchip_getnetinfo(&net_info);
    uint8_t saved_ip[4], saved_sn[4], saved_gw[4];
    memcpy(saved_ip, net_info.ip, 4);
    memcpy(saved_sn, net_info.sn, 4);
    memcpy(saved_gw, net_info.gw, 4);
    memset(net_info.ip, 0, 4);
    memset(net_info.sn, 0, 4);
    memset(net_info.gw, 0, 4);
    wizchip_setnetinfo(&net_info);

    /* Open UDP socket on port 68 */
    close(dhcp_socket);
    int8_t ret = socket(dhcp_socket, Sn_MR_UDP, DHCP_CLIENT_PORT, 0);
    if(ret != dhcp_socket) {
        furi_string_set(app->dhcp_text, "Failed to open\nUDP socket!\n");
        return;
    }

    /* Build DHCP Discover (heap to save stack) */
    uint8_t* dhcp_pkt = malloc(548);
    if(!dhcp_pkt) {
        furi_string_set(app->dhcp_text, "Memory alloc failed!\n");
        close(dhcp_socket);
        return;
    }
    uint32_t xid;
    furi_hal_random_fill_buf((uint8_t*)&xid, sizeof(xid));
    uint16_t pkt_len = dhcp_build_discover(dhcp_pkt, app->mac_addr, xid);

    /* Send to broadcast 255.255.255.255:67 */
    uint8_t bcast_ip[4] = {255, 255, 255, 255};
    int32_t sent = sendto(dhcp_socket, dhcp_pkt, pkt_len, bcast_ip, DHCP_SERVER_PORT);
    free(dhcp_pkt);
    if(sent <= 0) {
        furi_string_set(app->dhcp_text, "Failed to send\nDHCP Discover!\n");
        close(dhcp_socket);
        return;
    }

    FURI_LOG_I(TAG, "DHCP Discover sent (xid=0x%08lX)", (unsigned long)xid);
    furi_string_set(app->dhcp_text, "Waiting for DHCP\nOffer... (10s)\n");
    eth_tester_update_view(app->text_box_dhcp, app->dhcp_text);

    /* Wait for DHCP Offer */
    DhcpAnalyzeResult dhcp_result;
    bool got_offer = false;
    uint32_t start_tick = furi_get_tick();
    uint8_t* recv_buf = malloc(1024);
    if(!recv_buf) {
        furi_string_set(app->dhcp_text, "Memory alloc failed!\n");
        close(dhcp_socket);
        return;
    }

    while(furi_get_tick() - start_tick < 10000 && app->worker_running) { /* 10 sec timeout */
        uint16_t rx_size = getSn_RX_RSR(dhcp_socket);
        if(rx_size > 0) {
            uint8_t from_ip[4];
            uint16_t from_port;
            int32_t received = recvfrom(dhcp_socket, recv_buf, 1024, from_ip, &from_port);
            if(received > 0) {
                if(dhcp_parse_offer(recv_buf, (uint16_t)received, xid, &dhcp_result)) {
                    got_offer = true;
                    break;
                }
            }
        }
        furi_delay_ms(50);
    }

    free(recv_buf);
    close(dhcp_socket);

    /* Restore network settings */
    memcpy(net_info.ip, saved_ip, 4);
    memcpy(net_info.sn, saved_sn, 4);
    memcpy(net_info.gw, saved_gw, 4);
    wizchip_setnetinfo(&net_info);

    /* Format results */
    furi_string_reset(app->dhcp_text);

    if(got_offer) {
        char* result_buf = malloc(768);
        if(result_buf) {
            dhcp_format_result(&dhcp_result, result_buf, 768);
            furi_string_set(app->dhcp_text, result_buf);
            free(result_buf);
        }
    } else {
        furi_string_set(app->dhcp_text, "No DHCP server found.\n(waited 10 sec)\n");
    }

    /* Save results to SD card */
    eth_tester_save_and_notify(app, "dhcp_analyze.txt", app->dhcp_text);
}

static void eth_tester_do_ping(EthTesterApp* app) {
    furi_string_reset(app->ping_text);

    furi_string_set(app->ping_text, "Getting IP via DHCP...\n");
    eth_tester_update_view(app->text_box_ping, app->ping_text);

    if(!eth_tester_ensure_dhcp(app)) {
        furi_string_set(app->ping_text,
            !app->w5500_initialized ? "W5500 Not Found!\n" :
            !w5500_hal_get_link_status() ? "No Link!\nConnect cable.\n" :
            "DHCP failed.\nCannot ping.\n");
        return;
    }

    wiz_NetInfo net_info;
    wizchip_getnetinfo(&net_info);

    /* Use custom IP if set, otherwise ping the gateway */
    uint8_t target_ip[4];
    if(app->ping_ip_custom[0] != 0) {
        memcpy(target_ip, app->ping_ip_custom, 4);
    } else {
        memcpy(target_ip, net_info.gw, 4);
    }

    char target_str[16], my_ip_str[16];
    pkt_format_ip(target_ip, target_str);
    pkt_format_ip(net_info.ip, my_ip_str);

    furi_string_printf(
        app->ping_text,
        "My IP: %s\nPing %s\n\n",
        my_ip_str,
        target_str);
    eth_tester_update_view(app->text_box_ping, app->ping_text);

    /* Send 4 pings */
    for(uint16_t i = 1; i <= 4 && app->worker_running; i++) {
        PingResult result;
        bool ok = icmp_ping(W5500_PING_SOCKET, target_ip, i, 3000, &result);
        if(ok) {
            furi_string_cat_printf(
                app->ping_text,
                "#%d: %lu ms\n",
                i,
                (unsigned long)result.rtt_ms);
        } else {
            furi_string_cat_printf(app->ping_text, "#%d: timeout\n", i);
        }
        eth_tester_update_view(app->text_box_ping, app->ping_text);
        furi_delay_ms(100);
    }
}

/* ==================== DNS Lookup ==================== */

static void eth_tester_do_dns_lookup(EthTesterApp* app) {
    furi_string_reset(app->dns_text);

    furi_string_set(app->dns_text, "Getting IP via DHCP...\n");
    eth_tester_update_view(app->text_box_dns, app->dns_text);

    if(!eth_tester_ensure_dhcp(app)) {
        furi_string_set(app->dns_text,
            !app->w5500_initialized ? "W5500 Not Found!\n" :
            !w5500_hal_get_link_status() ? "No Link!\nConnect cable.\n" :
            "DHCP failed.\nCannot resolve DNS.\n");
        return;
    }

    wiz_NetInfo net_info;
    wizchip_getnetinfo(&net_info);

    /* Check DNS server is valid */
    if(net_info.dns[0] == 0 && net_info.dns[1] == 0 &&
       net_info.dns[2] == 0 && net_info.dns[3] == 0) {
        furi_string_set(app->dns_text, "No DNS server\nfrom DHCP.\n");
        return;
    }

    memcpy(app->dns_server_ip, net_info.dns, 4);

    char dns_str[16];
    pkt_format_ip(net_info.dns, dns_str);

    furi_string_printf(
        app->dns_text,
        "Resolving:\n%s\nDNS: %s\n\n",
        app->dns_hostname_input,
        dns_str);
    eth_tester_update_view(app->text_box_dns, app->dns_text);

    /* Perform DNS lookup */
    DnsLookupResult dns_result;
    bool ok = dns_lookup(W5500_DNS_SOCKET, net_info.dns, app->dns_hostname_input, &dns_result);

    if(ok) {
        char ip_str[16];
        pkt_format_ip(dns_result.resolved_ip, ip_str);
        furi_string_printf(
            app->dns_text,
            "[DNS Lookup]\n"
            "Host: %s\n"
            "DNS: %s\n\n"
            "Result: %s\n",
            app->dns_hostname_input,
            dns_str,
            ip_str);
    } else {
        furi_string_printf(
            app->dns_text,
            "[DNS Lookup]\n"
            "Host: %s\n"
            "DNS: %s\n\n"
            "%s\n",
            app->dns_hostname_input,
            dns_str,
            dns_result.rcode == DNS_RCODE_NXDOMAIN ? "NXDOMAIN (not found)" : "Timeout (3s)");
    }

    eth_tester_save_and_notify(app, "dns_lookup.txt", app->dns_text);
}

/* ==================== Wake-on-LAN ==================== */

static void eth_tester_do_wol(EthTesterApp* app) {
    furi_string_reset(app->wol_text);

    furi_string_set(app->wol_text, "Getting IP via DHCP...\n");
    eth_tester_update_view(app->text_box_wol, app->wol_text);

    if(!eth_tester_ensure_dhcp(app)) {
        furi_string_set(app->wol_text,
            !app->w5500_initialized ? "W5500 Not Found!\n" :
            !w5500_hal_get_link_status() ? "No Link!\nConnect cable.\n" :
            "DHCP failed.\nCannot send WoL.\n");
        return;
    }

    wiz_NetInfo net_info;
    wizchip_getnetinfo(&net_info);

    char mac_str[18];
    pkt_format_mac(app->wol_mac_input, mac_str);

    furi_string_printf(
        app->wol_text,
        "Sending WoL to:\n%s\n\n",
        mac_str);
    eth_tester_update_view(app->text_box_wol, app->wol_text);

    bool ok = wol_send(W5500_WOL_SOCKET, app->wol_mac_input);

    if(ok) {
        furi_string_printf(
            app->wol_text,
            "[Wake-on-LAN]\n"
            "Target: %s\n\n"
            "Magic packet sent!\n"
            "Press Back to return.\n",
            mac_str);
    } else {
        furi_string_printf(
            app->wol_text,
            "[Wake-on-LAN]\n"
            "Target: %s\n\n"
            "Failed to send!\n",
            mac_str);
    }
    if(app->setting_sound) {
        notification_message(app->notifications, ok ? &sequence_success : &sequence_error);
    }
}

/* ==================== MAC Changer ==================== */

static void eth_tester_do_mac_changer(EthTesterApp* app) {
    furi_string_reset(app->mac_changer_text);

    /* Read current MAC */
    uint8_t current_mac[6];
    if(app->w5500_initialized) {
        w5500_hal_get_mac(current_mac);
    } else {
        memcpy(current_mac, app->mac_addr, 6);
    }

    uint8_t default_mac[6] = MAC_CHANGER_DEFAULT_MAC;
    bool is_default = (memcmp(current_mac, default_mac, 6) == 0);

    char mac_str[18];
    pkt_format_mac(current_mac, mac_str);

    furi_string_printf(
        app->mac_changer_text,
        "Current MAC:\n"
        "%s %s\n\n"
        "OK = Randomize MAC\n"
        "Back = Cancel\n",
        mac_str,
        is_default ? "(default)" : "(custom)");
}

/* ==================== Traceroute ==================== */

static void eth_tester_do_traceroute(EthTesterApp* app) {
    furi_string_reset(app->traceroute_text);

    furi_string_set(app->traceroute_text, "Getting IP via DHCP...\n");
    eth_tester_update_view(app->text_box_traceroute, app->traceroute_text);

    if(!eth_tester_ensure_dhcp(app)) {
        furi_string_set(app->traceroute_text,
            !app->w5500_initialized ? "W5500 Not Found!\n" :
            !w5500_hal_get_link_status() ? "No Link!\nConnect cable.\n" :
            "DHCP failed.\n");
        return;
    }

    wiz_NetInfo net_info;
    wizchip_getnetinfo(&net_info);

    char target_str[16];
    pkt_format_ip(app->traceroute_target, target_str);

    furi_string_printf(
        app->traceroute_text,
        "[Traceroute]\n"
        "Target: %s\n\n",
        target_str);
    eth_tester_update_view(app->text_box_traceroute, app->traceroute_text);

    /* Run traceroute */
    for(uint8_t ttl = 1; ttl <= TRACEROUTE_MAX_TTL && app->worker_running; ttl++) {
        TracerouteHop hop;
        bool got_reply = traceroute_send_hop(
            W5500_TRACEROUTE_SOCKET,
            app->traceroute_target,
            ttl,
            ttl,
            TRACEROUTE_HOP_TIMEOUT_MS,
            &hop);

        if(got_reply) {
            char hop_ip_str[16];
            pkt_format_ip(hop.hop_ip, hop_ip_str);
            furi_string_cat_printf(
                app->traceroute_text,
                "%2d  %s  %lu ms\n",
                ttl,
                hop_ip_str,
                (unsigned long)hop.rtt_ms);
        } else {
            furi_string_cat_printf(app->traceroute_text, "%2d  * * *\n", ttl);
        }

        eth_tester_update_view(app->text_box_traceroute, app->traceroute_text);

        /* Stop if destination reached */
        if(got_reply && hop.is_destination) {
            furi_string_cat_str(app->traceroute_text, "\nDestination reached.\n");
            break;
        }
    }

    eth_tester_save_and_notify(app, "traceroute.txt", app->traceroute_text);
}

/* ==================== Ping Sweep ==================== */

/* Parse CIDR notation "192.168.1.0/24" into base IP and prefix length */
static bool parse_cidr(const char* str, uint8_t base_ip[4], uint8_t* prefix) {
    unsigned int a, b, c, d, p;
    if(sscanf(str, "%u.%u.%u.%u/%u", &a, &b, &c, &d, &p) != 5) return false;
    if(a > 255 || b > 255 || c > 255 || d > 255 || p > 32) return false;
    base_ip[0] = (uint8_t)a;
    base_ip[1] = (uint8_t)b;
    base_ip[2] = (uint8_t)c;
    base_ip[3] = (uint8_t)d;
    *prefix = (uint8_t)p;
    return true;
}

/* Phase 1: detect network via DHCP, then signal main thread to show input */
static void eth_tester_do_ping_sweep_detect(EthTesterApp* app) {
    furi_string_reset(app->ping_sweep_text);

    furi_string_set(app->ping_sweep_text, "Getting IP via DHCP...\n");
    eth_tester_update_view(app->text_box_ping_sweep, app->ping_sweep_text);

    if(!eth_tester_ensure_dhcp(app)) {
        furi_string_set(app->ping_sweep_text,
            !app->w5500_initialized ? "W5500 Not Found!\n" :
            !w5500_hal_get_link_status() ? "No Link!\nConnect cable.\n" :
            "DHCP failed.\n");
        eth_tester_update_view(app->text_box_ping_sweep, app->ping_sweep_text);
        return;
    }

    wiz_NetInfo net_info;
    wizchip_getnetinfo(&net_info);

    /* Populate CIDR from detected network */
    uint8_t net[4];
    for(int i = 0; i < 4; i++) net[i] = app->dhcp_ip[i] & app->dhcp_mask[i];
    uint8_t pfx = arp_mask_to_prefix(app->dhcp_mask);
    snprintf(app->ping_sweep_ip_input, sizeof(app->ping_sweep_ip_input),
        "%d.%d.%d.%d/%d", net[0], net[1], net[2], net[3], pfx);

    /* Signal main thread to show input */
    view_dispatcher_send_custom_event(app->view_dispatcher, CUSTOM_EVENT_PING_SWEEP_READY);
}

/* Phase 2: actual ping sweep scan */
static void eth_tester_do_ping_sweep(EthTesterApp* app) {
    furi_string_reset(app->ping_sweep_text);

    furi_string_set(app->ping_sweep_text, "Getting IP via DHCP...\n");
    eth_tester_update_view(app->text_box_ping_sweep, app->ping_sweep_text);

    if(!eth_tester_ensure_dhcp(app)) {
        furi_string_set(app->ping_sweep_text,
            !app->w5500_initialized ? "W5500 Not Found!\n" :
            !w5500_hal_get_link_status() ? "No Link!\nConnect cable.\n" :
            "DHCP failed.\n");
        return;
    }

    wiz_NetInfo net_info;
    wizchip_getnetinfo(&net_info);

    /* Parse CIDR input; if invalid, auto-detect from DHCP network */
    uint8_t base_ip[4];
    uint8_t prefix;
    uint8_t mask[4];

    if(parse_cidr(app->ping_sweep_ip_input, base_ip, &prefix)) {
        /* User provided valid CIDR */
        uint32_t mask32 = prefix ? (0xFFFFFFFF << (32 - prefix)) : 0;
        mask[0] = (uint8_t)(mask32 >> 24);
        mask[1] = (uint8_t)(mask32 >> 16);
        mask[2] = (uint8_t)(mask32 >> 8);
        mask[3] = (uint8_t)(mask32);
    } else {
        /* Auto-detect from DHCP */
        wiz_NetInfo auto_info;
        wizchip_getnetinfo(&auto_info);
        memcpy(base_ip, auto_info.ip, 4);
        memcpy(mask, auto_info.sn, 4);
        prefix = arp_mask_to_prefix(mask);
        /* Calculate network address */
        for(int i = 0; i < 4; i++) base_ip[i] &= mask[i];
        snprintf(app->ping_sweep_ip_input, sizeof(app->ping_sweep_ip_input),
            "%d.%d.%d.%d/%d", base_ip[0], base_ip[1], base_ip[2], base_ip[3], prefix);
    }

    uint8_t start_ip[4], end_ip[4];
    uint16_t num_hosts = arp_calc_scan_range(base_ip, mask, start_ip, end_ip);

    if(num_hosts == 0) {
        furi_string_set(app->ping_sweep_text, "No hosts in range.\n");
        return;
    }

    /* Cap to reasonable number */
    if(num_hosts > 254) num_hosts = 254;

    furi_string_printf(
        app->ping_sweep_text,
        "[Ping Sweep]\n"
        "Range: %s\n"
        "Hosts: %d\n\n",
        app->ping_sweep_ip_input,
        num_hosts);
    eth_tester_update_view(app->text_box_ping_sweep, app->ping_sweep_text);

    /* Sweep */
    uint32_t current = pkt_read_u32_be(start_ip);
    uint32_t last = pkt_read_u32_be(end_ip);
    uint16_t scanned = 0;
    uint16_t alive = 0;
    FuriString* results = furi_string_alloc();

    while(current <= last && scanned < num_hosts && app->worker_running) {
        uint8_t target[4];
        pkt_write_u32_be(target, current);

        PingResult result;
        bool ok = icmp_ping(W5500_PING_SOCKET, target, (uint16_t)(scanned + 1), 500, &result);
        scanned++;

        if(ok) {
            char ip_str[16];
            pkt_format_ip(target, ip_str);
            furi_string_cat_printf(results, "  %s: %lu ms\n", ip_str, (unsigned long)result.rtt_ms);
            alive++;
        }

        /* Update progress every 5 hosts */
        if(scanned % 5 == 0 || current == last) {
            char progress[28];
            eth_tester_progress_bar(progress, sizeof(progress), scanned, num_hosts);
            furi_string_printf(
                app->ping_sweep_text,
                "[Ping Sweep]\n"
                "%s\n"
                "Alive: %d/%d scanned\n\n%s",
                progress,
                alive,
                scanned,
                furi_string_get_cstr(results));
            eth_tester_update_view(app->text_box_ping_sweep, app->ping_sweep_text);
        }

        current++;
    }

    /* Final results */
    furi_string_printf(
        app->ping_sweep_text,
        "[Ping Sweep]\n"
        "Range: %s\n"
        "Scanned: %d\n"
        "Alive: %d\n\n"
        "Responding hosts:\n%s",
        app->ping_sweep_ip_input,
        scanned,
        alive,
        furi_string_get_cstr(results));

    if(alive == 0) {
        furi_string_cat_str(app->ping_sweep_text, "  (none)\n");
    }

    furi_string_free(results);
    eth_tester_save_and_notify(app, "ping_sweep.txt", app->ping_sweep_text);
}

/* ==================== mDNS / SSDP Discovery ==================== */

static void eth_tester_do_discovery(EthTesterApp* app) {
    furi_string_reset(app->discovery_text);

    furi_string_set(app->discovery_text, "Getting IP via DHCP...\n");
    eth_tester_update_view(app->text_box_discovery, app->discovery_text);

    if(!eth_tester_ensure_dhcp(app)) {
        furi_string_set(app->discovery_text,
            !app->w5500_initialized ? "W5500 Not Found!\n" :
            !w5500_hal_get_link_status() ? "No Link!\nConnect cable.\n" :
            "DHCP failed.\n");
        return;
    }

    wiz_NetInfo net_info;
    wizchip_getnetinfo(&net_info);

    furi_string_set(app->discovery_text, "Sending mDNS + SSDP...\n");
    eth_tester_update_view(app->text_box_discovery, app->discovery_text);

    /* Allocate device array */
    DiscoveryDevice* devices = malloc(sizeof(DiscoveryDevice) * DISCOVERY_MAX_DEVICES);
    if(!devices) {
        furi_string_set(app->discovery_text, "Memory alloc failed!\n");
        return;
    }
    memset(devices, 0, sizeof(DiscoveryDevice) * DISCOVERY_MAX_DEVICES);
    uint16_t device_count = 0;

    /* Send both queries */
    bool mdns_ok = mdns_send_query(W5500_MDNS_SOCKET);
    bool ssdp_ok = ssdp_send_msearch(W5500_SSDP_SOCKET);

    if(!mdns_ok && !ssdp_ok) {
        furi_string_set(app->discovery_text, "Failed to send queries!\n");
        free(devices);
        return;
    }

    furi_string_set(app->discovery_text, "Listening for responses...\n(5 seconds)\n");
    eth_tester_update_view(app->text_box_discovery, app->discovery_text);

    /* Listen for responses */
    uint8_t recv_buf[512];
    uint32_t start_tick = furi_get_tick();

    while(furi_get_tick() - start_tick < DISCOVERY_TIMEOUT_MS && device_count < DISCOVERY_MAX_DEVICES && app->worker_running) {
        /* Check mDNS socket */
        if(mdns_ok) {
            uint16_t rx = getSn_RX_RSR(W5500_MDNS_SOCKET);
            if(rx > 0) {
                uint8_t from_ip[4];
                uint16_t from_port;
                int32_t received = recvfrom(W5500_MDNS_SOCKET, recv_buf, sizeof(recv_buf), from_ip, &from_port);
                if(received > 0) {
                    DiscoveryDevice dev;
                    if(mdns_parse_response(recv_buf, (uint16_t)received, from_ip, &dev)) {
                        /* Check for duplicate IP */
                        bool dup = false;
                        for(uint16_t i = 0; i < device_count; i++) {
                            if(memcmp(devices[i].ip, dev.ip, 4) == 0 &&
                               devices[i].source == dev.source) {
                                dup = true;
                                break;
                            }
                        }
                        if(!dup) {
                            memcpy(&devices[device_count++], &dev, sizeof(dev));
                        }
                    }
                }
            }
        }

        /* Check SSDP socket */
        if(ssdp_ok) {
            uint16_t rx = getSn_RX_RSR(W5500_SSDP_SOCKET);
            if(rx > 0) {
                uint8_t from_ip[4];
                uint16_t from_port;
                int32_t received = recvfrom(W5500_SSDP_SOCKET, recv_buf, sizeof(recv_buf), from_ip, &from_port);
                if(received > 0) {
                    DiscoveryDevice dev;
                    if(ssdp_parse_response(recv_buf, (uint16_t)received, from_ip, &dev)) {
                        /* Check for duplicate IP + source */
                        bool dup = false;
                        for(uint16_t i = 0; i < device_count; i++) {
                            if(memcmp(devices[i].ip, dev.ip, 4) == 0 &&
                               devices[i].source == dev.source) {
                                dup = true;
                                break;
                            }
                        }
                        if(!dup) {
                            memcpy(&devices[device_count++], &dev, sizeof(dev));
                        }
                    }
                }
            }
        }

        furi_delay_ms(50);
    }

    /* Close sockets */
    if(mdns_ok) close(W5500_MDNS_SOCKET);
    if(ssdp_ok) close(W5500_SSDP_SOCKET);

    /* Format results */
    furi_string_printf(
        app->discovery_text,
        "[Discovery]\n"
        "Found %d device(s)\n\n",
        device_count);

    for(uint16_t i = 0; i < device_count; i++) {
        DiscoveryDevice* d = &devices[i];
        char ip_str[16];
        pkt_format_ip(d->ip, ip_str);
        furi_string_cat_printf(
            app->discovery_text,
            "%s [%s]\n %s\n %s\n\n",
            ip_str,
            d->source == DiscoverySourceMdns ? "mDNS" : "SSDP",
            d->name,
            d->service_type);
    }

    if(device_count == 0) {
        furi_string_cat_str(app->discovery_text, "No devices found.\n");
    }

    free(devices);
    eth_tester_save_and_notify(app, "discovery.txt", app->discovery_text);
}

/* ==================== STP/BPDU + VLAN Detection ==================== */

static void eth_tester_do_stp_vlan(EthTesterApp* app) {
    furi_string_reset(app->stp_vlan_text);

    if(!eth_tester_ensure_w5500(app)) {
        furi_string_set(app->stp_vlan_text, "W5500 Not Found!\n");
        return;
    }

    if(!w5500_hal_get_link_status()) {
        furi_string_set(app->stp_vlan_text, "No Link!\nConnect cable.\n");
        return;
    }

    furi_string_set(app->stp_vlan_text, "Listening for BPDU\nand VLAN tags...\n(30s remaining)\n");
    eth_tester_update_view(app->text_box_stp_vlan, app->stp_vlan_text);

    /* Open MACRAW socket */
    if(!w5500_hal_open_macraw()) {
        furi_string_set(app->stp_vlan_text, "Failed to open\nMACRAW socket!\n");
        return;
    }

    BpduInfo bpdu;
    memset(&bpdu, 0, sizeof(bpdu));

    VlanState vlan_state;
    vlan_state_init(&vlan_state);

    uint32_t start_tick = furi_get_tick();
    uint32_t timeout_ms = 30000;
    uint32_t last_update = 0;
    uint32_t last_countdown = 0;

    while(furi_get_tick() - start_tick < timeout_ms && app->worker_running) {
        /* Update countdown */
        uint32_t elapsed_sec = (furi_get_tick() - start_tick) / 1000;
        if(elapsed_sec != last_countdown && !bpdu.valid) {
            last_countdown = elapsed_sec;
            furi_string_printf(app->stp_vlan_text,
                "Listening for BPDU\nand VLAN tags...\n(%lus remaining)\n",
                (unsigned long)(30 - elapsed_sec));
            eth_tester_update_view(app->text_box_stp_vlan, app->stp_vlan_text);
        }

        uint16_t recv_len = w5500_hal_macraw_recv(app->frame_buf, FRAME_BUF_SIZE);
        if(recv_len >= ETH_HEADER_SIZE) {
            /* Count frame for stats */
            eth_tester_count_frame(app, app->frame_buf, recv_len);

            /* Check for BPDU */
            if(!bpdu.valid) {
                stp_parse_bpdu(app->frame_buf, recv_len, &bpdu);
            }

            /* Check for 802.1Q VLAN tag */
            uint16_t vlan_id;
            if(vlan_extract_tag(app->frame_buf, recv_len, &vlan_id)) {
                vlan_state_add(&vlan_state, vlan_id);
            }
        }

        /* Update display every 2 seconds */
        uint32_t elapsed = furi_get_tick() - start_tick;
        if(elapsed - last_update > 2000) {
            last_update = elapsed;
            furi_string_reset(app->stp_vlan_text);
            furi_string_printf(
                app->stp_vlan_text,
                "Listening... %lus/%lus\n\n",
                (unsigned long)(elapsed / 1000),
                (unsigned long)(timeout_ms / 1000));

            if(bpdu.valid) {
                char bpdu_buf[256];
                stp_format_bpdu(&bpdu, bpdu_buf, sizeof(bpdu_buf));
                furi_string_cat_str(app->stp_vlan_text, bpdu_buf);
            } else {
                furi_string_cat_str(app->stp_vlan_text, "No BPDU detected yet.\n");
            }

            furi_string_cat_str(app->stp_vlan_text, "\n--- VLANs ---\n");
            if(vlan_state.vlan_count > 0) {
                for(uint16_t i = 0; i < vlan_state.vlan_count; i++) {
                    furi_string_cat_printf(
                        app->stp_vlan_text,
                        "VLAN %d: %lu frames\n",
                        vlan_state.vlans[i].vlan_id,
                        (unsigned long)vlan_state.vlans[i].frame_count);
                }
            } else {
                furi_string_cat_str(app->stp_vlan_text, "No 802.1Q tags.\n");
            }

            eth_tester_update_view(app->text_box_stp_vlan, app->stp_vlan_text);
        }

        furi_delay_ms(50);
    }

    w5500_hal_close_macraw();

    /* Format final results */
    furi_string_reset(app->stp_vlan_text);

    if(bpdu.valid) {
        char bpdu_buf[256];
        stp_format_bpdu(&bpdu, bpdu_buf, sizeof(bpdu_buf));
        furi_string_cat_str(app->stp_vlan_text, bpdu_buf);
    } else {
        furi_string_set(app->stp_vlan_text, "[STP/VLAN]\nNo BPDU detected.\n");
    }

    furi_string_cat_str(app->stp_vlan_text, "\n--- VLANs ---\n");
    if(vlan_state.vlan_count > 0) {
        furi_string_cat_printf(
            app->stp_vlan_text,
            "Tagged frames: %lu\n",
            (unsigned long)vlan_state.total_tagged_frames);
        for(uint16_t i = 0; i < vlan_state.vlan_count; i++) {
            furi_string_cat_printf(
                app->stp_vlan_text,
                "VLAN %d: %lu frames\n",
                vlan_state.vlans[i].vlan_id,
                (unsigned long)vlan_state.vlans[i].frame_count);
        }
    } else {
        furi_string_cat_str(app->stp_vlan_text, "No 802.1Q tags detected.\n(Not on trunk port?)\n");
    }

    eth_tester_save_and_notify(app, "stp_vlan.txt", app->stp_vlan_text);
}

/* ==================== History Browser ==================== */

static void eth_tester_history_populate(EthTesterApp* app) {
    submenu_reset(app->submenu_history);

    /* Free previous state if any */
    if(app->history_state) {
        free(app->history_state);
        app->history_state = NULL;
    }

    app->history_state = malloc(sizeof(HistoryState));
    if(!app->history_state) return;

    uint16_t count = history_list(app->history_state);

    if(count == 0) {
        submenu_add_item(app->submenu_history, "No saved results", 0, NULL, NULL);
        return;
    }

    for(uint16_t i = 0; i < count; i++) {
        HistoryEntry* e = &app->history_state->files[i];

        /* Build display label via temp buffer to avoid restrict overlap */
        char tmp[HISTORY_FILENAME_LEN];
        if(strlen(e->filename) > 15 && e->filename[8] == '_') {
            snprintf(tmp, sizeof(tmp),
                "[%s] %.2s-%.2s %.2s:%.2s",
                e->type,
                e->filename + 4,
                e->filename + 6,
                e->filename + 9,
                e->filename + 11);
        } else {
            snprintf(tmp, sizeof(tmp), "%s", e->filename);
        }
        memcpy(e->label, tmp, sizeof(e->label));

        /* View entry */
        submenu_add_item(
            app->submenu_history,
            e->label,
            i,
            eth_tester_history_file_callback,
            app);
        /* Delete entry (index offset by HISTORY_MAX_FILES) */
        char del_label[HISTORY_FILENAME_LEN];
        snprintf(del_label, sizeof(del_label), "  DEL %s", e->label);
        submenu_add_item(
            app->submenu_history,
            del_label,
            HISTORY_MAX_FILES + i,
            eth_tester_history_delete_callback,
            app);
    }
}

static void eth_tester_history_file_callback(void* context, uint32_t index) {
    EthTesterApp* app = context;
    furi_assert(app);

    if(!app->history_state || index >= app->history_state->file_count) return;

    app->history_selected = index;
    const char* filename = app->history_state->files[index].filename;

    char* buf = malloc(2048);
    if(!buf) {
        furi_string_set(app->history_file_text, "Memory alloc failed!\n");
    } else if(history_read_file(filename, buf, 2048)) {
        furi_string_set(app->history_file_text, buf);
        free(buf);
    } else {
        furi_string_printf(app->history_file_text, "Failed to read:\n%s\n", filename);
        free(buf);
    }

    text_box_reset(app->text_box_history_file);
    text_box_set_text(app->text_box_history_file, furi_string_get_cstr(app->history_file_text));
    view_dispatcher_switch_to_view(app->view_dispatcher, EthTesterViewHistoryFile);
}

static void eth_tester_history_delete_callback(void* context, uint32_t index) {
    EthTesterApp* app = context;
    furi_assert(app);

    uint16_t file_idx = index - HISTORY_MAX_FILES;
    if(!app->history_state || file_idx >= app->history_state->file_count) return;

    const char* filename = app->history_state->files[file_idx].filename;
    history_delete_file(filename);
    if(app->setting_sound) notification_message(app->notifications, &sequence_success);

    /* Refresh list */
    eth_tester_history_populate(app);
}

/* ==================== Port Scanner ==================== */

static void eth_tester_do_port_scan(EthTesterApp* app) {
    furi_string_reset(app->port_scan_text);

    furi_string_set(app->port_scan_text, "Getting IP via DHCP...\n");
    eth_tester_update_view(app->text_box_port_scan, app->port_scan_text);

    if(!eth_tester_ensure_dhcp(app)) {
        furi_string_set(app->port_scan_text,
            !app->w5500_initialized ? "W5500 Not Found!\n" :
            !w5500_hal_get_link_status() ? "No Link!\nConnect cable.\n" :
            "DHCP failed.\nCannot scan.\n");
        return;
    }

    wiz_NetInfo net_info;
    wizchip_getnetinfo(&net_info);

    char target_str[16];
    pkt_format_ip(app->port_scan_target, target_str);

    /* Select port preset */
    const uint16_t* ports;
    uint16_t port_count;
    if(app->port_scan_top100) {
        ports = PORT_PRESET_TOP100;
        port_count = PORT_PRESET_TOP100_COUNT;
    } else {
        ports = PORT_PRESET_TOP20;
        port_count = PORT_PRESET_TOP20_COUNT;
    }

    furi_string_printf(
        app->port_scan_text,
        "[Port Scan]\n"
        "Target: %s\n"
        "Ports: Top %d\n\n"
        "Scanning...\n",
        target_str,
        port_count);
    eth_tester_update_view(app->text_box_port_scan, app->port_scan_text);

    /* Scan ports and collect results */
    uint16_t open_count = 0;
    uint16_t closed_count = 0;
    uint16_t filtered_count = 0;

    /* Build results string progressively */
    FuriString* results = furi_string_alloc();

    for(uint16_t i = 0; i < port_count && app->worker_running; i++) {
        uint16_t port = ports[i];

        PortState state = port_scan_tcp(
            W5500_SCAN_SOCKET_BASE,
            app->port_scan_target,
            port,
            PORT_SCAN_TIMEOUT_MS);

        const char* state_str;
        switch(state) {
        case PortStateOpen:
            state_str = "OPEN";
            open_count++;
            break;
        case PortStateClosed:
            state_str = "CLOSED";
            closed_count++;
            break;
        default:
            state_str = "FILTERED";
            filtered_count++;
            break;
        }

        /* Only show open ports in detail, summarize others */
        if(state == PortStateOpen) {
            furi_string_cat_printf(results, "  %d: %s\n", port, state_str);
        }

        /* Update progress */
        {
            char progress[28];
            eth_tester_progress_bar(progress, sizeof(progress), i + 1, port_count);
            furi_string_printf(
                app->port_scan_text,
                "[Port Scan] %s\n"
                "%s\n\n"
                "Open ports:\n%s",
                target_str,
                progress,
                furi_string_get_cstr(results));
        }
        eth_tester_update_view(app->text_box_port_scan, app->port_scan_text);
    }

    /* Final results */
    furi_string_printf(
        app->port_scan_text,
        "[Port Scan]\n"
        "Target: %s\n"
        "Scanned: %d ports\n\n"
        "Open: %d  Closed: %d\n"
        "Filtered: %d\n\n",
        target_str,
        port_count,
        open_count,
        closed_count,
        filtered_count);

    if(open_count > 0) {
        furi_string_cat_str(app->port_scan_text, "Open ports:\n");
        furi_string_cat(app->port_scan_text, results);
    } else {
        furi_string_cat_str(app->port_scan_text, "No open ports found.\n");
    }

    furi_string_free(results);

    eth_tester_save_and_notify(app, "port_scan.txt", app->port_scan_text);
}

/* ==================== Continuous Ping ==================== */

static void eth_tester_do_cont_ping(EthTesterApp* app) {
    if(!eth_tester_ensure_dhcp(app)) return;

    /* Allocate ping graph state */
    PingGraphState* pg = malloc(sizeof(PingGraphState));
    if(!pg) return;
    ping_graph_init(pg);
    app->ping_graph = pg;

    /* Update view model */
    with_view_model(
        app->view_cont_ping,
        ContPingViewModel* vm,
        { vm->app = app; },
        true);

    /* Continuous ping loop */
    uint16_t seq = 1;
    while(app->worker_running) {
        PingResult result;
        bool ok = icmp_ping(W5500_PING_SOCKET, app->cont_ping_target, seq, PING_GRAPH_TIMEOUT_MS, &result);

        if(ok) {
            ping_graph_add_sample(pg, result.rtt_ms);
        } else {
            ping_graph_add_sample(pg, PING_RTT_TIMEOUT);
        }

        /* Trigger view redraw */
        with_view_model(
            app->view_cont_ping,
            ContPingViewModel* vm,
            { UNUSED(vm); },
            true);

        seq++;

        /* Wait for the remainder of the interval (account for ping duration) */
        uint32_t elapsed = ok ? result.rtt_ms : PING_GRAPH_TIMEOUT_MS;
        if(elapsed < PING_GRAPH_INTERVAL_MS) {
            /* Check running flag periodically during wait */
            uint32_t remaining = PING_GRAPH_INTERVAL_MS - elapsed;
            uint32_t wait_start = furi_get_tick();
            while(app->worker_running && (furi_get_tick() - wait_start < remaining)) {
                furi_delay_ms(50);
            }
        }
    }

    /* Save results to SD card */
    FuriString* log = furi_string_alloc();
    char target_str[16];
    pkt_format_ip(app->cont_ping_target, target_str);
    furi_string_printf(
        log,
        "Continuous Ping: %s\n"
        "Sent: %lu Received: %lu\n"
        "Loss: %d%%\n"
        "Min: %lu ms Avg: %lu ms Max: %lu ms\n",
        target_str,
        (unsigned long)pg->total_sent,
        (unsigned long)pg->total_received,
        ping_graph_loss_percent(pg),
        (unsigned long)((pg->rtt_min == UINT32_MAX) ? 0 : pg->rtt_min),
        (unsigned long)ping_graph_avg_rtt(pg),
        (unsigned long)pg->rtt_max);
    if(app->setting_autosave) {
        eth_tester_save_results("cont_ping.txt", furi_string_get_cstr(log));
    }
    furi_string_free(log);

    /* Cleanup */
    app->ping_graph = NULL;
    free(pg);
}

/* ==================== Packet statistics ==================== */

static void eth_tester_count_frame(EthTesterApp* app, const uint8_t* frame, uint16_t len) {
    if(len < ETH_HEADER_SIZE) return;

    app->stats.total_frames++;

    /* Classify by destination MAC */
    uint8_t dst[6];
    pkt_get_dst_mac(frame, dst);
    if(pkt_is_broadcast(dst)) {
        app->stats.broadcast_frames++;
    } else if(pkt_is_multicast(dst)) {
        app->stats.multicast_frames++;
    } else {
        app->stats.unicast_frames++;
    }

    /* Classify by EtherType */
    uint16_t ethertype = pkt_get_ethertype(frame);
    switch(ethertype) {
    case ETHERTYPE_IPV4:
        app->stats.ipv4_frames++;
        break;
    case ETHERTYPE_ARP:
        app->stats.arp_frames++;
        break;
    case ETHERTYPE_IPV6:
        app->stats.ipv6_frames++;
        break;
    case ETHERTYPE_LLDP:
        app->stats.lldp_frames++;
        break;
    default:
        /* Check for CDP (length field + LLC/SNAP) */
        if(ethertype < 0x0600 && len >= 22) {
            const uint8_t cdp_mac[] = CDP_DST_MAC;
            if(memcmp(frame, cdp_mac, 6) == 0) {
                app->stats.cdp_frames++;
                break;
            }
        }
        app->stats.unknown_frames++;
        break;
    }
}

static void eth_tester_do_stats(EthTesterApp* app) {
    furi_string_reset(app->stats_text);

    if(!eth_tester_ensure_w5500(app)) {
        furi_string_set(app->stats_text, "W5500 Not Found!\n");
        return;
    }

    if(!w5500_hal_get_link_status()) {
        furi_string_set(app->stats_text, "No Link!\nConnect cable first.\n");
        return;
    }

    /* If no frames counted yet, do a quick capture */
    if(app->stats.total_frames == 0) {
        furi_string_set(app->stats_text, "Capturing frames...\n(10s remaining)\n");
        eth_tester_update_view(app->text_box_stats, app->stats_text);

        if(!w5500_hal_open_macraw()) {
            furi_string_set(app->stats_text, "Failed to open\nMACRAW!\n");
            return;
        }

        uint32_t start_tick = furi_get_tick();
        uint32_t last_sec = 0;
        while(furi_get_tick() - start_tick < 10000 && app->worker_running) {
            uint16_t recv_len = w5500_hal_macraw_recv(app->frame_buf, FRAME_BUF_SIZE);
            if(recv_len >= ETH_HEADER_SIZE) {
                eth_tester_count_frame(app, app->frame_buf, recv_len);
            }
            /* Update countdown every second */
            uint32_t sec = (furi_get_tick() - start_tick) / 1000;
            if(sec != last_sec) {
                last_sec = sec;
                furi_string_printf(app->stats_text,
                    "Capturing frames...\n(%lus remaining)\nFrames: %lu\n",
                    (unsigned long)(10 - sec),
                    (unsigned long)app->stats.total_frames);
                eth_tester_update_view(app->text_box_stats, app->stats_text);
            }
            furi_delay_ms(10);
        }

        w5500_hal_close_macraw();
    }

    /* Format statistics with compact layout */
    PacketStats* s = &app->stats;
    uint32_t t = s->total_frames ? s->total_frames : 1; /* avoid div by 0 */
    furi_string_printf(
        app->stats_text,
        "[Stats] %lu frames\n"
        "Uni:%lu Bcast:%lu Mcast:%lu\n"
        "\nIPv4:%lu(%lu%%) ARP:%lu\n"
        "IPv6:%lu LLDP:%lu CDP:%lu\n"
        "Other:%lu\n",
        (unsigned long)s->total_frames,
        (unsigned long)s->unicast_frames,
        (unsigned long)s->broadcast_frames,
        (unsigned long)s->multicast_frames,
        (unsigned long)s->ipv4_frames,
        (unsigned long)(s->ipv4_frames * 100 / t),
        (unsigned long)s->arp_frames,
        (unsigned long)s->ipv6_frames,
        (unsigned long)s->lldp_frames,
        (unsigned long)s->cdp_frames,
        (unsigned long)s->unknown_frames);

    /* Save stats to SD card (no sound — passive capture) */
    if(app->setting_autosave) {
        eth_tester_save_results("stats.txt", furi_string_get_cstr(app->stats_text));
    }
}

/* ==================== Save results to SD card ==================== */

static bool eth_tester_save_results(const char* type, const char* content) {
    /* Extract scan type from filename (remove .txt extension if present) */
    char scan_type[32];
    strncpy(scan_type, type, sizeof(scan_type) - 1);
    scan_type[sizeof(scan_type) - 1] = '\0';
    uint16_t len = strlen(scan_type);
    if(len > 4 && strcmp(&scan_type[len - 4], ".txt") == 0) {
        scan_type[len - 4] = '\0';
    }

    return history_save(scan_type, content);
}

/* Save results and append status to the display text, with optional LED/vibro feedback */
static void eth_tester_save_and_notify(EthTesterApp* app, const char* type, FuriString* text) {
    if(app->setting_autosave) {
        bool ok = eth_tester_save_results(type, furi_string_get_cstr(text));
        furi_string_cat_str(text, ok ? "\nSaved to History\n" : "\nHistory save failed\n");
    }
    if(app->setting_sound) {
        notification_message(app->notifications, &sequence_success);
    }
}

/* ==================== ETH Bridge ==================== */

static void eth_tester_do_eth_bridge(EthTesterApp* app) {
    /* Helper macro for status updates */
    #define BRIDGE_SET_STATUS(msg) \
        with_view_model(app->view_bridge, BridgeViewModel* vm, \
            { vm->active = false; vm->status_line = (msg); }, true)

    /* Step 1: Initialize W5500 */
    if(!eth_tester_ensure_w5500(app)) {
        BRIDGE_SET_STATUS("W5500 Not Found!\nCheck SPI wiring.");
        if(app->setting_sound) notification_message(app->notifications, &sequence_error);
        return;
    }

    /* Step 2: Check link */
    if(!w5500_hal_get_link_status()) {
        BRIDGE_SET_STATUS("No LAN link!\nConnect Ethernet cable.");
        if(app->setting_sound) notification_message(app->notifications, &sequence_error);
        return;
    }

    /* Read PHY info */
    bool link_up = false;
    uint8_t speed = 0, duplex = 0;
    w5500_hal_get_phy_info(&link_up, &speed, &duplex);

    /* Step 3: Open MACRAW socket */
    if(!w5500_hal_open_macraw()) {
        BRIDGE_SET_STATUS("Failed to open MACRAW!");
        if(app->setting_sound) notification_message(app->notifications, &sequence_error);
        return;
    }

    /* Step 4: Initialize USB CDC-ECM */
    BRIDGE_SET_STATUS("Starting USB Network...");

    if(!usb_eth_init()) {
        BRIDGE_SET_STATUS("USB init failed!");
        w5500_hal_close_macraw();
        if(app->setting_sound) notification_message(app->notifications, &sequence_error);
        return;
    }

    /* Step 5: Initialize bridge state and activate the view */
    eth_bridge_init(app->bridge_state);

    with_view_model(
        app->view_bridge,
        BridgeViewModel* vm,
        {
            vm->active = true;
            vm->usb_connected = false;
            vm->lan_link_up = link_up;
            vm->lan_speed = speed;
            vm->lan_duplex = duplex;
            vm->frames_to_eth = 0;
            vm->frames_to_usb = 0;
            vm->errors = 0;
        },
        true);

    if(app->setting_sound) notification_message(app->notifications, &sequence_success);

    /* Step 6: Bridge loop */
    uint32_t update_tick = 0;
    while(app->worker_running) {
        eth_bridge_poll(app->bridge_state, app->frame_buf, 1518);

        /* Update display every ~500ms (256 * 100us ≈ 25ms, so use 0x1FFF ≈ 800ms) */
        update_tick++;
        if((update_tick & 0x1FFF) == 0) {
            EthBridgeState* bs = app->bridge_state;
            with_view_model(
                app->view_bridge,
                BridgeViewModel* vm,
                {
                    vm->usb_connected = bs->usb_connected;
                    vm->lan_link_up = bs->lan_link_up;
                    vm->frames_to_eth = bs->frames_usb_to_eth;
                    vm->frames_to_usb = bs->frames_eth_to_usb;
                    vm->errors = bs->errors;
                },
                true);
        }

        furi_delay_us(100);
    }

    /* Cleanup */
    usb_eth_deinit();
    w5500_hal_close_macraw();

    EthBridgeState* bs = app->bridge_state;
    FURI_LOG_I(TAG, "ETH Bridge stopped: USB->ETH=%lu ETH->USB=%lu err=%lu",
        bs->frames_usb_to_eth, bs->frames_eth_to_usb, bs->errors);

    /* Show final stats */
    with_view_model(
        app->view_bridge,
        BridgeViewModel* vm,
        {
            vm->active = false;
            vm->status_line = "Bridge stopped. USB restored.";
        },
        true);

    #undef BRIDGE_SET_STATUS
}

/* ==================== Entry point ==================== */

int32_t eth_tester_app(void* p) {
    UNUSED(p);

    FURI_LOG_I(TAG, "LAN Tester starting");

    furi_hal_power_insomnia_enter();

    EthTesterApp* app = eth_tester_app_alloc();

    /* Start on main menu */
    eth_tester_update_menu_header(app);
    view_dispatcher_switch_to_view(app->view_dispatcher, EthTesterViewMainMenu);
    view_dispatcher_run(app->view_dispatcher);

    /* Cleanup */
    eth_tester_app_free(app);

    furi_hal_power_insomnia_exit();

    FURI_LOG_I(TAG, "LAN Tester stopped");
    return 0;
}
