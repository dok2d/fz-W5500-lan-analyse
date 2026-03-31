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

/* Frame receive buffer (shared, used one operation at a time) */
#define FRAME_BUF_SIZE 1600
static uint8_t frame_buf[FRAME_BUF_SIZE];

/* ==================== Forward declarations ==================== */

static void eth_tester_submenu_callback(void* context, uint32_t index);
static uint32_t eth_tester_navigation_exit_callback(void* context);
static uint32_t eth_tester_navigation_submenu_callback(void* context);

static void eth_tester_do_link_info(EthTesterApp* app);
static void eth_tester_do_lldp_cdp(EthTesterApp* app);
static void eth_tester_do_arp_scan(EthTesterApp* app);
static void eth_tester_do_dhcp_analyze(EthTesterApp* app);
static void eth_tester_do_ping(EthTesterApp* app);
static void eth_tester_do_stats(EthTesterApp* app);
static void eth_tester_do_dns_lookup(EthTesterApp* app);
static void eth_tester_do_wol(EthTesterApp* app);
static void eth_tester_do_cont_ping(EthTesterApp* app);
static void eth_tester_count_frame(EthTesterApp* app, const uint8_t* frame, uint16_t len);
static void eth_tester_save_results(const char* filename, const char* content);

/* ==================== App alloc / free ==================== */

static EthTesterApp* eth_tester_app_alloc(void) {
    EthTesterApp* app = malloc(sizeof(EthTesterApp));
    memset(app, 0, sizeof(EthTesterApp));

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

    /* Set initial text */
    furi_string_set(app->link_info_text, "Press OK to read\nlink status...\n");
    furi_string_set(app->lldp_text, "Listening for\nLLDP/CDP...\n");
    furi_string_set(app->arp_text, "ARP Scan ready.\nPress Back to return.\n");
    furi_string_set(app->dhcp_text, "DHCP Analyze ready.\nPress Back to return.\n");
    furi_string_set(app->ping_text, "Ping ready.\nPress Back to return.\n");
    furi_string_set(app->stats_text, "No statistics yet.\nRun LLDP/CDP or ARP\nto collect data.\n");
    furi_string_set(app->dns_text, "DNS Lookup ready.\n");
    furi_string_set(app->wol_text, "Wake-on-LAN ready.\n");

    /* Open GUI */
    app->gui = furi_record_open(RECORD_GUI);
    app->notifications = furi_record_open(RECORD_NOTIFICATION);

    /* ViewDispatcher */
    app->view_dispatcher = view_dispatcher_alloc();
    view_dispatcher_attach_to_gui(app->view_dispatcher, app->gui, ViewDispatcherTypeFullscreen);

    /* Main menu (Submenu view) */
    app->submenu = submenu_alloc();
    submenu_add_item(app->submenu, "Link Info", EthTesterMenuItemLinkInfo, eth_tester_submenu_callback, app);
    submenu_add_item(app->submenu, "LLDP/CDP", EthTesterMenuItemLldpCdp, eth_tester_submenu_callback, app);
    submenu_add_item(app->submenu, "ARP Scan", EthTesterMenuItemArpScan, eth_tester_submenu_callback, app);
    submenu_add_item(app->submenu, "DHCP Analyze", EthTesterMenuItemDhcpAnalyze, eth_tester_submenu_callback, app);
    submenu_add_item(app->submenu, "Ping", EthTesterMenuItemPing, eth_tester_submenu_callback, app);
    submenu_add_item(app->submenu, "Statistics", EthTesterMenuItemStats, eth_tester_submenu_callback, app);
    submenu_add_item(app->submenu, "DNS Lookup", EthTesterMenuItemDnsLookup, eth_tester_submenu_callback, app);
    submenu_add_item(app->submenu, "Wake-on-LAN", EthTesterMenuItemWol, eth_tester_submenu_callback, app);
    submenu_add_item(app->submenu, "Continuous Ping", EthTesterMenuItemContPing, eth_tester_submenu_callback, app);
    view_set_previous_callback(submenu_get_view(app->submenu), eth_tester_navigation_exit_callback);
    view_dispatcher_add_view(app->view_dispatcher, EthTesterViewMainMenu, submenu_get_view(app->submenu));

    /* TextBox views for each feature */
    app->text_box_link = text_box_alloc();
    text_box_set_font(app->text_box_link, TextBoxFontText);
    view_set_previous_callback(text_box_get_view(app->text_box_link), eth_tester_navigation_submenu_callback);
    view_dispatcher_add_view(app->view_dispatcher, EthTesterViewLinkInfo, text_box_get_view(app->text_box_link));

    app->text_box_lldp = text_box_alloc();
    text_box_set_font(app->text_box_lldp, TextBoxFontText);
    view_set_previous_callback(text_box_get_view(app->text_box_lldp), eth_tester_navigation_submenu_callback);
    view_dispatcher_add_view(app->view_dispatcher, EthTesterViewLldp, text_box_get_view(app->text_box_lldp));

    app->text_box_arp = text_box_alloc();
    text_box_set_font(app->text_box_arp, TextBoxFontText);
    view_set_previous_callback(text_box_get_view(app->text_box_arp), eth_tester_navigation_submenu_callback);
    view_dispatcher_add_view(app->view_dispatcher, EthTesterViewArpScan, text_box_get_view(app->text_box_arp));

    app->text_box_dhcp = text_box_alloc();
    text_box_set_font(app->text_box_dhcp, TextBoxFontText);
    view_set_previous_callback(text_box_get_view(app->text_box_dhcp), eth_tester_navigation_submenu_callback);
    view_dispatcher_add_view(app->view_dispatcher, EthTesterViewDhcpAnalyze, text_box_get_view(app->text_box_dhcp));

    app->text_box_ping = text_box_alloc();
    text_box_set_font(app->text_box_ping, TextBoxFontText);
    view_set_previous_callback(text_box_get_view(app->text_box_ping), eth_tester_navigation_submenu_callback);
    view_dispatcher_add_view(app->view_dispatcher, EthTesterViewPing, text_box_get_view(app->text_box_ping));

    app->text_box_stats = text_box_alloc();
    text_box_set_font(app->text_box_stats, TextBoxFontText);
    view_set_previous_callback(text_box_get_view(app->text_box_stats), eth_tester_navigation_submenu_callback);
    view_dispatcher_add_view(app->view_dispatcher, EthTesterViewStats, text_box_get_view(app->text_box_stats));

    /* TextInput for ping target IP */
    app->text_input_ping = text_input_alloc();
    view_set_previous_callback(text_input_get_view(app->text_input_ping), eth_tester_navigation_submenu_callback);
    view_dispatcher_add_view(app->view_dispatcher, EthTesterViewPingInput, text_input_get_view(app->text_input_ping));

    /* Default ping target */
    strncpy(app->ping_ip_input, "8.8.8.8", sizeof(app->ping_ip_input));

    /* DNS Lookup views */
    app->text_box_dns = text_box_alloc();
    text_box_set_font(app->text_box_dns, TextBoxFontText);
    view_set_previous_callback(text_box_get_view(app->text_box_dns), eth_tester_navigation_submenu_callback);
    view_dispatcher_add_view(app->view_dispatcher, EthTesterViewDnsLookup, text_box_get_view(app->text_box_dns));

    app->text_input_dns = text_input_alloc();
    view_set_previous_callback(text_input_get_view(app->text_input_dns), eth_tester_navigation_submenu_callback);
    view_dispatcher_add_view(app->view_dispatcher, EthTesterViewDnsInput, text_input_get_view(app->text_input_dns));

    /* Default DNS hostname */
    strncpy(app->dns_hostname_input, "google.com", sizeof(app->dns_hostname_input));

    /* Wake-on-LAN views */
    app->text_box_wol = text_box_alloc();
    text_box_set_font(app->text_box_wol, TextBoxFontText);
    view_set_previous_callback(text_box_get_view(app->text_box_wol), eth_tester_navigation_submenu_callback);
    view_dispatcher_add_view(app->view_dispatcher, EthTesterViewWol, text_box_get_view(app->text_box_wol));

    app->byte_input_wol = byte_input_alloc();
    view_set_previous_callback(byte_input_get_view(app->byte_input_wol), eth_tester_navigation_submenu_callback);
    view_dispatcher_add_view(app->view_dispatcher, EthTesterViewWolInput, byte_input_get_view(app->byte_input_wol));

    /* Continuous Ping views */
    app->view_cont_ping = view_alloc();
    view_allocate_model(app->view_cont_ping, ViewModelTypeLocking, sizeof(ContPingViewModel));
    view_set_draw_callback(app->view_cont_ping, cont_ping_draw_callback);
    view_set_input_callback(app->view_cont_ping, cont_ping_input_callback);
    view_set_context(app->view_cont_ping, app);
    with_view_model(
        app->view_cont_ping,
        ContPingViewModel * vm,
        { vm->app = app; },
        false);
    view_dispatcher_add_view(app->view_dispatcher, EthTesterViewContPing, app->view_cont_ping);

    app->text_input_cont_ping = text_input_alloc();
    view_set_previous_callback(text_input_get_view(app->text_input_cont_ping), eth_tester_navigation_submenu_callback);
    view_dispatcher_add_view(app->view_dispatcher, EthTesterViewContPingInput, text_input_get_view(app->text_input_cont_ping));

    /* Default continuous ping target */
    strncpy(app->cont_ping_ip_input, "8.8.8.8", sizeof(app->cont_ping_ip_input));

    return app;
}

static void eth_tester_app_free(EthTesterApp* app) {
    furi_assert(app);

    /* Remove and free views */
    view_dispatcher_remove_view(app->view_dispatcher, EthTesterViewMainMenu);
    view_dispatcher_remove_view(app->view_dispatcher, EthTesterViewLinkInfo);
    view_dispatcher_remove_view(app->view_dispatcher, EthTesterViewLldp);
    view_dispatcher_remove_view(app->view_dispatcher, EthTesterViewArpScan);
    view_dispatcher_remove_view(app->view_dispatcher, EthTesterViewDhcpAnalyze);
    view_dispatcher_remove_view(app->view_dispatcher, EthTesterViewPing);
    view_dispatcher_remove_view(app->view_dispatcher, EthTesterViewPingInput);
    view_dispatcher_remove_view(app->view_dispatcher, EthTesterViewStats);
    view_dispatcher_remove_view(app->view_dispatcher, EthTesterViewDnsLookup);
    view_dispatcher_remove_view(app->view_dispatcher, EthTesterViewDnsInput);
    view_dispatcher_remove_view(app->view_dispatcher, EthTesterViewWol);
    view_dispatcher_remove_view(app->view_dispatcher, EthTesterViewWolInput);
    view_dispatcher_remove_view(app->view_dispatcher, EthTesterViewContPing);
    view_dispatcher_remove_view(app->view_dispatcher, EthTesterViewContPingInput);

    submenu_free(app->submenu);
    text_box_free(app->text_box_link);
    text_box_free(app->text_box_lldp);
    text_box_free(app->text_box_arp);
    text_box_free(app->text_box_dhcp);
    text_box_free(app->text_box_ping);
    text_input_free(app->text_input_ping);
    text_box_free(app->text_box_stats);
    text_box_free(app->text_box_dns);
    text_input_free(app->text_input_dns);
    text_box_free(app->text_box_wol);
    byte_input_free(app->byte_input_wol);
    view_free(app->view_cont_ping);
    text_input_free(app->text_input_cont_ping);

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

    /* Stop and free DHCP timer */
    furi_timer_stop(app->dhcp_timer);
    furi_timer_free(app->dhcp_timer);

    /* Deinit W5500 if initialized */
    if(app->w5500_initialized) {
        w5500_hal_deinit();
    }

    furi_record_close(RECORD_GUI);
    furi_record_close(RECORD_NOTIFICATION);

    free(app);
}

/* ==================== Navigation callbacks ==================== */

static uint32_t eth_tester_navigation_exit_callback(void* context) {
    UNUSED(context);
    return VIEW_NONE;
}

static uint32_t eth_tester_navigation_submenu_callback(void* context) {
    UNUSED(context);
    return EthTesterViewMainMenu;
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

    /* Switch to result view immediately so user sees progress */
    eth_tester_show_view(app, app->text_box_ping, EthTesterViewPing, app->ping_text, "Initializing...\n");

    /* Parse entered IP */
    if(eth_tester_parse_ip(app->ping_ip_input, app->ping_ip_custom)) {
        eth_tester_do_ping(app);
    } else {
        furi_string_set(app->ping_text, "Invalid IP address!\n");
        memset(app->ping_ip_custom, 0, 4);
    }
    eth_tester_update_view(app->text_box_ping, app->ping_text);
}

/* ==================== Continuous Ping view callbacks ==================== */

/* Model for the continuous ping custom view */
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

    /* Screen: 128x64
     * Top area (0-10): text stats
     * Graph area (12-63): line graph
     */

    /* Draw stats text at top */
    canvas_set_font(canvas, FontSecondary);

    char buf[64];
    uint32_t cur = 0;
    if(pg->sample_count > 0) {
        uint32_t last = ping_graph_get_sample(pg, pg->sample_count - 1);
        cur = (last == PING_RTT_TIMEOUT) ? 0 : last;
    }
    uint32_t avg = ping_graph_avg_rtt(pg);
    uint8_t loss = ping_graph_loss_percent(pg);

    snprintf(buf, sizeof(buf), "Cur:%lums Avg:%lums", (unsigned long)cur, (unsigned long)avg);
    canvas_draw_str(canvas, 0, 8, buf);

    uint32_t mn = (pg->rtt_min == UINT32_MAX) ? 0 : pg->rtt_min;
    snprintf(
        buf,
        sizeof(buf),
        "Min:%lu Max:%lu Loss:%d%%",
        (unsigned long)mn,
        (unsigned long)pg->rtt_max,
        loss);
    canvas_draw_str(canvas, 0, 18, buf);

    /* Graph area: y=22 to y=63, height=42 pixels, width=128 pixels */
    uint8_t graph_top = 22;
    uint8_t graph_bottom = 63;
    uint8_t graph_height = graph_bottom - graph_top;
    uint8_t graph_width = 128;

    /* Draw graph border */
    canvas_draw_line(canvas, 0, graph_top, 0, graph_bottom);
    canvas_draw_line(canvas, 0, graph_bottom, graph_width - 1, graph_bottom);

    uint16_t count = ping_graph_visible_count(pg);
    if(count == 0) return;

    /* Find max RTT for auto-scaling (exclude timeouts) */
    uint32_t max_rtt = 1; /* Minimum scale 1ms */
    for(uint16_t i = 0; i < count; i++) {
        uint32_t s = ping_graph_get_sample(pg, i);
        if(s != PING_RTT_TIMEOUT && s > max_rtt) {
            max_rtt = s;
        }
    }
    /* Add 10% headroom */
    max_rtt = max_rtt + max_rtt / 10 + 1;

    /* Draw samples as line graph, right-aligned */
    uint16_t start_x = (count < graph_width) ? (graph_width - count) : 0;
    uint16_t start_sample = (count > graph_width) ? (count - graph_width) : 0;

    int16_t prev_y = -1;
    for(uint16_t i = 0; i < count && (start_x + i - start_sample) < graph_width; i++) {
        uint16_t si = start_sample + i;
        if(si >= count) break;

        uint32_t rtt = ping_graph_get_sample(pg, si);
        uint8_t x = (uint8_t)(start_x + i - start_sample);

        if(rtt == PING_RTT_TIMEOUT) {
            /* Draw timeout marker as dot at top */
            canvas_draw_dot(canvas, x, graph_top + 1);
            canvas_draw_dot(canvas, x, graph_top + 2);
            prev_y = -1;
        } else {
            /* Scale RTT to graph height */
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
        /* Stop the ping loop */
        if(app->ping_graph) {
            app->ping_graph->running = false;
        }
        return true;
    }

    return false;
}

/* ==================== Continuous Ping IP input callback ==================== */

static void eth_tester_cont_ping_ip_input_callback(void* context) {
    EthTesterApp* app = context;
    furi_assert(app);

    if(!eth_tester_parse_ip(app->cont_ping_ip_input, app->cont_ping_target)) {
        /* Show error then return to menu */
        view_dispatcher_switch_to_view(app->view_dispatcher, EthTesterViewMainMenu);
        return;
    }

    /* Switch to the graph view */
    view_dispatcher_switch_to_view(app->view_dispatcher, EthTesterViewContPing);

    /* Run the ping loop */
    eth_tester_do_cont_ping(app);

    /* When done, return to menu */
    view_dispatcher_switch_to_view(app->view_dispatcher, EthTesterViewMainMenu);
}

/* ==================== DNS hostname input callback ==================== */

static void eth_tester_dns_input_callback(void* context) {
    EthTesterApp* app = context;
    furi_assert(app);

    eth_tester_show_view(app, app->text_box_dns, EthTesterViewDnsLookup, app->dns_text, "Initializing...\n");
    eth_tester_do_dns_lookup(app);
    eth_tester_update_view(app->text_box_dns, app->dns_text);
}

/* ==================== WoL MAC input callback ==================== */

static void eth_tester_wol_input_callback(void* context) {
    EthTesterApp* app = context;
    furi_assert(app);

    eth_tester_show_view(app, app->text_box_wol, EthTesterViewWol, app->wol_text, "Sending WoL...\n");
    eth_tester_do_wol(app);
    eth_tester_update_view(app->text_box_wol, app->wol_text);
}

/* ==================== Submenu callback ==================== */

static void eth_tester_submenu_callback(void* context, uint32_t index) {
    EthTesterApp* app = context;
    furi_assert(app);

    switch(index) {
    case EthTesterMenuItemLinkInfo:
        eth_tester_show_view(app, app->text_box_link, EthTesterViewLinkInfo, app->link_info_text, "Reading link status...\n");
        eth_tester_do_link_info(app);
        eth_tester_update_view(app->text_box_link, app->link_info_text);
        break;

    case EthTesterMenuItemLldpCdp:
        eth_tester_show_view(app, app->text_box_lldp, EthTesterViewLldp, app->lldp_text, "Listening for LLDP/CDP...\n");
        eth_tester_do_lldp_cdp(app);
        eth_tester_update_view(app->text_box_lldp, app->lldp_text);
        break;

    case EthTesterMenuItemArpScan:
        eth_tester_show_view(app, app->text_box_arp, EthTesterViewArpScan, app->arp_text, "Initializing W5500...\n");
        eth_tester_do_arp_scan(app);
        eth_tester_update_view(app->text_box_arp, app->arp_text);
        break;

    case EthTesterMenuItemDhcpAnalyze:
        eth_tester_show_view(app, app->text_box_dhcp, EthTesterViewDhcpAnalyze, app->dhcp_text, "Initializing W5500...\n");
        eth_tester_do_dhcp_analyze(app);
        eth_tester_update_view(app->text_box_dhcp, app->dhcp_text);
        break;

    case EthTesterMenuItemPing:
        text_input_reset(app->text_input_ping);
        text_input_set_header_text(app->text_input_ping, "Ping target IP:");
        text_input_set_result_callback(
            app->text_input_ping,
            eth_tester_ping_ip_input_callback,
            app,
            app->ping_ip_input,
            sizeof(app->ping_ip_input),
            false);
        view_dispatcher_switch_to_view(app->view_dispatcher, EthTesterViewPingInput);
        break;

    case EthTesterMenuItemStats:
        eth_tester_show_view(app, app->text_box_stats, EthTesterViewStats, app->stats_text, "Initializing W5500...\n");
        eth_tester_do_stats(app);
        eth_tester_update_view(app->text_box_stats, app->stats_text);
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

    case EthTesterMenuItemContPing:
        text_input_reset(app->text_input_cont_ping);
        text_input_set_header_text(app->text_input_cont_ping, "Ping target IP:");
        text_input_set_result_callback(
            app->text_input_cont_ping,
            eth_tester_cont_ping_ip_input_callback,
            app,
            app->cont_ping_ip_input,
            sizeof(app->cont_ping_ip_input),
            false);
        view_dispatcher_switch_to_view(app->view_dispatcher, EthTesterViewContPingInput);
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
        "=== Link Info ===\n"
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

    while(furi_get_tick() - start_tick < timeout_ms) {
        uint16_t recv_len = w5500_hal_macraw_recv(frame_buf, FRAME_BUF_SIZE);
        if(recv_len >= ETH_HEADER_SIZE) {
            /* Count frame for statistics */
            eth_tester_count_frame(app, frame_buf, recv_len);

            uint16_t ethertype = pkt_get_ethertype(frame_buf);

            /* Check for LLDP */
            if(ethertype == ETHERTYPE_LLDP && !lldp_neighbor.valid) {
                FURI_LOG_I(TAG, "LLDP frame received (%d bytes)", recv_len);
                if(lldp_parse(frame_buf + ETH_HEADER_SIZE, recv_len - ETH_HEADER_SIZE, &lldp_neighbor)) {
                    lldp_neighbor.last_seen_tick = furi_get_tick();
                    found = true;
                }
            }

            /* Check for CDP (LLC/SNAP) */
            if(!cdp_neighbor.valid) {
                uint16_t cdp_offset = cdp_check_frame(frame_buf, recv_len);
                if(cdp_offset > 0) {
                    FURI_LOG_I(TAG, "CDP frame received (%d bytes)", recv_len);
                    if(cdp_parse(frame_buf + cdp_offset, recv_len - cdp_offset, &cdp_neighbor)) {
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
    eth_tester_save_results("lldp_cdp.txt", furi_string_get_cstr(app->lldp_text));
}

static void eth_tester_do_arp_scan(EthTesterApp* app) {
    furi_string_reset(app->arp_text);

    if(!eth_tester_ensure_w5500(app)) {
        furi_string_set(app->arp_text, "W5500 Not Found!\n");
        return;
    }

    if(!w5500_hal_get_link_status()) {
        furi_string_set(app->arp_text, "No Link!\nConnect cable.\n");
        return;
    }

    furi_string_set(app->arp_text, "Getting IP via DHCP...\n");
    eth_tester_update_view(app->text_box_arp, app->arp_text);

    /*
     * First, get our IP via the W5500's built-in DHCP.
     * Use Socket 1 for DHCP.
     * Allocate on heap to avoid stack overflow (app stack is only 4 KB).
     */
    uint8_t* dhcp_buffer = malloc(1024);
    if(!dhcp_buffer) {
        furi_string_set(app->arp_text, "Memory alloc failed!\n");
        return;
    }
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
    while(furi_get_tick() - dhcp_start < 15000) { /* 15 sec timeout */
        uint8_t dhcp_ret = DHCP_run();
        if(dhcp_ret == DHCP_IP_LEASED || dhcp_ret == DHCP_IP_ASSIGN || dhcp_ret == DHCP_IP_CHANGED) {
            getIPfromDHCP(net_info.ip);
            getSNfromDHCP(net_info.sn);
            getGWfromDHCP(net_info.gw);
            getDNSfromDHCP(net_info.dns);
            net_info.dhcp = NETINFO_DHCP;
            wizchip_setnetinfo(&net_info);
            got_ip = true;
            break;
        }
        if(dhcp_ret == DHCP_FAILED) {
            break;
        }
        furi_delay_ms(10);
    }
    DHCP_stop();
    free(dhcp_buffer);

    if(!got_ip) {
        furi_string_set(app->arp_text, "DHCP failed.\nCannot determine\nsubnet for ARP scan.\n");
        return;
    }

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

    while(current_ip <= last_ip) {
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
                uint16_t recv_len = w5500_hal_macraw_recv(frame_buf, FRAME_BUF_SIZE);
                if(recv_len == 0) break;

                uint8_t sender_mac[6], sender_ip[4];
                if(arp_parse_reply(frame_buf, recv_len, sender_mac, sender_ip)) {
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
    while(furi_get_tick() - tail_start < ARP_TAIL_WAIT_MS) {
        uint16_t recv_len = w5500_hal_macraw_recv(frame_buf, FRAME_BUF_SIZE);
        if(recv_len > 0) {
            uint8_t sender_mac[6], sender_ip[4];
            if(arp_parse_reply(frame_buf, recv_len, sender_mac, sender_ip)) {
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
        char ip_buf[16], mac_buf[18];
        pkt_format_ip(h->ip, ip_buf);
        pkt_format_mac(h->mac, mac_buf);
        furi_string_cat_printf(app->arp_text, "%s\n %s\n %s\n", ip_buf, mac_buf, h->vendor);
    }

    if(scan->count == 0) {
        furi_string_cat_str(app->arp_text, "No hosts found.\n");
    }

    free(scan->hosts);
    free(scan);

    /* Save results to SD card */
    eth_tester_save_results("arp_scan.txt", furi_string_get_cstr(app->arp_text));
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

    while(furi_get_tick() - start_tick < 10000) { /* 10 sec timeout */
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
    eth_tester_save_results("dhcp_analyze.txt", furi_string_get_cstr(app->dhcp_text));
}

static void eth_tester_do_ping(EthTesterApp* app) {
    furi_string_reset(app->ping_text);

    if(!eth_tester_ensure_w5500(app)) {
        furi_string_set(app->ping_text, "W5500 Not Found!\n");
        return;
    }

    if(!w5500_hal_get_link_status()) {
        furi_string_set(app->ping_text, "No Link!\nConnect cable.\n");
        return;
    }

    /* First get IP via DHCP */
    furi_string_set(app->ping_text, "Getting IP via DHCP...\n");
    eth_tester_update_view(app->text_box_ping, app->ping_text);

    uint8_t* dhcp_buffer = malloc(1024);
    if(!dhcp_buffer) {
        furi_string_set(app->ping_text, "Memory alloc failed!\n");
        return;
    }
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
    while(furi_get_tick() - dhcp_start < 15000) {
        uint8_t dhcp_ret = DHCP_run();
        if(dhcp_ret == DHCP_IP_LEASED || dhcp_ret == DHCP_IP_ASSIGN || dhcp_ret == DHCP_IP_CHANGED) {
            getIPfromDHCP(net_info.ip);
            getSNfromDHCP(net_info.sn);
            getGWfromDHCP(net_info.gw);
            getDNSfromDHCP(net_info.dns);
            net_info.dhcp = NETINFO_DHCP;
            wizchip_setnetinfo(&net_info);
            got_ip = true;
            break;
        }
        if(dhcp_ret == DHCP_FAILED) break;
        furi_delay_ms(10);
    }
    DHCP_stop();
    free(dhcp_buffer);

    if(!got_ip) {
        furi_string_set(app->ping_text, "DHCP failed.\nCannot ping.\n");
        return;
    }

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
    for(uint16_t i = 1; i <= 4; i++) {
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

    if(!eth_tester_ensure_w5500(app)) {
        furi_string_set(app->dns_text, "W5500 Not Found!\n");
        return;
    }

    if(!w5500_hal_get_link_status()) {
        furi_string_set(app->dns_text, "No Link!\nConnect cable.\n");
        return;
    }

    /* Get IP and DNS server via DHCP */
    furi_string_set(app->dns_text, "Getting IP via DHCP...\n");
    eth_tester_update_view(app->text_box_dns, app->dns_text);

    uint8_t* dhcp_buffer = malloc(1024);
    if(!dhcp_buffer) {
        furi_string_set(app->dns_text, "Memory alloc failed!\n");
        return;
    }
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
    while(furi_get_tick() - dhcp_start < 15000) {
        uint8_t dhcp_ret = DHCP_run();
        if(dhcp_ret == DHCP_IP_LEASED || dhcp_ret == DHCP_IP_ASSIGN || dhcp_ret == DHCP_IP_CHANGED) {
            getIPfromDHCP(net_info.ip);
            getSNfromDHCP(net_info.sn);
            getGWfromDHCP(net_info.gw);
            getDNSfromDHCP(net_info.dns);
            net_info.dhcp = NETINFO_DHCP;
            wizchip_setnetinfo(&net_info);
            got_ip = true;
            break;
        }
        if(dhcp_ret == DHCP_FAILED) break;
        furi_delay_ms(10);
    }
    DHCP_stop();
    free(dhcp_buffer);

    if(!got_ip) {
        furi_string_set(app->dns_text, "DHCP failed.\nCannot resolve DNS.\n");
        return;
    }

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
            "=== DNS Lookup ===\n"
            "Host: %s\n"
            "DNS: %s\n\n"
            "Result: %s\n",
            app->dns_hostname_input,
            dns_str,
            ip_str);
    } else {
        furi_string_printf(
            app->dns_text,
            "=== DNS Lookup ===\n"
            "Host: %s\n"
            "DNS: %s\n\n"
            "%s\n",
            app->dns_hostname_input,
            dns_str,
            dns_result.rcode == DNS_RCODE_NXDOMAIN ? "NXDOMAIN (not found)" : "Timeout (3s)");
    }

    eth_tester_save_results("dns_lookup.txt", furi_string_get_cstr(app->dns_text));
}

/* ==================== Wake-on-LAN ==================== */

static void eth_tester_do_wol(EthTesterApp* app) {
    furi_string_reset(app->wol_text);

    if(!eth_tester_ensure_w5500(app)) {
        furi_string_set(app->wol_text, "W5500 Not Found!\n");
        return;
    }

    if(!w5500_hal_get_link_status()) {
        furi_string_set(app->wol_text, "No Link!\nConnect cable.\n");
        return;
    }

    /* Need a valid IP for sending UDP - get via DHCP */
    furi_string_set(app->wol_text, "Getting IP via DHCP...\n");
    eth_tester_update_view(app->text_box_wol, app->wol_text);

    uint8_t* dhcp_buffer = malloc(1024);
    if(!dhcp_buffer) {
        furi_string_set(app->wol_text, "Memory alloc failed!\n");
        return;
    }
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
    while(furi_get_tick() - dhcp_start < 15000) {
        uint8_t dhcp_ret = DHCP_run();
        if(dhcp_ret == DHCP_IP_LEASED || dhcp_ret == DHCP_IP_ASSIGN || dhcp_ret == DHCP_IP_CHANGED) {
            getIPfromDHCP(net_info.ip);
            getSNfromDHCP(net_info.sn);
            getGWfromDHCP(net_info.gw);
            getDNSfromDHCP(net_info.dns);
            net_info.dhcp = NETINFO_DHCP;
            wizchip_setnetinfo(&net_info);
            got_ip = true;
            break;
        }
        if(dhcp_ret == DHCP_FAILED) break;
        furi_delay_ms(10);
    }
    DHCP_stop();
    free(dhcp_buffer);

    if(!got_ip) {
        furi_string_set(app->wol_text, "DHCP failed.\nCannot send WoL.\n");
        return;
    }

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
            "=== Wake-on-LAN ===\n"
            "Target: %s\n\n"
            "Magic packet sent!\n"
            "Press Back to return.\n",
            mac_str);
    } else {
        furi_string_printf(
            app->wol_text,
            "=== Wake-on-LAN ===\n"
            "Target: %s\n\n"
            "Failed to send!\n",
            mac_str);
    }
}

/* ==================== Continuous Ping ==================== */

static void eth_tester_do_cont_ping(EthTesterApp* app) {
    if(!eth_tester_ensure_w5500(app)) return;
    if(!w5500_hal_get_link_status()) return;

    /* Get IP via DHCP */
    uint8_t* dhcp_buffer = malloc(1024);
    if(!dhcp_buffer) return;

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
    while(furi_get_tick() - dhcp_start < 15000) {
        uint8_t dhcp_ret = DHCP_run();
        if(dhcp_ret == DHCP_IP_LEASED || dhcp_ret == DHCP_IP_ASSIGN || dhcp_ret == DHCP_IP_CHANGED) {
            getIPfromDHCP(net_info.ip);
            getSNfromDHCP(net_info.sn);
            getGWfromDHCP(net_info.gw);
            getDNSfromDHCP(net_info.dns);
            net_info.dhcp = NETINFO_DHCP;
            wizchip_setnetinfo(&net_info);
            got_ip = true;
            break;
        }
        if(dhcp_ret == DHCP_FAILED) break;
        furi_delay_ms(10);
    }
    DHCP_stop();
    free(dhcp_buffer);

    if(!got_ip) return;

    /* Allocate ping graph state */
    PingGraphState* pg = malloc(sizeof(PingGraphState));
    if(!pg) return;
    ping_graph_init(pg);
    app->ping_graph = pg;

    /* Update view model */
    with_view_model(
        app->view_cont_ping,
        ContPingViewModel * vm,
        { vm->app = app; },
        true);

    /* Continuous ping loop */
    uint16_t seq = 1;
    while(pg->running) {
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
            ContPingViewModel * vm,
            { UNUSED(vm); },
            true);

        seq++;

        /* Wait for the remainder of the interval (account for ping duration) */
        uint32_t elapsed = ok ? result.rtt_ms : PING_GRAPH_TIMEOUT_MS;
        if(elapsed < PING_GRAPH_INTERVAL_MS) {
            /* Check running flag periodically during wait */
            uint32_t remaining = PING_GRAPH_INTERVAL_MS - elapsed;
            uint32_t wait_start = furi_get_tick();
            while(pg->running && (furi_get_tick() - wait_start < remaining)) {
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
    eth_tester_save_results("cont_ping.txt", furi_string_get_cstr(log));
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
        furi_string_set(app->stats_text, "Capturing frames...\n(10 seconds)\n");
        eth_tester_update_view(app->text_box_stats, app->stats_text);

        if(!w5500_hal_open_macraw()) {
            furi_string_set(app->stats_text, "Failed to open\nMACRAW!\n");
            return;
        }

        uint32_t start_tick = furi_get_tick();
        while(furi_get_tick() - start_tick < 10000) {
            uint16_t recv_len = w5500_hal_macraw_recv(frame_buf, FRAME_BUF_SIZE);
            if(recv_len >= ETH_HEADER_SIZE) {
                eth_tester_count_frame(app, frame_buf, recv_len);
            }
            furi_delay_ms(10);
        }

        w5500_hal_close_macraw();
    }

    /* Format statistics */
    PacketStats* s = &app->stats;
    furi_string_printf(
        app->stats_text,
        "=== Packet Stats ===\n"
        "Total: %lu\n"
        "Unicast: %lu\n"
        "Broadcast: %lu\n"
        "Multicast: %lu\n"
        "\n=== By EtherType ===\n"
        "IPv4: %lu\n"
        "ARP: %lu\n"
        "IPv6: %lu\n"
        "LLDP: %lu\n"
        "CDP: %lu\n"
        "Other: %lu\n",
        (unsigned long)s->total_frames,
        (unsigned long)s->unicast_frames,
        (unsigned long)s->broadcast_frames,
        (unsigned long)s->multicast_frames,
        (unsigned long)s->ipv4_frames,
        (unsigned long)s->arp_frames,
        (unsigned long)s->ipv6_frames,
        (unsigned long)s->lldp_frames,
        (unsigned long)s->cdp_frames,
        (unsigned long)s->unknown_frames);

    /* Save stats to SD card */
    eth_tester_save_results("stats.txt", furi_string_get_cstr(app->stats_text));
}

/* ==================== Save results to SD card ==================== */

static void eth_tester_save_results(const char* filename, const char* content) {
    Storage* storage = furi_record_open(RECORD_STORAGE);

    /* Ensure directory exists */
    storage_simply_mkdir(storage, APP_DATA_PATH(""));

    File* file = storage_file_alloc(storage);
    char filepath[128];
    snprintf(filepath, sizeof(filepath), APP_DATA_PATH("%s"), filename);

    if(storage_file_open(file, filepath, FSAM_WRITE, FSOM_CREATE_ALWAYS)) {
        storage_file_write(file, content, strlen(content));
        storage_file_close(file);
        FURI_LOG_I(TAG, "Results saved to %s", filepath);
    } else {
        FURI_LOG_E(TAG, "Failed to save results to %s", filepath);
    }

    storage_file_free(file);
    furi_record_close(RECORD_STORAGE);
}

/* ==================== Entry point ==================== */

int32_t eth_tester_app(void* p) {
    UNUSED(p);

    FURI_LOG_I(TAG, "LAN Tester starting");

    furi_hal_power_insomnia_enter();

    EthTesterApp* app = eth_tester_app_alloc();

    /* Start on main menu */
    view_dispatcher_switch_to_view(app->view_dispatcher, EthTesterViewMainMenu);
    view_dispatcher_run(app->view_dispatcher);

    /* Cleanup */
    eth_tester_app_free(app);

    furi_hal_power_insomnia_exit();

    FURI_LOG_I(TAG, "LAN Tester stopped");
    return 0;
}
