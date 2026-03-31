#include "eth_tester_app.h"
#include "hal/w5500_hal.h"
#include "protocols/lldp.h"
#include "protocols/cdp.h"
#include "protocols/arp_scan.h"
#include "protocols/dhcp_discover.h"
#include "protocols/icmp.h"
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
static void eth_tester_count_frame(EthTesterApp* app, const uint8_t* frame, uint16_t len);

/* ==================== App alloc / free ==================== */

static EthTesterApp* eth_tester_app_alloc(void) {
    EthTesterApp* app = malloc(sizeof(EthTesterApp));
    memset(app, 0, sizeof(EthTesterApp));

    /* Set default MAC */
    uint8_t default_mac[6] = DEFAULT_MAC;
    memcpy(app->mac_addr, default_mac, 6);

    /* Allocate text buffers */
    app->link_info_text = furi_string_alloc();
    app->lldp_text = furi_string_alloc();
    app->arp_text = furi_string_alloc();
    app->dhcp_text = furi_string_alloc();
    app->ping_text = furi_string_alloc();
    app->stats_text = furi_string_alloc();

    /* Set initial text */
    furi_string_set(app->link_info_text, "Press OK to read\nlink status...\n");
    furi_string_set(app->lldp_text, "Listening for\nLLDP/CDP...\n");
    furi_string_set(app->arp_text, "ARP Scan ready.\nPress Back to return.\n");
    furi_string_set(app->dhcp_text, "DHCP Analyze ready.\nPress Back to return.\n");
    furi_string_set(app->ping_text, "Ping ready.\nPress Back to return.\n");
    furi_string_set(app->stats_text, "No statistics yet.\nRun LLDP/CDP or ARP\nto collect data.\n");

    /* Open GUI */
    app->gui = furi_record_open(RECORD_GUI);
    app->notifications = furi_record_open(RECORD_NOTIFICATION);

    /* ViewDispatcher */
    app->view_dispatcher = view_dispatcher_alloc();
    view_dispatcher_enable_queue(app->view_dispatcher);
    view_dispatcher_attach_to_gui(app->view_dispatcher, app->gui, ViewDispatcherTypeFullscreen);

    /* Main menu (Submenu view) */
    app->submenu = submenu_alloc();
    submenu_add_item(app->submenu, "Link Info", EthTesterMenuItemLinkInfo, eth_tester_submenu_callback, app);
    submenu_add_item(app->submenu, "LLDP/CDP", EthTesterMenuItemLldpCdp, eth_tester_submenu_callback, app);
    submenu_add_item(app->submenu, "ARP Scan", EthTesterMenuItemArpScan, eth_tester_submenu_callback, app);
    submenu_add_item(app->submenu, "DHCP Analyze", EthTesterMenuItemDhcpAnalyze, eth_tester_submenu_callback, app);
    submenu_add_item(app->submenu, "Ping", EthTesterMenuItemPing, eth_tester_submenu_callback, app);
    submenu_add_item(app->submenu, "Statistics", EthTesterMenuItemStats, eth_tester_submenu_callback, app);
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
    view_dispatcher_remove_view(app->view_dispatcher, EthTesterViewStats);

    submenu_free(app->submenu);
    text_box_free(app->text_box_link);
    text_box_free(app->text_box_lldp);
    text_box_free(app->text_box_arp);
    text_box_free(app->text_box_dhcp);
    text_box_free(app->text_box_ping);
    text_box_free(app->text_box_stats);

    view_dispatcher_free(app->view_dispatcher);

    /* Free text buffers */
    furi_string_free(app->link_info_text);
    furi_string_free(app->lldp_text);
    furi_string_free(app->arp_text);
    furi_string_free(app->dhcp_text);
    furi_string_free(app->ping_text);
    furi_string_free(app->stats_text);

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

/* ==================== Submenu callback ==================== */

static void eth_tester_submenu_callback(void* context, uint32_t index) {
    EthTesterApp* app = context;
    furi_assert(app);

    switch(index) {
    case EthTesterMenuItemLinkInfo:
        eth_tester_do_link_info(app);
        text_box_set_text(app->text_box_link, furi_string_get_cstr(app->link_info_text));
        view_dispatcher_switch_to_view(app->view_dispatcher, EthTesterViewLinkInfo);
        break;

    case EthTesterMenuItemLldpCdp:
        eth_tester_do_lldp_cdp(app);
        text_box_set_text(app->text_box_lldp, furi_string_get_cstr(app->lldp_text));
        view_dispatcher_switch_to_view(app->view_dispatcher, EthTesterViewLldp);
        break;

    case EthTesterMenuItemArpScan:
        eth_tester_do_arp_scan(app);
        text_box_set_text(app->text_box_arp, furi_string_get_cstr(app->arp_text));
        view_dispatcher_switch_to_view(app->view_dispatcher, EthTesterViewArpScan);
        break;

    case EthTesterMenuItemDhcpAnalyze:
        eth_tester_do_dhcp_analyze(app);
        text_box_set_text(app->text_box_dhcp, furi_string_get_cstr(app->dhcp_text));
        view_dispatcher_switch_to_view(app->view_dispatcher, EthTesterViewDhcpAnalyze);
        break;

    case EthTesterMenuItemPing:
        eth_tester_do_ping(app);
        text_box_set_text(app->text_box_ping, furi_string_get_cstr(app->ping_text));
        view_dispatcher_switch_to_view(app->view_dispatcher, EthTesterViewPing);
        break;

    case EthTesterMenuItemStats:
        eth_tester_do_stats(app);
        text_box_set_text(app->text_box_stats, furi_string_get_cstr(app->stats_text));
        view_dispatcher_switch_to_view(app->view_dispatcher, EthTesterViewStats);
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

    /*
     * First, get our IP via the W5500's built-in DHCP.
     * Use Socket 1 for DHCP.
     */
    uint8_t dhcp_buffer[1024];
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

    if(!got_ip) {
        furi_string_set(app->arp_text, "DHCP failed.\nCannot determine\nsubnet for ARP scan.\n");
        return;
    }

    FURI_LOG_I(TAG, "Got IP: %d.%d.%d.%d", net_info.ip[0], net_info.ip[1], net_info.ip[2], net_info.ip[3]);

    /* Calculate scan range */
    uint8_t start_ip[4], end_ip[4];
    uint16_t num_hosts = arp_calc_scan_range(net_info.ip, net_info.sn, start_ip, end_ip);

    if(num_hosts == 0) {
        furi_string_set(app->arp_text, "Subnet too large!\nMax /24 (254 hosts)\n");
        return;
    }

    char ip_str[16];
    pkt_format_ip(net_info.ip, ip_str);
    furi_string_printf(app->arp_text, "Scanning %s/%d\n%d hosts...\n", ip_str, 24, num_hosts);

    /* Open MACRAW for sending ARP requests and receiving replies */
    if(!w5500_hal_open_macraw()) {
        furi_string_set(app->arp_text, "Failed to open\nMACRAW!\n");
        return;
    }

    ArpScanState scan;
    memset(&scan, 0, sizeof(scan));
    scan.scanning = true;
    scan.start_tick = furi_get_tick();

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
        scan.total_sent++;
        current_ip++;
        batch_count++;

        /* After each batch, pause and collect replies */
        if(batch_count >= ARP_BATCH_SIZE) {
            batch_count = 0;
            furi_delay_ms(ARP_BATCH_DELAY_MS);

            /* Collect any pending replies */
            for(uint8_t i = 0; i < 20; i++) {
                uint16_t recv_len = w5500_hal_macraw_recv(frame_buf, FRAME_BUF_SIZE);
                if(recv_len == 0) break;

                uint8_t sender_mac[6], sender_ip[4];
                if(arp_parse_reply(frame_buf, recv_len, sender_mac, sender_ip)) {
                    if(scan.count < ARP_MAX_HOSTS) {
                        ArpHost* host = &scan.hosts[scan.count];
                        memcpy(host->ip, sender_ip, 4);
                        memcpy(host->mac, sender_mac, 6);
                        const char* vendor = oui_lookup(sender_mac);
                        strncpy(host->vendor, vendor, sizeof(host->vendor) - 1);
                        host->responded = true;
                        scan.count++;
                    }
                }
            }
        }
    }

    /* Wait for late replies */
    uint32_t tail_start = furi_get_tick();
    while(furi_get_tick() - tail_start < ARP_TAIL_WAIT_MS) {
        uint16_t recv_len = w5500_hal_macraw_recv(frame_buf, FRAME_BUF_SIZE);
        if(recv_len > 0) {
            uint8_t sender_mac[6], sender_ip[4];
            if(arp_parse_reply(frame_buf, recv_len, sender_mac, sender_ip)) {
                /* Check for duplicate */
                bool duplicate = false;
                for(uint8_t j = 0; j < scan.count; j++) {
                    if(memcmp(scan.hosts[j].ip, sender_ip, 4) == 0) {
                        duplicate = true;
                        break;
                    }
                }
                if(!duplicate && scan.count < ARP_MAX_HOSTS) {
                    ArpHost* host = &scan.hosts[scan.count];
                    memcpy(host->ip, sender_ip, 4);
                    memcpy(host->mac, sender_mac, 6);
                    const char* vendor = oui_lookup(sender_mac);
                    strncpy(host->vendor, vendor, sizeof(host->vendor) - 1);
                    host->responded = true;
                    scan.count++;
                }
            }
        }
        furi_delay_ms(50);
    }

    w5500_hal_close_macraw();

    scan.elapsed_ms = furi_get_tick() - scan.start_tick;
    scan.scanning = false;
    scan.complete = true;

    /* Format results */
    furi_string_reset(app->arp_text);
    furi_string_printf(
        app->arp_text,
        "Found %d hosts in %lu.%lus\n\n",
        scan.count,
        (unsigned long)(scan.elapsed_ms / 1000),
        (unsigned long)((scan.elapsed_ms % 1000) / 100));

    for(uint8_t i = 0; i < scan.count; i++) {
        ArpHost* h = &scan.hosts[i];
        char ip_buf[16], mac_buf[18];
        pkt_format_ip(h->ip, ip_buf);
        pkt_format_mac(h->mac, mac_buf);
        furi_string_cat_printf(app->arp_text, "%s\n %s\n %s\n", ip_buf, mac_buf, h->vendor);
    }

    if(scan.count == 0) {
        furi_string_cat_str(app->arp_text, "No hosts found.\n");
    }

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

    /* Build DHCP Discover */
    uint8_t dhcp_pkt[548];
    uint32_t xid;
    furi_hal_random_fill_buf((uint8_t*)&xid, sizeof(xid));
    uint16_t pkt_len = dhcp_build_discover(dhcp_pkt, app->mac_addr, xid);

    /* Send to broadcast 255.255.255.255:67 */
    uint8_t bcast_ip[4] = {255, 255, 255, 255};
    int32_t sent = sendto(dhcp_socket, dhcp_pkt, pkt_len, bcast_ip, DHCP_SERVER_PORT);
    if(sent <= 0) {
        furi_string_set(app->dhcp_text, "Failed to send\nDHCP Discover!\n");
        close(dhcp_socket);
        return;
    }

    FURI_LOG_I(TAG, "DHCP Discover sent (xid=0x%08lX)", (unsigned long)xid);

    /* Wait for DHCP Offer */
    DhcpAnalyzeResult dhcp_result;
    bool got_offer = false;
    uint32_t start_tick = furi_get_tick();
    uint8_t recv_buf[1024];

    while(furi_get_tick() - start_tick < 10000) { /* 10 sec timeout */
        uint16_t rx_size = getSn_RX_RSR(dhcp_socket);
        if(rx_size > 0) {
            uint8_t from_ip[4];
            uint16_t from_port;
            int32_t received = recvfrom(dhcp_socket, recv_buf, sizeof(recv_buf), from_ip, &from_port);
            if(received > 0) {
                if(dhcp_parse_offer(recv_buf, (uint16_t)received, xid, &dhcp_result)) {
                    got_offer = true;
                    break;
                }
            }
        }
        furi_delay_ms(50);
    }

    close(dhcp_socket);

    /* Restore network settings */
    memcpy(net_info.ip, saved_ip, 4);
    memcpy(net_info.sn, saved_sn, 4);
    memcpy(net_info.gw, saved_gw, 4);
    wizchip_setnetinfo(&net_info);

    /* Format results */
    furi_string_reset(app->dhcp_text);

    if(got_offer) {
        char result_buf[768];
        dhcp_format_result(&dhcp_result, result_buf, sizeof(result_buf));
        furi_string_set(app->dhcp_text, result_buf);
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

    uint8_t dhcp_buffer[1024];
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

    if(!got_ip) {
        furi_string_set(app->ping_text, "DHCP failed.\nCannot ping.\n");
        return;
    }

    /* Ping the gateway */
    uint8_t target_ip[4];
    memcpy(target_ip, net_info.gw, 4);

    char target_str[16], my_ip_str[16];
    pkt_format_ip(target_ip, target_str);
    pkt_format_ip(net_info.ip, my_ip_str);

    furi_string_printf(
        app->ping_text,
        "My IP: %s\nPing %s\n\n",
        my_ip_str,
        target_str);

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
        furi_delay_ms(100);
    }
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
