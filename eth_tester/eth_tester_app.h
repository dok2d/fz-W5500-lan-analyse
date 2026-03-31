#pragma once

#include <furi.h>
#include <gui/gui.h>
#include <gui/view_dispatcher.h>
#include <gui/modules/submenu.h>
#include <gui/modules/text_box.h>
#include <gui/modules/text_input.h>
#include <gui/modules/byte_input.h>
#include <gui/view.h>
#include <notification/notification_messages.h>
#include "protocols/ping_graph.h"

/* Forward declarations */
typedef struct EthTesterApp EthTesterApp;

/* View IDs for ViewDispatcher */
typedef enum {
    EthTesterViewMainMenu,
    EthTesterViewLinkInfo,
    EthTesterViewLldp,
    EthTesterViewArpScan,
    EthTesterViewDhcpAnalyze,
    EthTesterViewPing,
    EthTesterViewPingInput,
    EthTesterViewStats,
    EthTesterViewDnsLookup,
    EthTesterViewDnsInput,
    EthTesterViewWol,
    EthTesterViewWolInput,
    EthTesterViewContPing,
    EthTesterViewContPingInput,
    EthTesterViewCount,
} EthTesterView;

/* Main menu item indices */
typedef enum {
    EthTesterMenuItemLinkInfo,
    EthTesterMenuItemLldpCdp,
    EthTesterMenuItemArpScan,
    EthTesterMenuItemDhcpAnalyze,
    EthTesterMenuItemPing,
    EthTesterMenuItemStats,
    EthTesterMenuItemDnsLookup,
    EthTesterMenuItemWol,
    EthTesterMenuItemContPing,
} EthTesterMenuItem;

/* Packet statistics counters */
typedef struct {
    uint32_t total_frames;
    uint32_t broadcast_frames;
    uint32_t multicast_frames;
    uint32_t unicast_frames;
    uint32_t ipv4_frames;
    uint32_t arp_frames;
    uint32_t ipv6_frames;
    uint32_t lldp_frames;
    uint32_t cdp_frames;
    uint32_t unknown_frames;
} PacketStats;

/* Application state */
struct EthTesterApp {
    Gui* gui;
    ViewDispatcher* view_dispatcher;
    Submenu* submenu;
    TextBox* text_box_link;
    TextBox* text_box_lldp;
    TextBox* text_box_arp;
    TextBox* text_box_dhcp;
    TextBox* text_box_ping;
    TextBox* text_box_stats;
    TextBox* text_box_dns;
    TextBox* text_box_wol;
    TextInput* text_input_ping;
    TextInput* text_input_dns;
    ByteInput* byte_input_wol;
    View* view_cont_ping;
    TextInput* text_input_cont_ping;
    NotificationApp* notifications;

    /* W5500 state */
    bool w5500_initialized;
    bool spi_acquired;
    bool link_up;
    uint8_t link_speed;   /* 0 = 10M, 1 = 100M */
    uint8_t link_duplex;  /* 0 = half, 1 = full */
    uint8_t mac_addr[6];

    /* DHCP timer (1 second periodic for DHCP_time_handler) */
    FuriTimer* dhcp_timer;

    /* Custom ping target IP (parsed from user input) */
    uint8_t ping_ip_custom[4];
    char ping_ip_input[16]; /* text input buffer "xxx.xxx.xxx.xxx" */

    /* Packet statistics */
    PacketStats stats;

    /* DNS lookup state */
    char dns_hostname_input[64]; /* text input buffer for hostname */
    uint8_t dns_server_ip[4];   /* DNS server from DHCP */

    /* Wake-on-LAN state */
    uint8_t wol_mac_input[6]; /* byte input buffer for MAC */

    /* Continuous ping state */
    char cont_ping_ip_input[16]; /* text input buffer */
    uint8_t cont_ping_target[4]; /* parsed target IP */
    PingGraphState* ping_graph;  /* heap-allocated ping graph state */

    /* Text buffers for views */
    FuriString* link_info_text;
    FuriString* lldp_text;
    FuriString* arp_text;
    FuriString* dhcp_text;
    FuriString* ping_text;
    FuriString* stats_text;
    FuriString* dns_text;
    FuriString* wol_text;
};
