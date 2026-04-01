#pragma once

#include <furi.h>
#include <gui/gui.h>
#include <gui/view_dispatcher.h>
#include <gui/modules/submenu.h>
#include <gui/modules/variable_item_list.h>
#include <gui/modules/text_box.h>
#include <gui/modules/text_input.h>
#include <gui/modules/byte_input.h>
#include <gui/view.h>
#include <notification/notification_messages.h>
#include "protocols/ping_graph.h"
#include "protocols/history.h"
#include "bridge/eth_bridge.h"

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
    EthTesterViewPortScan,
    EthTesterViewPortScanInput,
    EthTesterViewMacChanger,
    EthTesterViewMacChangerInput,
    EthTesterViewTraceroute,
    EthTesterViewTracerouteInput,
    EthTesterViewPingSweep,
    EthTesterViewPingSweepInput,
    EthTesterViewDiscovery,
    EthTesterViewStpVlan,
    EthTesterViewHistory,
    EthTesterViewHistoryFile,
    EthTesterViewAbout,
    EthTesterViewCatNetInfo,
    EthTesterViewCatDiscovery,
    EthTesterViewCatDiag,
    EthTesterViewCatTools,
    EthTesterViewSettings,
    EthTesterViewEthBridge,
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
    EthTesterMenuItemPortScan,
    EthTesterMenuItemPortScanFull,
    EthTesterMenuItemMacChanger,
    EthTesterMenuItemTraceroute,
    EthTesterMenuItemPingSweep,
    EthTesterMenuItemDiscovery,
    EthTesterMenuItemStpVlan,
    EthTesterMenuItemHistory,
    EthTesterMenuItemAbout,
    EthTesterMenuItemEthBridge,
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
    Submenu* submenu_cat_netinfo;
    Submenu* submenu_cat_discovery;
    Submenu* submenu_cat_diag;
    Submenu* submenu_cat_tools;
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
    TextBox* text_box_port_scan;
    TextInput* text_input_port_scan;
    TextBox* text_box_mac_changer;
    ByteInput* byte_input_mac_changer;
    TextBox* text_box_traceroute;
    TextInput* text_input_traceroute;
    TextBox* text_box_ping_sweep;
    TextInput* text_input_ping_sweep;
    TextBox* text_box_discovery;
    TextBox* text_box_stp_vlan;
    Submenu* submenu_history;
    TextBox* text_box_history_file;
    HistoryState* history_state;
    uint16_t history_selected; /* index of currently viewed file */
    TextBox* text_box_about;
    VariableItemList* settings_list;
    NotificationApp* notifications;

    /* User settings (persisted to SD) */
    bool setting_autosave;  /* auto-save results to history */
    bool setting_sound;     /* LED/vibro/sound notifications */

    /* Worker thread for non-blocking operations */
    FuriThread* worker_thread;
    volatile bool worker_running;
    uint32_t worker_op; /* EthTesterMenuItem value */

    /* W5500 state */
    bool w5500_initialized;
    bool spi_acquired;
    bool link_up;
    uint8_t link_speed;   /* 0 = 10M, 1 = 100M */
    uint8_t link_duplex;  /* 0 = half, 1 = full */
    uint8_t mac_addr[6];

    /* Frame receive buffer (heap-allocated, shared by worker thread) */
    uint8_t* frame_buf;

    /* DHCP timer (1 second periodic for DHCP_time_handler) */
    FuriTimer* dhcp_timer;

    /* Cached DHCP results (for auto-populating scan ranges) */
    uint8_t dhcp_ip[4];
    uint8_t dhcp_mask[4];
    uint8_t dhcp_gw[4];
    uint8_t dhcp_dns[4];
    bool dhcp_valid;

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

    /* Port scanner state */
    char port_scan_ip_input[16]; /* text input buffer */
    uint8_t port_scan_target[4]; /* parsed target IP */
    bool port_scan_top100;       /* false=Top20, true=Top100 */

    /* MAC changer state */
    uint8_t mac_changer_input[6]; /* byte input buffer for custom MAC */

    /* Traceroute state */
    char traceroute_ip_input[16]; /* text input buffer */
    uint8_t traceroute_target[4]; /* parsed target IP */

    /* Ping sweep state */
    char ping_sweep_ip_input[20]; /* "192.168.1.0/24" */

    /* ETH Bridge state */
    TextBox* text_box_bridge;
    EthBridgeState* bridge_state;
    FuriString* bridge_text;

    /* Text buffers for views */
    FuriString* link_info_text;
    FuriString* lldp_text;
    FuriString* arp_text;
    FuriString* dhcp_text;
    FuriString* ping_text;
    FuriString* stats_text;
    FuriString* dns_text;
    FuriString* wol_text;
    FuriString* port_scan_text;
    FuriString* mac_changer_text;
    FuriString* traceroute_text;
    FuriString* ping_sweep_text;
    FuriString* discovery_text;
    FuriString* stp_vlan_text;
    FuriString* history_file_text;
};
