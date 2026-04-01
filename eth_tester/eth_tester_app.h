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
#include "protocols/pxe_server.h"
#include "bridge/eth_bridge.h"
#include "bridge/pcap_dump.h"
#include "ip_keyboard.h"

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
    EthTesterViewStats,
    EthTesterViewDnsLookup,
    EthTesterViewDnsInput,
    EthTesterViewWol,
    EthTesterViewWolInput,
    EthTesterViewContPing,
    EthTesterViewPortScan,
    EthTesterViewMacChanger,
    EthTesterViewMacChangerInput,
    EthTesterViewTraceroute,
    EthTesterViewTracerouteInput,
    EthTesterViewPortScanCustomInput,
    EthTesterViewPingSweep,
    EthTesterViewIpKeyboard,
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
    EthTesterViewPxeServer,
    EthTesterViewPxeSettings,
    EthTesterViewPxeHelp,
    EthTesterViewFileManager,
    EthTesterViewPacketCapture,
    EthTesterViewHostList,
    EthTesterViewHostActions,
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
    EthTesterMenuItemPortScanCustom,
    EthTesterMenuItemPingSweep,
    EthTesterMenuItemDiscovery,
    EthTesterMenuItemStpVlan,
    EthTesterMenuItemHistory,
    EthTesterMenuItemAbout,
    EthTesterMenuItemEthBridge,
    EthTesterMenuItemPxeServer,
    EthTesterMenuItemFileManager,
    EthTesterMenuItemPacketCapture,
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

/* Discovered host from scan results */
typedef struct {
    uint8_t ip[4];
    uint8_t mac[6];
    bool has_mac;
} DiscoveredHost;

#define MAX_DISCOVERED_HOSTS 64

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
    TextInput* text_input_dns;
    ByteInput* byte_input_wol;
    View* view_cont_ping;
    TextBox* text_box_port_scan;
    TextBox* text_box_mac_changer;
    ByteInput* byte_input_mac_changer;
    TextBox* text_box_traceroute;
    TextInput* text_input_traceroute;
    TextInput* text_input_port_custom;
    TextBox* text_box_ping_sweep;
    IpKeyboard* ip_keyboard;
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
    bool setting_autosave; /* auto-save results to history */
    bool setting_sound; /* LED/vibro/sound notifications */
    bool dns_custom_enabled; /* use custom DNS instead of DHCP */
    uint8_t dns_custom_server[4]; /* custom DNS IP (default 8.8.8.8) */
    char dns_custom_ip_input[16]; /* text input buffer for DNS IP */

    /* Ping settings */
    uint8_t ping_count; /* packets for normal ping (1-100, default 4) */
    uint16_t ping_timeout_ms; /* reply timeout (500-10000, step 500, default 3000) */
    uint16_t ping_interval_ms; /* continuous ping interval (200-5000, step 200, default 1000) */

    /* Worker thread for non-blocking operations */
    FuriThread* worker_thread;
    volatile bool worker_running;
    uint32_t worker_op; /* EthTesterMenuItem value */

    /* W5500 state */
    bool w5500_initialized;
    bool spi_acquired;
    bool link_up;
    uint8_t link_speed; /* 0 = 10M, 1 = 100M */
    uint8_t link_duplex; /* 0 = half, 1 = full */
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
    uint8_t dns_server_ip[4]; /* DNS server from DHCP */

    /* Wake-on-LAN state */
    uint8_t wol_mac_input[6]; /* byte input buffer for MAC */

    /* Continuous ping state */
    char cont_ping_ip_input[16]; /* text input buffer */
    uint8_t cont_ping_target[4]; /* parsed target IP */
    PingGraphState* ping_graph; /* heap-allocated ping graph state */

    /* Port scanner state */
    char port_scan_ip_input[16]; /* text input buffer */
    uint8_t port_scan_target[4]; /* parsed target IP */
    bool port_scan_top100; /* false=Top20, true=Top100 */
    bool port_scan_custom; /* true = custom range mode */
    uint16_t port_scan_custom_start; /* default 1 */
    uint16_t port_scan_custom_end; /* default 1024 */
    char port_scan_start_input[6]; /* text buffer "xxxxx" */
    char port_scan_end_input[6];

    /* MAC changer state */
    uint8_t mac_changer_input[6]; /* byte input buffer for custom MAC */

    /* Traceroute state */
    char traceroute_ip_input[16]; /* text input buffer (kept for compat) */
    uint8_t traceroute_target[4]; /* parsed target IP */
    char traceroute_host_input[64]; /* text input for IP or hostname */
    bool traceroute_is_hostname; /* true if input is hostname, not IP */

    /* Ping sweep state */
    char ping_sweep_ip_input[20]; /* "192.168.1.0/24" */

    /* ETH Bridge state */
    View* view_bridge;
    EthBridgeState* bridge_state;

    /* PXE Server state */
    TextBox* text_box_pxe;
    TextBox* text_box_pxe_help;
    FuriString* pxe_text;
    VariableItemList* pxe_settings_list;
    VariableItem* pxe_item_dhcp;
    VariableItem* pxe_item_sip;
    VariableItem* pxe_item_cip;
    VariableItem* pxe_item_sub;
    VariableItem* pxe_item_boot;

    /* PXE settings (user-configurable) */
    char pxe_server_ip_input[16]; /* "192.168.77.1" */
    char pxe_client_ip_input[16]; /* "192.168.77.10" */
    char pxe_subnet_input[16]; /* "255.255.255.0" */
    bool pxe_dhcp_enabled; /* true = run DHCP server */
    uint8_t pxe_server_ip[4]; /* parsed */
    uint8_t pxe_client_ip[4]; /* parsed */
    uint8_t pxe_subnet[4]; /* parsed */

    /* PXE boot file selection */
    PxeServerState pxe_scan; /* cached boot file scan results */
    uint8_t pxe_boot_file_idx; /* currently selected boot file */
    bool pxe_dhcp_probed; /* external DHCP already probed? */

    /* Discovered hosts from scans */
    Submenu* submenu_host_list;
    Submenu* submenu_host_actions;
    DiscoveredHost discovered_hosts[MAX_DISCOVERED_HOSTS];
    uint16_t discovered_host_count;
    uint16_t selected_host_idx;

    /* Packet Capture state */
    View* view_packet_capture;
    PcapDumpState pcap_state;
    uint32_t pcap_start_tick;

    /* File Manager state */
    TextBox* text_box_file_manager;
    FuriString* file_manager_text;

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
