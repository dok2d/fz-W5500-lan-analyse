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

/* ==================== View IDs ==================== */
typedef enum {
    EthTesterViewMainMenu,
    EthTesterViewWorkerOutput,   /* Shared TextBox for all long operations */
    EthTesterViewContPing,       /* Custom View for ping graph */
    EthTesterViewTextInput,      /* Shared TextInput for IP/hostname entry */
    EthTesterViewByteInput,      /* Shared ByteInput for MAC entry */
    EthTesterViewAbout,
    EthTesterViewCount,
} EthTesterView;

/* ==================== Operations (worker_operation values) ==================== */
typedef enum {
    OpNone = 0,
    /* --- Network Info --- */
    OpLinkInfo,
    OpLldpCdp,
    OpDhcpAnalyze,
    OpStatistics,
    /* --- Scanning --- */
    OpArpScan,
    OpPingSweep,
    OpPortScan,
    OpMdnsSsdp,
    OpStpVlan,
    /* --- Tools --- */
    OpPing,
    OpContPing,
    OpTraceroute,
    OpDnsLookup,
    OpWol,
    /* --- System --- */
    OpMacChanger,
    OpHistory,
    OpAbout,
} EthTesterOp;

/* Custom events for ViewDispatcher */
typedef enum {
    WorkerEventDone = 100,
} EthTesterCustomEvent;

/* ==================== Packet statistics ==================== */
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

/* ==================== Application state ==================== */
struct EthTesterApp {
    Gui* gui;
    ViewDispatcher* view_dispatcher;
    Submenu* submenu;
    NotificationApp* notifications;

    /* Shared output views */
    TextBox* text_box_worker;
    FuriString* worker_text;
    TextBox* text_box_about;
    FuriString* about_text;

    /* Shared input views */
    TextInput* text_input;
    ByteInput* byte_input;

    /* Continuous ping custom view */
    View* view_cont_ping;

    /* Worker thread */
    FuriThread* worker_thread;
    volatile bool worker_running;
    EthTesterOp worker_op;

    /* W5500 state */
    bool w5500_initialized;
    bool link_up;
    uint8_t link_speed;
    uint8_t link_duplex;
    uint8_t mac_addr[6];

    /* DHCP timer */
    FuriTimer* dhcp_timer;

    /* DHCP-obtained network info (cached for reuse) */
    uint8_t dhcp_ip[4];
    uint8_t dhcp_mask[4];
    uint8_t dhcp_gw[4];
    uint8_t dhcp_dns[4];
    bool dhcp_valid;

    /* Packet statistics */
    PacketStats stats;

    /* Shared input buffers */
    char ip_input_buf[20];       /* "xxx.xxx.xxx.xxx" or CIDR */
    char hostname_input_buf[64]; /* for DNS lookup */
    uint8_t mac_input_buf[6];    /* for WoL / MAC changer */

    /* Parsed targets */
    uint8_t target_ip[4];

    /* Continuous ping state */
    PingGraphState* ping_graph;
};
