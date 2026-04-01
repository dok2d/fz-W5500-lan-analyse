#pragma once

#include <furi_hal_usb.h>

/**
 * USB CDC-ECM interface descriptor and configuration.
 *
 * Exposes a standard CDC-ECM (Communications Device Class - Ethernet
 * Control Model) device with:
 *   - Interface 0: CDC Communication (notifications)
 *   - Interface 1: CDC Data (Bulk IN/OUT for Ethernet frames)
 */

/* Endpoint addresses */
#define CDC_ECM_EP_NOTIF  0x81  /* IN endpoint for notifications */
#define CDC_ECM_EP_IN     0x82  /* IN endpoint: device -> host (Ethernet frames) */
#define CDC_ECM_EP_OUT    0x02  /* OUT endpoint: host -> device (Ethernet frames) */

/* Endpoint sizes (USB Full-Speed) */
#define CDC_ECM_EP_NOTIF_SIZE  16
#define CDC_ECM_EP_DATA_SIZE   64  /* Max packet size for FS bulk */

/* Maximum Ethernet frame segment size */
#define CDC_ECM_MAX_SEGMENT_SIZE 1518

/* Get the FuriHalUsbInterface for CDC-ECM */
extern FuriHalUsbInterface usb_eth_ecm_interface;
