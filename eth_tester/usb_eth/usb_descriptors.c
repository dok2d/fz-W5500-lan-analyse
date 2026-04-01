#include "usb_descriptors.h"

#include <furi.h>
#include <furi_hal.h>
#include <furi_hal_usb.h>
#include <usb.h>
#include <usb_cdc.h>

#include <string.h>

#define TAG "USB_ECM"

/* ==================== CDC-ECM Descriptor Structures ==================== */

/* CDC ECM Functional Descriptor (Table 3 in CDC ECM spec) */
struct usb_cdc_ecm_descriptor {
    uint8_t bLength;
    uint8_t bDescriptorType;
    uint8_t bDescriptorSubtype;
    uint8_t iMACAddress;        /* String index of MAC address */
    uint32_t bmEthernetStatistics;
    uint16_t wMaxSegmentSize;
    uint16_t wNumberMCFilters;
    uint8_t bNumberPowerFilters;
} __attribute__((packed));

/* Full configuration descriptor tree */
struct ecm_config_desc {
    struct usb_config_descriptor config;

    /* Interface 0: CDC Communication */
    struct usb_interface_descriptor comm_iface;
    struct usb_cdc_header_desc cdc_header;
    struct usb_cdc_union_desc cdc_union;
    struct usb_cdc_ecm_descriptor cdc_ecm;
    struct usb_endpoint_descriptor notif_ep;

    /* Interface 1: CDC Data (alt 0 = no endpoints = inactive) */
    struct usb_interface_descriptor data_iface_alt0;

    /* Interface 1: CDC Data (alt 1 = active with bulk endpoints) */
    struct usb_interface_descriptor data_iface_alt1;
    struct usb_endpoint_descriptor data_ep_out;
    struct usb_endpoint_descriptor data_ep_in;
} __attribute__((packed));

/* ==================== String Descriptors ==================== */

/* String index assignments */
#define STR_IDX_MANUFACTURER 1
#define STR_IDX_PRODUCT      2
#define STR_IDX_MAC          3

/* MAC address as a USB string: "001122334455" (12 hex chars as UTF-16) */
static struct usb_string_descriptor* ecm_str_mac = NULL;

/* ==================== Global State ==================== */

/* Ring buffer for received frames from USB host */
#define USB_RX_BUF_SIZE 2048
static uint8_t usb_rx_buf[USB_RX_BUF_SIZE];
static volatile uint16_t usb_rx_head = 0;
static volatile uint16_t usb_rx_tail = 0;
static volatile uint16_t usb_rx_frame_len = 0;  /* Length of current frame being assembled */

/* Frame assembly buffer */
#define USB_FRAME_BUF_SIZE 1520
static uint8_t usb_rx_frame[USB_FRAME_BUF_SIZE];
static volatile uint16_t usb_rx_frame_pos = 0;
static volatile bool usb_rx_frame_ready = false;

/* TX state */
static const uint8_t* usb_tx_data = NULL;
static volatile uint16_t usb_tx_len = 0;
static volatile uint16_t usb_tx_pos = 0;
static volatile bool usb_tx_busy = false;

/* Connection state */
static volatile bool ecm_connected = false;
static volatile bool ecm_data_active = false;

/* USB device handle */
static usbd_device* ecm_usbd = NULL;

/* MAC address for ECM descriptor */
static uint8_t ecm_mac[6] = {0x00, 0x08, 0xDC, 0x47, 0x47, 0x54};

/* ==================== Descriptor Data ==================== */

static const struct usb_device_descriptor ecm_dev_desc = {
    .bLength = sizeof(struct usb_device_descriptor),
    .bDescriptorType = USB_DTYPE_DEVICE,
    .bcdUSB = VERSION_BCD(2, 0, 0),
    .bDeviceClass = USB_CLASS_CDC,
    .bDeviceSubClass = 0,
    .bDeviceProtocol = 0,
    .bMaxPacketSize0 = CDC_ECM_EP_DATA_SIZE,
    .idVendor = 0x0483,   /* STMicroelectronics */
    .idProduct = 0x5741,   /* Custom PID for ECM */
    .bcdDevice = VERSION_BCD(1, 0, 0),
    .iManufacturer = STR_IDX_MANUFACTURER,
    .iProduct = STR_IDX_PRODUCT,
    .iSerialNumber = 0,
    .bNumConfigurations = 1,
};

static const struct ecm_config_desc ecm_cfg_desc = {
    .config = {
        .bLength = sizeof(struct usb_config_descriptor),
        .bDescriptorType = USB_DTYPE_CONFIGURATION,
        .wTotalLength = sizeof(struct ecm_config_desc),
        .bNumInterfaces = 2,
        .bConfigurationValue = 1,
        .iConfiguration = 0,
        .bmAttributes = USB_CFG_ATTR_RESERVED,
        .bMaxPower = USB_CFG_POWER_MA(200),
    },

    /* Interface 0: CDC Communication */
    .comm_iface = {
        .bLength = sizeof(struct usb_interface_descriptor),
        .bDescriptorType = USB_DTYPE_INTERFACE,
        .bInterfaceNumber = 0,
        .bAlternateSetting = 0,
        .bNumEndpoints = 1,
        .bInterfaceClass = USB_CLASS_CDC,
        .bInterfaceSubClass = USB_CDC_SUBCLASS_ECM,
        .bInterfaceProtocol = USB_CDC_PROTO_NONE,
        .iInterface = 0,
    },
    .cdc_header = {
        .bLength = sizeof(struct usb_cdc_header_desc),
        .bDescriptorType = USB_DTYPE_CS_INTERFACE,
        .bDescriptorSubtype = USB_DTYPE_CDC_HEADER,
        .bcdCDC = VERSION_BCD(1, 2, 0),
    },
    .cdc_union = {
        .bLength = sizeof(struct usb_cdc_union_desc),
        .bDescriptorType = USB_DTYPE_CS_INTERFACE,
        .bDescriptorSubtype = USB_DTYPE_CDC_UNION,
        .bMasterInterface0 = 0,
        .bSlaveInterface0 = 1,
    },
    .cdc_ecm = {
        .bLength = sizeof(struct usb_cdc_ecm_descriptor),
        .bDescriptorType = USB_DTYPE_CS_INTERFACE,
        .bDescriptorSubtype = 0x0F, /* Ethernet Networking Functional Descriptor */
        .iMACAddress = STR_IDX_MAC,
        .bmEthernetStatistics = 0,
        .wMaxSegmentSize = CDC_ECM_MAX_SEGMENT_SIZE,
        .wNumberMCFilters = 0,
        .bNumberPowerFilters = 0,
    },
    .notif_ep = {
        .bLength = sizeof(struct usb_endpoint_descriptor),
        .bDescriptorType = USB_DTYPE_ENDPOINT,
        .bEndpointAddress = CDC_ECM_EP_NOTIF,
        .bmAttributes = USB_EPTYPE_INTERRUPT,
        .wMaxPacketSize = CDC_ECM_EP_NOTIF_SIZE,
        .bInterval = 32,
    },

    /* Interface 1 Alt 0: Data (inactive - no endpoints) */
    .data_iface_alt0 = {
        .bLength = sizeof(struct usb_interface_descriptor),
        .bDescriptorType = USB_DTYPE_INTERFACE,
        .bInterfaceNumber = 1,
        .bAlternateSetting = 0,
        .bNumEndpoints = 0,
        .bInterfaceClass = USB_CLASS_CDC_DATA,
        .bInterfaceSubClass = 0,
        .bInterfaceProtocol = 0,
        .iInterface = 0,
    },

    /* Interface 1 Alt 1: Data (active - bulk endpoints) */
    .data_iface_alt1 = {
        .bLength = sizeof(struct usb_interface_descriptor),
        .bDescriptorType = USB_DTYPE_INTERFACE,
        .bInterfaceNumber = 1,
        .bAlternateSetting = 1,
        .bNumEndpoints = 2,
        .bInterfaceClass = USB_CLASS_CDC_DATA,
        .bInterfaceSubClass = 0,
        .bInterfaceProtocol = 0,
        .iInterface = 0,
    },
    .data_ep_out = {
        .bLength = sizeof(struct usb_endpoint_descriptor),
        .bDescriptorType = USB_DTYPE_ENDPOINT,
        .bEndpointAddress = CDC_ECM_EP_OUT,
        .bmAttributes = USB_EPTYPE_BULK,
        .wMaxPacketSize = CDC_ECM_EP_DATA_SIZE,
        .bInterval = 0,
    },
    .data_ep_in = {
        .bLength = sizeof(struct usb_endpoint_descriptor),
        .bDescriptorType = USB_DTYPE_ENDPOINT,
        .bEndpointAddress = CDC_ECM_EP_IN,
        .bmAttributes = USB_EPTYPE_BULK,
        .wMaxPacketSize = CDC_ECM_EP_DATA_SIZE,
        .bInterval = 0,
    },
};

/* ==================== String Descriptor Helpers ==================== */

static const struct usb_string_descriptor ecm_str_manufacturer = USB_STRING_DESC("Flipper Devices");
static const struct usb_string_descriptor ecm_str_product = USB_STRING_DESC("Flipper ECM Network");

static void ecm_build_mac_string(const uint8_t mac[6]) {
    /* MAC string: "001122334455" as UTF-16LE (12 chars = 24 bytes + 2 header) */
    if(ecm_str_mac) {
        free(ecm_str_mac);
    }
    ecm_str_mac = malloc(2 + 12 * 2);
    ecm_str_mac->bLength = 2 + 12 * 2;
    ecm_str_mac->bDescriptorType = USB_DTYPE_STRING;

    static const char hex[] = "0123456789ABCDEF";
    for(int i = 0; i < 6; i++) {
        ecm_str_mac->wString[i * 2] = hex[(mac[i] >> 4) & 0x0F];
        ecm_str_mac->wString[i * 2 + 1] = hex[mac[i] & 0x0F];
    }
}

/* ==================== USB Callbacks ==================== */

static usbd_respond ecm_getdesc(usbd_ctlreq* req, void** address, uint16_t* length) {
    uint8_t dtype = req->wValue >> 8;
    uint8_t dindex = req->wValue & 0xFF;

    switch(dtype) {
    case USB_DTYPE_DEVICE:
        *address = (void*)&ecm_dev_desc;
        *length = sizeof(ecm_dev_desc);
        return usbd_ack;

    case USB_DTYPE_CONFIGURATION:
        *address = (void*)&ecm_cfg_desc;
        *length = sizeof(ecm_cfg_desc);
        return usbd_ack;

    case USB_DTYPE_STRING:
        switch(dindex) {
        case 0: {
            /* Language ID descriptor (English) */
            static const struct usb_string_descriptor lang = {
                .bLength = 4,
                .bDescriptorType = USB_DTYPE_STRING,
                .wString = {0x0409},
            };
            *address = (void*)&lang;
            *length = lang.bLength;
            return usbd_ack;
        }
        case STR_IDX_MANUFACTURER:
            *address = (void*)&ecm_str_manufacturer;
            *length = ecm_str_manufacturer.bLength;
            return usbd_ack;
        case STR_IDX_PRODUCT:
            *address = (void*)&ecm_str_product;
            *length = ecm_str_product.bLength;
            return usbd_ack;
        case STR_IDX_MAC:
            if(ecm_str_mac) {
                *address = (void*)ecm_str_mac;
                *length = ecm_str_mac->bLength;
                return usbd_ack;
            }
            return usbd_fail;
        }
        break;
    }
    return usbd_fail;
}

/* CDC ECM Network Connection notification */
static const uint8_t ecm_notify_connected[] = {
    0xA1,  /* bmRequestType: class, interface, device-to-host */
    0x00,  /* bNotification: NETWORK_CONNECTION */
    0x01, 0x00,  /* wValue: Connected */
    0x00, 0x00,  /* wIndex: interface 0 */
    0x00, 0x00,  /* wLength: 0 */
};

static const uint8_t ecm_notify_speed[] = {
    0xA1,  /* bmRequestType */
    0x2A,  /* bNotification: CONNECTION_SPEED_CHANGE */
    0x00, 0x00,  /* wValue */
    0x00, 0x00,  /* wIndex: interface 0 */
    0x08, 0x00,  /* wLength: 8 */
    /* DL bitrate (10 Mbps) */
    0x80, 0x96, 0x98, 0x00,
    /* UL bitrate (10 Mbps) */
    0x80, 0x96, 0x98, 0x00,
};

static void ecm_rx_ep_callback(usbd_device* dev, uint8_t event, uint8_t ep);
static void ecm_tx_ep_callback(usbd_device* dev, uint8_t event, uint8_t ep);

static usbd_respond ecm_control(usbd_device* dev, usbd_ctlreq* req) {
    UNUSED(dev);

    /* Handle SET_INTERFACE for alt setting selection */
    if((req->bmRequestType & (USB_REQ_TYPE | USB_REQ_RECIPIENT)) ==
       (USB_REQ_STANDARD | USB_REQ_RECIPIENT_INTERFACE)) {
        if(req->bRequest == USB_STD_SET_INTERFACE) {
            if(req->wIndex == 1) {  /* Data interface */
                if(req->wValue == 1) {
                    /* Alt 1: activate data interface */
                    ecm_data_active = true;
                    FURI_LOG_I(TAG, "Data interface activated");

                    /* Send network connection notification */
                    usbd_ep_write(ecm_usbd, CDC_ECM_EP_NOTIF,
                        ecm_notify_connected, sizeof(ecm_notify_connected));

                    /* Prime the OUT endpoint for receiving */
                    usbd_ep_read(dev, CDC_ECM_EP_OUT, usb_rx_frame, CDC_ECM_EP_DATA_SIZE);

                    return usbd_ack;
                } else {
                    /* Alt 0: deactivate */
                    ecm_data_active = false;
                    FURI_LOG_I(TAG, "Data interface deactivated");
                    return usbd_ack;
                }
            }
        }
    }

    /* Handle CDC class requests */
    if((req->bmRequestType & USB_REQ_TYPE) == USB_REQ_CLASS) {
        switch(req->bRequest) {
        case 0x43: /* SET_ETHERNET_PACKET_FILTER */
            FURI_LOG_D(TAG, "SET_ETHERNET_PACKET_FILTER: 0x%04X", req->wValue);
            ecm_connected = true;
            return usbd_ack;
        }
    }

    return usbd_fail;
}

static void ecm_rx_ep_callback(usbd_device* dev, uint8_t event, uint8_t ep) {
    UNUSED(ep);

    if(event != usbd_evt_eptx) {
        /* Data received from host */
        int32_t len = usbd_ep_read(dev, CDC_ECM_EP_OUT,
            usb_rx_frame + usb_rx_frame_pos,
            CDC_ECM_EP_DATA_SIZE);

        if(len > 0) {
            usb_rx_frame_pos += len;

            /* If we got a short packet or buffer is nearly full, frame is complete */
            if(len < CDC_ECM_EP_DATA_SIZE || usb_rx_frame_pos >= USB_FRAME_BUF_SIZE - CDC_ECM_EP_DATA_SIZE) {
                usb_rx_frame_len = usb_rx_frame_pos;
                usb_rx_frame_pos = 0;
                usb_rx_frame_ready = true;
                /* Don't re-prime until frame is consumed */
                return;
            }
        }

        /* Re-prime for next packet */
        usbd_ep_read(dev, CDC_ECM_EP_OUT,
            usb_rx_frame + usb_rx_frame_pos, CDC_ECM_EP_DATA_SIZE);
    }
}

static void ecm_tx_ep_callback(usbd_device* dev, uint8_t event, uint8_t ep) {
    UNUSED(ep);

    if(event == usbd_evt_eptx) {
        /* Previous TX completed */
        if(usb_tx_data && usb_tx_pos < usb_tx_len) {
            uint16_t chunk = usb_tx_len - usb_tx_pos;
            if(chunk > CDC_ECM_EP_DATA_SIZE) chunk = CDC_ECM_EP_DATA_SIZE;
            usbd_ep_write(dev, CDC_ECM_EP_IN, usb_tx_data + usb_tx_pos, chunk);
            usb_tx_pos += chunk;
        } else {
            /* If the last chunk was exactly EP_DATA_SIZE, send ZLP */
            if(usb_tx_data && (usb_tx_len % CDC_ECM_EP_DATA_SIZE) == 0) {
                usbd_ep_write(dev, CDC_ECM_EP_IN, NULL, 0);
                usb_tx_data = NULL;
            }
            usb_tx_busy = false;
            usb_tx_data = NULL;
        }
    }
}

static usbd_respond ecm_ep_config(usbd_device* dev, uint8_t cfg) {
    switch(cfg) {
    case 0:
        /* Deconfiguration */
        usbd_ep_deconfig(dev, CDC_ECM_EP_NOTIF);
        usbd_ep_deconfig(dev, CDC_ECM_EP_IN);
        usbd_ep_deconfig(dev, CDC_ECM_EP_OUT);
        usbd_reg_endpoint(dev, CDC_ECM_EP_OUT, NULL);
        usbd_reg_endpoint(dev, CDC_ECM_EP_IN, NULL);
        ecm_connected = false;
        ecm_data_active = false;
        return usbd_ack;

    case 1:
        /* Configure endpoints */
        usbd_ep_config(dev, CDC_ECM_EP_NOTIF, USB_EPTYPE_INTERRUPT, CDC_ECM_EP_NOTIF_SIZE);
        usbd_ep_config(dev, CDC_ECM_EP_IN, USB_EPTYPE_BULK, CDC_ECM_EP_DATA_SIZE);
        usbd_ep_config(dev, CDC_ECM_EP_OUT, USB_EPTYPE_BULK, CDC_ECM_EP_DATA_SIZE);
        usbd_reg_endpoint(dev, CDC_ECM_EP_OUT, ecm_rx_ep_callback);
        usbd_reg_endpoint(dev, CDC_ECM_EP_IN, ecm_tx_ep_callback);
        return usbd_ack;

    default:
        return usbd_fail;
    }
}

/* ==================== FuriHalUsbInterface Implementation ==================== */

static void ecm_init(usbd_device* dev, FuriHalUsbInterface* intf, void* ctx) {
    UNUSED(intf);
    UNUSED(ctx);

    ecm_usbd = dev;

    /* Reset state */
    ecm_connected = false;
    ecm_data_active = false;
    usb_rx_frame_pos = 0;
    usb_rx_frame_ready = false;
    usb_rx_frame_len = 0;
    usb_tx_busy = false;
    usb_tx_data = NULL;
    usb_tx_len = 0;
    usb_tx_pos = 0;

    /* Build MAC string descriptor */
    ecm_build_mac_string(ecm_mac);

    usbd_reg_descr(dev, ecm_getdesc);
    usbd_reg_control(dev, ecm_control);
    usbd_reg_config(dev, ecm_ep_config);

    usbd_enable(dev, true);
    usbd_connect(dev, true);

    FURI_LOG_I(TAG, "CDC-ECM initialized");
}

static void ecm_deinit(usbd_device* dev) {
    usbd_reg_descr(dev, NULL);
    usbd_reg_control(dev, NULL);
    usbd_reg_config(dev, NULL);

    ecm_connected = false;
    ecm_data_active = false;
    ecm_usbd = NULL;

    if(ecm_str_mac) {
        free(ecm_str_mac);
        ecm_str_mac = NULL;
    }

    FURI_LOG_I(TAG, "CDC-ECM deinitialized");
}

static void ecm_wakeup(usbd_device* dev) {
    UNUSED(dev);
}

static void ecm_suspend(usbd_device* dev) {
    UNUSED(dev);
    ecm_connected = false;
    ecm_data_active = false;
}

/* ==================== Public Interface ==================== */

FuriHalUsbInterface usb_eth_ecm_interface = {
    .init = ecm_init,
    .deinit = ecm_deinit,
    .wakeup = ecm_wakeup,
    .suspend = ecm_suspend,
    .dev_descr = (struct usb_device_descriptor*)&ecm_dev_desc,
    .cfg_descr = (void*)&ecm_cfg_desc,
};

void usb_eth_set_mac(const uint8_t mac[6]) {
    memcpy(ecm_mac, mac, 6);
}

bool usb_eth_is_connected_internal(void) {
    return ecm_connected && ecm_data_active;
}

bool usb_eth_send_frame_internal(const uint8_t* frame, uint16_t len) {
    if(!ecm_data_active || !ecm_usbd || len == 0 || len > CDC_ECM_MAX_SEGMENT_SIZE) {
        return false;
    }

    /* Wait for previous TX to complete (with timeout) */
    uint32_t timeout = 50; /* ~50ms */
    while(usb_tx_busy && timeout > 0) {
        furi_delay_ms(1);
        timeout--;
    }
    if(usb_tx_busy) return false;

    usb_tx_busy = true;
    usb_tx_data = frame;
    usb_tx_len = len;
    usb_tx_pos = 0;

    /* Start first chunk */
    uint16_t chunk = len;
    if(chunk > CDC_ECM_EP_DATA_SIZE) chunk = CDC_ECM_EP_DATA_SIZE;
    usb_tx_pos = chunk;
    usbd_ep_write(ecm_usbd, CDC_ECM_EP_IN, frame, chunk);

    return true;
}

int16_t usb_eth_receive_frame_internal(uint8_t* frame, uint16_t max_len) {
    if(!usb_rx_frame_ready) return 0;

    uint16_t len = usb_rx_frame_len;
    if(len > max_len) len = max_len;
    if(len > 0) {
        memcpy(frame, usb_rx_frame, len);
    }

    /* Reset and re-prime the endpoint */
    usb_rx_frame_ready = false;
    usb_rx_frame_len = 0;
    usb_rx_frame_pos = 0;

    if(ecm_data_active && ecm_usbd) {
        usbd_ep_read(ecm_usbd, CDC_ECM_EP_OUT, usb_rx_frame, CDC_ECM_EP_DATA_SIZE);
    }

    return (int16_t)len;
}
