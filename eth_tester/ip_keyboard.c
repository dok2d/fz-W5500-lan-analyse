#include "ip_keyboard.h"

#include <gui/elements.h>
#include <furi.h>
#include <stdio.h>
#include <string.h>

/* ── View-model stored inside the View ── */

typedef struct {
    uint8_t octets[4];
    uint8_t prefix;   /* CIDR prefix length 0-32 */
    bool cidr_mode;
    uint8_t selected; /* 0-3 = octet, 4 = prefix (CIDR only) */

    const char* header;

    char* result_str;
    uint8_t result_str_size;

    IpKeyboardCallback callback;
    void* callback_context;
} IpKeyboardModel;

struct IpKeyboard {
    View* view;
};

/* ── Helpers ── */

/** Parse "x.x.x.x" or "x.x.x.x/p" into octets[] and prefix. */
static void ip_keyboard_parse(
    const char* str,
    uint8_t octets[4],
    uint8_t* prefix) {
    unsigned int a = 0, b = 0, c = 0, d = 0, p = 24;
    if(!str || !str[0]) {
        memset(octets, 0, 4);
        *prefix = 24;
        return;
    }
    /* Try CIDR first */
    if(sscanf(str, "%u.%u.%u.%u/%u", &a, &b, &c, &d, &p) >= 4) {
        /* OK */
    } else {
        a = b = c = d = 0;
        p = 24;
    }
    octets[0] = (a > 255) ? 255 : (uint8_t)a;
    octets[1] = (b > 255) ? 255 : (uint8_t)b;
    octets[2] = (c > 255) ? 255 : (uint8_t)c;
    octets[3] = (d > 255) ? 255 : (uint8_t)d;
    *prefix = (p > 32) ? 32 : (uint8_t)p;
}

/* ── Draw callback ── */

/*
 * Screen layout (128 x 64):
 *
 *  y= 2  Header text                     (FontSecondary)
 *  y=18  Up-arrow chevrons above selected (drawn as two lines)
 *  y=24..38  Octet boxes                  (FontPrimary, baseline 36)
 *  y=44  Down-arrow chevrons below selected
 *  y=62  Hint line                        (FontSecondary)
 */

static void ip_keyboard_draw(Canvas* canvas, void* model) {
    IpKeyboardModel* m = model;
    canvas_clear(canvas);

    /* ── Header ── */
    canvas_set_font(canvas, FontSecondary);
    canvas_draw_str_aligned(
        canvas,
        64,
        2,
        AlignCenter,
        AlignTop,
        m->header ? m->header : "Enter IP address:");

    /* ── Prepare font metrics ── */
    canvas_set_font(canvas, FontPrimary);

    /* Measure the widest possible octet string "255" to size boxes uniformly */
    uint8_t octet_box_w = canvas_string_width(canvas, "255") + 6; /* 3px pad each side */
    uint8_t dot_gap = 4; /* pixels between box edge and dot, and dot and next box */

    /* Dot width */
    uint8_t dot_w = canvas_string_width(canvas, ".");

    /* Total width of the four octets + three dots */
    uint16_t total_w = (uint16_t)(4 * octet_box_w + 3 * (dot_gap + dot_w + dot_gap));

    uint8_t slash_w = 0;
    uint8_t prefix_box_w = 0;
    if(m->cidr_mode) {
        slash_w = canvas_string_width(canvas, "/");
        prefix_box_w = canvas_string_width(canvas, "32") + 6;
        total_w += dot_gap + slash_w + 2 + prefix_box_w;
    }

    uint8_t sx = (128 > total_w) ? (uint8_t)((128 - total_w) / 2) : 0;
    uint8_t y_base = 36; /* text baseline */
    uint8_t box_top = y_base - 12;
    uint8_t box_h = 16;

    /* ── Draw each octet ── */
    uint8_t x = sx;
    char buf[4];

    for(uint8_t i = 0; i < 4; i++) {
        snprintf(buf, sizeof(buf), "%d", m->octets[i]);
        uint8_t str_w = canvas_string_width(canvas, buf);
        uint8_t text_x = x + (octet_box_w - str_w) / 2;

        if(i == m->selected) {
            /* Inverted rounded box */
            canvas_draw_rbox(canvas, x, box_top, octet_box_w, box_h, 3);
            canvas_set_color(canvas, ColorWhite);
            canvas_draw_str(canvas, text_x, y_base, buf);
            canvas_set_color(canvas, ColorBlack);

            /* Up chevron */
            uint8_t cx = x + octet_box_w / 2;
            uint8_t arrow_y = box_top - 5;
            canvas_draw_line(canvas, cx - 4, arrow_y + 4, cx, arrow_y);
            canvas_draw_line(canvas, cx, arrow_y, cx + 4, arrow_y + 4);

            /* Down chevron */
            arrow_y = box_top + box_h + 2;
            canvas_draw_line(canvas, cx - 4, arrow_y, cx, arrow_y + 4);
            canvas_draw_line(canvas, cx, arrow_y + 4, cx + 4, arrow_y);
        } else {
            canvas_draw_rframe(canvas, x, box_top, octet_box_w, box_h, 3);
            canvas_draw_str(canvas, text_x, y_base, buf);
        }

        x += octet_box_w;

        /* Dot separator (except after last octet) */
        if(i < 3) {
            x += dot_gap;
            canvas_draw_str(canvas, x, y_base, ".");
            x += dot_w + dot_gap;
        }
    }

    /* ── CIDR prefix ── */
    if(m->cidr_mode) {
        x += dot_gap;
        canvas_draw_str(canvas, x, y_base, "/");
        x += slash_w + 2;

        snprintf(buf, sizeof(buf), "%d", m->prefix);
        uint8_t str_w = canvas_string_width(canvas, buf);
        uint8_t text_x = x + (prefix_box_w - str_w) / 2;

        if(m->selected == 4) {
            canvas_draw_rbox(canvas, x, box_top, prefix_box_w, box_h, 3);
            canvas_set_color(canvas, ColorWhite);
            canvas_draw_str(canvas, text_x, y_base, buf);
            canvas_set_color(canvas, ColorBlack);

            uint8_t cx = x + prefix_box_w / 2;
            uint8_t arrow_y = box_top - 5;
            canvas_draw_line(canvas, cx - 4, arrow_y + 4, cx, arrow_y);
            canvas_draw_line(canvas, cx, arrow_y, cx + 4, arrow_y + 4);

            arrow_y = box_top + box_h + 2;
            canvas_draw_line(canvas, cx - 4, arrow_y, cx, arrow_y + 4);
            canvas_draw_line(canvas, cx, arrow_y + 4, cx + 4, arrow_y);
        } else {
            canvas_draw_rframe(canvas, x, box_top, prefix_box_w, box_h, 3);
            canvas_draw_str(canvas, text_x, y_base, buf);
        }
    }

    /* ── Hint line ── */
    canvas_set_font(canvas, FontSecondary);
    canvas_draw_str_aligned(
        canvas, 64, 62, AlignCenter, AlignBottom, "<> move  ^v edit  OK send");
}

/* ── Input callback ── */

static bool ip_keyboard_input(InputEvent* event, void* context) {
    IpKeyboard* kb = context;

    /* We handle Short, Long, and Repeat events for Up/Down/Left/Right/OK.
     * Back is left unhandled so view_dispatcher uses previous_callback. */

    if(event->key == InputKeyBack) {
        return false; /* let view_dispatcher navigate back */
    }

    if(event->type != InputTypeShort && event->type != InputTypeLong &&
       event->type != InputTypeRepeat) {
        return false;
    }

    IpKeyboardCallback callback = NULL;
    void* cb_context = NULL;

    with_view_model(
        kb->view,
        IpKeyboardModel * m,
        {
            /* Delta: +1 for short/repeat, +10 for long press */
            int delta = (event->type == InputTypeLong) ? 10 : 1;
            uint8_t max_sel = m->cidr_mode ? 4 : 3;

            switch(event->key) {
            case InputKeyUp:
                if(m->selected < 4) {
                    m->octets[m->selected] =
                        (uint8_t)((m->octets[m->selected] + delta) & 0xFF);
                } else {
                    int v = m->prefix + delta;
                    m->prefix = (v > 32) ? 32 : (uint8_t)v;
                }
                break;

            case InputKeyDown:
                if(m->selected < 4) {
                    m->octets[m->selected] =
                        (uint8_t)((m->octets[m->selected] - delta + 256) & 0xFF);
                } else {
                    int v = (int)m->prefix - delta;
                    m->prefix = (v < 0) ? 0 : (uint8_t)v;
                }
                break;

            case InputKeyLeft:
                if(m->selected > 0) m->selected--;
                break;

            case InputKeyRight:
                if(m->selected < max_sel) m->selected++;
                break;

            case InputKeyOk:
                if(event->type == InputTypeShort) {
                    /* Format result string */
                    if(m->result_str && m->result_str_size > 0) {
                        if(m->cidr_mode) {
                            snprintf(
                                m->result_str,
                                m->result_str_size,
                                "%d.%d.%d.%d/%d",
                                m->octets[0],
                                m->octets[1],
                                m->octets[2],
                                m->octets[3],
                                m->prefix);
                        } else {
                            snprintf(
                                m->result_str,
                                m->result_str_size,
                                "%d.%d.%d.%d",
                                m->octets[0],
                                m->octets[1],
                                m->octets[2],
                                m->octets[3]);
                        }
                    }
                    callback = m->callback;
                    cb_context = m->callback_context;
                }
                break;

            default:
                break;
            }
        },
        true);

    /* Fire the callback outside the model lock */
    if(callback) {
        callback(cb_context);
    }

    return true;
}

/* ── Public API ── */

IpKeyboard* ip_keyboard_alloc(void) {
    IpKeyboard* kb = malloc(sizeof(IpKeyboard));
    kb->view = view_alloc();

    view_allocate_model(kb->view, ViewModelTypeLocking, sizeof(IpKeyboardModel));
    view_set_draw_callback(kb->view, ip_keyboard_draw);
    view_set_input_callback(kb->view, ip_keyboard_input);
    view_set_context(kb->view, kb);

    /* Sensible defaults */
    with_view_model(
        kb->view,
        IpKeyboardModel * m,
        {
            m->octets[0] = 192;
            m->octets[1] = 168;
            m->octets[2] = 1;
            m->octets[3] = 1;
            m->prefix = 24;
            m->cidr_mode = false;
            m->selected = 0;
            m->header = "Enter IP address:";
            m->result_str = NULL;
            m->result_str_size = 0;
            m->callback = NULL;
            m->callback_context = NULL;
        },
        false);

    return kb;
}

void ip_keyboard_free(IpKeyboard* kb) {
    furi_assert(kb);
    view_free(kb->view);
    free(kb);
}

View* ip_keyboard_get_view(IpKeyboard* kb) {
    furi_assert(kb);
    return kb->view;
}

void ip_keyboard_setup(
    IpKeyboard* kb,
    const char* header,
    const char* initial_str,
    bool cidr_mode,
    IpKeyboardCallback callback,
    void* context,
    char* result_buffer,
    uint8_t result_size,
    ViewNavigationCallback back_callback) {
    furi_assert(kb);

    uint8_t octets[4];
    uint8_t prefix;
    ip_keyboard_parse(initial_str, octets, &prefix);

    with_view_model(
        kb->view,
        IpKeyboardModel * m,
        {
            memcpy(m->octets, octets, 4);
            m->prefix = prefix;
            m->cidr_mode = cidr_mode;
            m->selected = 0;
            m->header = header;
            m->result_str = result_buffer;
            m->result_str_size = result_size;
            m->callback = callback;
            m->callback_context = context;
        },
        true);

    view_set_previous_callback(kb->view, back_callback);
}
