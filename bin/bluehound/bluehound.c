#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <errno.h>

#include <sys/socket.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>

static int running = 1;

void stop_running(int sig) {
    running = 0;
}

void print_json(const char *mac, int rssi, const char *name) {
    const char *level = "weak";

    if (rssi >= -55) level = "strong";
    else if (rssi >= -70) level = "medium";

    printf(
        "{\"mac\":\"%s\",\"name\":\"%s\",\"rssi\":%d,\"level\":\"%s\"}\n",
        mac,
        name && strlen(name) ? name : "Unknown BLE",
        rssi,
        level
    );

    fflush(stdout);
}

void parse_name(uint8_t *data, int len, char *name, size_t name_size) {
    int index = 0;

    while (index < len) {
        uint8_t field_len = data[index];

        if (field_len == 0) break;
        if (index + field_len >= len) break;

        uint8_t type = data[index + 1];

        if (type == 0x08 || type == 0x09) {
            int name_len = field_len - 1;

            if (name_len > 0 && name_len < (int)name_size) {
                memcpy(name, &data[index + 2], name_len);
                name[name_len] = '\0';
                return;
            }
        }

        index += field_len + 1;
    }

    strncpy(name, "Unknown BLE", name_size - 1);
}

int main() {
    signal(SIGINT, stop_running);
    signal(SIGTERM, stop_running);

    int dev_id = hci_get_route(NULL);

    if (dev_id < 0) {
        fprintf(stderr, "No Bluetooth adapter found\n");
        return 1;
    }

    int sock = hci_open_dev(dev_id);

    if (sock < 0) {
        fprintf(stderr, "Could not open Bluetooth adapter\n");
        return 1;
    }

    le_set_scan_parameters_cp scan_params;
    memset(&scan_params, 0, sizeof(scan_params));

    scan_params.type = 0x01;
    scan_params.interval = htobs(0x0010);
    scan_params.window = htobs(0x0010);
    scan_params.own_bdaddr_type = 0x00;
    scan_params.filter = 0x00;

    struct hci_request rq;
    memset(&rq, 0, sizeof(rq));

    rq.ogf = OGF_LE_CTL;
    rq.ocf = OCF_LE_SET_SCAN_PARAMETERS;
    rq.cparam = &scan_params;
    rq.clen = LE_SET_SCAN_PARAMETERS_CP_SIZE;

    if (hci_send_req(sock, &rq, 1000) < 0) {
        fprintf(stderr, "Failed to set BLE scan parameters\n");
        close(sock);
        return 1;
    }

    le_set_scan_enable_cp scan_enable;
    memset(&scan_enable, 0, sizeof(scan_enable));

    scan_enable.enable = 0x01;
    scan_enable.filter_dup = 0x00;

    memset(&rq, 0, sizeof(rq));

    rq.ogf = OGF_LE_CTL;
    rq.ocf = OCF_LE_SET_SCAN_ENABLE;
    rq.cparam = &scan_enable;
    rq.clen = LE_SET_SCAN_ENABLE_CP_SIZE;

    if (hci_send_req(sock, &rq, 1000) < 0) {
        fprintf(stderr, "Failed to enable BLE scanning\n");
        close(sock);
        return 1;
    }

    struct hci_filter old_filter;
    socklen_t old_filter_len = sizeof(old_filter);

    if (getsockopt(sock, SOL_HCI, HCI_FILTER, &old_filter, &old_filter_len) < 0) {
        fprintf(stderr, "Could not get HCI filter\n");
    }

    struct hci_filter new_filter;
    hci_filter_clear(&new_filter);
    hci_filter_set_ptype(HCI_EVENT_PKT, &new_filter);
    hci_filter_set_event(EVT_LE_META_EVENT, &new_filter);

    if (setsockopt(sock, SOL_HCI, HCI_FILTER, &new_filter, sizeof(new_filter)) < 0) {
        fprintf(stderr, "Could not set HCI filter\n");
        close(sock);
        return 1;
    }

    printf("{\"status\":\"bluehound_ble_started\"}\n");
    fflush(stdout);

    while (running) {
        unsigned char buf[HCI_MAX_EVENT_SIZE];
        int len = read(sock, buf, sizeof(buf));

        if (len < 0) {
            if (errno == EINTR) continue;
            usleep(100000);
            continue;
        }

        evt_le_meta_event *meta = (evt_le_meta_event *)(buf + HCI_EVENT_HDR_SIZE + 1);

        if (meta->subevent != EVT_LE_ADVERTISING_REPORT) {
            continue;
        }

        le_advertising_info *info = (le_advertising_info *)(meta->data + 1);

        char mac[18];
        ba2str(&info->bdaddr, mac);

        int rssi = (int8_t)info->data[info->length];

        char name[64] = {0};
        parse_name(info->data, info->length, name, sizeof(name));

        print_json(mac, rssi, name);
    }

    scan_enable.enable = 0x00;
    scan_enable.filter_dup = 0x00;

    memset(&rq, 0, sizeof(rq));

    rq.ogf = OGF_LE_CTL;
    rq.ocf = OCF_LE_SET_SCAN_ENABLE;
    rq.cparam = &scan_enable;
    rq.clen = LE_SET_SCAN_ENABLE_CP_SIZE;

    hci_send_req(sock, &rq, 1000);

    setsockopt(sock, SOL_HCI, HCI_FILTER, &old_filter, sizeof(old_filter));

    printf("{\"status\":\"bluehound_ble_stopped\"}\n");
    fflush(stdout);

    close(sock);
    return 0;
}
