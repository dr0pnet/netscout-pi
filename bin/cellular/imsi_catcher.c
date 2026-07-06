/*
 * Passive IMSI Catcher for RTL-SDR v5
 * Captures IMSI/TMSI from GSM control channels
 * Compile: gcc -o imsi_catcher imsi_catcher.c -lrtlsdr -losmocore -ltalloc -lfftw3 -lm -lpthread
 * Usage: sudo ./imsi_catcher -f 941.8e6 -g 40
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>
#include <math.h>
#include <time.h>
#include <getopt.h>
#include <rtl-sdr.h>
#include <osmocom/core/msgb.h>
#include <osmocom/gsm/gsm48.h>
#include <osmocom/gsm/lapdm.h>

#define SAMPLE_RATE 2048000
#define FFT_SIZE 1024
#define GSM_SYMBOL_RATE 270833

static volatile int running = 1;
static rtlsdr_dev_t *dev = NULL;

typedef struct {
    uint64_t imsi;
    uint32_t tmsi;
    int mcc, mnc, lac, cid;
    int signal_db;
    time_t first_seen;
    time_t last_seen;
    int count;
} Subscriber;

#define MAX_SUBS 1000
static Subscriber subscribers[MAX_SUBS];
static int sub_count = 0;
static pthread_mutex_t sub_mutex = PTHREAD_MUTEX_INITIALIZER;

void signal_handler(int sig) {
    running = 0;
    fprintf(stderr, "\nStopping...\n");
}

void print_banner(void) {
    printf("\033[2J\033[H"); // Clear screen
    printf("╔══════════════════════════════════════════════════════════╗\n");
    printf("║        PASSIVE IMSI CATCHER - RTL-SDR v5                ║\n");
    printf("║        Receiving GSM Control Channels...                ║\n");
    printf("╚══════════════════════════════════════════════════════════╝\n\n");
}

void print_realtime_status(uint32_t freq_hz, int gain, int total_msgs) {
    printf("\033[3;1H"); // Move to line 3
    printf("Frequency: %.3f MHz | Gain: %d dB | Messages: %d | Subscribers: %d    \n",
           freq_hz / 1e6, gain / 10, total_msgs, sub_count);
    printf("────────────────────────────────────────────────────────────\n");
}

void decode_imsi_from_frame(uint8_t *data, int len, int signal_db) {
    // Look for MM LOCATION UPDATING REQUEST or CM SERVICE REQUEST
    // These contain IMSI or TMSI
    
    if (len < 20) return;
    
    // GSM 04.08 protocol parsing
    uint8_t pd = data[0] & 0x0F;  // Protocol Discriminator
    uint8_t mt = (data[0] >> 4) & 0x07;  // Message Type
    
    uint64_t imsi = 0;
    uint32_t tmsi = 0;
    int has_imsi = 0, has_tmsi = 0;
    
    // Parse Mobile Identity
    for (int i = 5; i < len - 5; i++) {
        // Look for IEI 0x08 (Mobile Identity)
        if (data[i] == 0x08 || data[i] == 0x09) {
            uint8_t id_type = data[i+1] & 0x07;
            
            if (id_type == 0x01) { // IMSI
                has_imsi = 1;
                // Decode BCD IMSI (15 digits max)
                for (int j = 0; j < 8 && (i+2+j) < len; j++) {
                    uint8_t b = data[i+2+j];
                    imsi = (imsi * 100) + ((b & 0x0F) * 10) + ((b >> 4) & 0x0F);
                }
            } else if (id_type == 0x04) { // TMSI
                has_tmsi = 1;
                tmsi = (data[i+2] << 24) | (data[i+3] << 16) | 
                       (data[i+4] << 8) | data[i+5];
            }
        }
    }
    
    if (!has_imsi && !has_tmsi) return;
    
    pthread_mutex_lock(&sub_mutex);
    
    // Check if already seen
    int found = -1;
    for (int i = 0; i < sub_count; i++) {
        if ((has_imsi && subscribers[i].imsi == imsi) ||
            (has_tmsi && subscribers[i].tmsi == tmsi)) {
            found = i;
            break;
        }
    }
    
    time_t now = time(NULL);
    
    if (found >= 0) {
        subscribers[found].last_seen = now;
        subscribers[found].count++;
        subscribers[found].signal_db = signal_db;
        if (has_tmsi) subscribers[found].tmsi = tmsi;
    } else if (sub_count < MAX_SUBS) {
        // New subscriber
        subscribers[sub_count].imsi = imsi;
        subscribers[sub_count].tmsi = tmsi;
        subscribers[sub_count].signal_db = signal_db;
        subscribers[sub_count].first_seen = now;
        subscribers[sub_count].last_seen = now;
        subscribers[sub_count].count = 1;
        
        printf("\n\033[32m[NEW SUBSCRIBER]\033[0m #%d\n", sub_count + 1);
        if (has_imsi) {
            printf("  IMSI:  %015lu\n", imsi);
            printf("  MCC:   %03d | MNC: %02d\n", 
                   (int)(imsi / 1000000000ULL) % 1000,
                   (int)(imsi / 10000000ULL) % 100);
        }
        if (has_tmsi) {
            printf("  TMSI:  0x%08X\n", tmsi);
        }
        printf("  RSSI:  %d dBm\n", signal_db);
        printf("  Time:  %s", ctime(&now));
        
        sub_count++;
    }
    
    pthread_mutex_unlock(&sub_mutex);
}

void *receive_loop(void *arg) {
    uint32_t freq = *(uint32_t*)arg;
    int16_t *buffer = malloc(SAMPLE_RATE * 2 * sizeof(int16_t));
    int total_msgs = 0;
    
    while (running) {
        int n_read;
        uint8_t raw[SAMPLE_RATE * 2];
        
        rtlsdr_read_sync(dev, raw, SAMPLE_RATE * 2, &n_read);
        
        // Convert to signed and calculate signal strength
        int sum = 0;
        for (int i = 0; i < n_read; i++) {
            buffer[i] = (int16_t)raw[i] - 127;
            sum += buffer[i] * buffer[i];
        }
        int signal_db = (int)(10 * log10(sum / n_read + 1)) - 90;
        
        // GSM demodulation (simplified GMSK)
        // In real implementation, use libosmocore's demod
        uint8_t frame[256];
        int frame_len = 0;
        
        // Placeholder: Look for frame sync patterns
        for (int i = 0; i < n_read - 100; i++) {
            if (buffer[i] > 50 && buffer[i+1] < -50) {
                // Potential bit transition - extract frame
                frame_len = 23; // SDCCH frame size
                for (int j = 0; j < frame_len && (i+j) < n_read; j++) {
                    frame[j] = buffer[i+j] > 0 ? 1 : 0;
                }
                
                decode_imsi_from_frame(frame, frame_len, signal_db);
                total_msgs++;
            }
        }
        
        print_realtime_status(freq, rtlsdr_get_tuner_gain(dev), total_msgs);
    }
    
    free(buffer);
    return NULL;
}

void print_summary(void) {
    printf("\n\n════════════════════════════════════════════════════════════\n");
    printf("                    CAPTURE SUMMARY                         \n");
    printf("════════════════════════════════════════════════════════════\n");
    printf("Total unique subscribers: %d\n\n", sub_count);
    
    for (int i = 0; i < sub_count; i++) {
        printf("#%d | IMSI: %015lu | TMSI: %08X | Count: %d | RSSI: %d dBm\n",
               i + 1, subscribers[i].imsi, subscribers[i].tmsi,
               subscribers[i].count, subscribers[i].signal_db);
    }
}

int main(int argc, char **argv) {
    uint32_t freq = 941800000; // 941.8 MHz - common GSM downlink
    int gain = 400; // 40.0 dB
    
    int opt;
    while ((opt = getopt(argc, argv, "f:g:h")) != -1) {
        switch (opt) {
            case 'f': freq = (uint32_t)atof(optarg); break;
            case 'g': gain = atoi(optarg) * 10; break;
            case 'h':
            default:
                printf("Usage: %s -f <freq_hz> -g <gain_db>\n", argv[0]);
                printf("Example: %s -f 941.8e6 -g 40\n", argv[0]);
                return 1;
        }
    }
    
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    print_banner();
    
    // Open RTL-SDR
    if (rtlsdr_open(&dev, 0) < 0) {
        fprintf(stderr, "Failed to open RTL-SDR\n");
        return 1;
    }
    
    rtlsdr_set_center_freq(dev, freq);
    rtlsdr_set_sample_rate(dev, SAMPLE_RATE);
    rtlsdr_set_tuner_gain_mode(dev, 1);
    rtlsdr_set_tuner_gain(dev, gain);
    rtlsdr_set_agc_mode(dev, 0);
    rtlsdr_set_freq_correction(dev, 0);
    
    printf("Device: %s\n", rtlsdr_get_device_name(0));
    printf("Tuner: %s\n", rtlsdr_get_tuner_type(dev) == RTLSDR_TUNER_R820T ? "R820T2" : "Other");
    printf("Frequency: %.3f MHz\n\n", rtlsdr_get_center_freq(dev) / 1e6);
    printf("Listening for GSM control channels...\n");
    printf("Press Ctrl+C to stop and show summary\n\n");
    
    rtlsdr_reset_buffer(dev);
    
    pthread_t rx_thread;
    pthread_create(&rx_thread, NULL, receive_loop, &freq);
    pthread_join(rx_thread, NULL);
    
    print_summary();
    
    rtlsdr_close(dev);
    return 0;
}
