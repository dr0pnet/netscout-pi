/*
 * SMS Control Channel Sniffer (GSM SDCCH)
 * Captures unencrypted SMS on GSM control channels
 * Compile: gcc -o sms_sniffer sms_sniffer.c -lrtlsdr -losmocore -lm -lpthread
 * Usage: sudo ./sms_sniffer -f 941.8e6
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <math.h>
#include <signal.h>
#include <time.h>
#include <pthread.h>
#include <rtl-sdr.h>

#define SAMPLE_RATE 2048000

typedef struct {
    char sender[16];
    char recipient[16];
    char text[256];
    time_t timestamp;
    int signal_db;
} SMSMessage;

static SMSMessage sms_log[100];
static int sms_count = 0;
static pthread_mutex_t sms_mutex = PTHREAD_MUTEX_INITIALIZER;
static volatile int running = 1;
static rtlsdr_dev_t *dev = NULL;

// Decode 7-bit GSM alphabet to ASCII
void gsm7_to_ascii(uint8_t *gsm7, int len, char *ascii) {
    static const char gsm_table[] = "@£$¥èéùìòÇ\nØø\rÅåΔ_ΦΓΛΩΠΨΣΘΞ\x1BÆæßÉ"
                                    " !\"#¤%&'()*+,-./0123456789:;<=>?"
                                    "¡ABCDEFGHIJKLMNOPQRSTUVWXYZÄÖÑÜ§¿"
                                    "abcdefghijklmnopqrstuvwxyzäöñüà";
    
    int out_pos = 0;
    for (int i = 0; i < len && out_pos < 255; i++) {
        uint8_t c = gsm7[i];
        if (c < sizeof(gsm_table) - 1) {
            ascii[out_pos++] = gsm_table[c];
        } else {
            ascii[out_pos++] = '.';
        }
    }
    ascii[out_pos] = '\0';
}

// Parse SMS from LAPDm frame
void parse_sms_frame(uint8_t *data, int len, int signal_db) {
    if (len < 20) return;
    
    // Look for CP-DATA (SMS TPDU)
    // Message type 0x01 for CP-DATA
    
    uint8_t pd = data[0] & 0x0F;
    if (pd != 0x09) return; // Not SMS protocol
    
    // Extract TP-DA (destination) and TP-OA (originator)
    // and TP-UD (user data)
    
    SMSMessage sms;
    memset(&sms, 0, sizeof(sms));
    sms.timestamp = time(NULL);
    sms.signal_db = signal_db;
    
    // Simplified parsing - real implementation needs full GSM 04.11 parsing
    // Look for phone number in semi-octet BCD
    for (int i = 5; i < len - 10; i++) {
        if (data[i] == 0x81 || data[i] == 0x91) { // Type of number
            int num_len = data[i-1] & 0xFF;
            if (num_len > 0 && num_len < 20) {
                for (int j = 0; j < num_len && (i+1+j) < len; j++) {
                    uint8_t b = data[i+1+j];
                    sprintf(sms.sender + strlen(sms.sender), "%d%d", 
                            b & 0x0F, (b >> 4) & 0x0F);
                }
            }
        }
    }
    
    // Extract text (7-bit packed)
    for (int i = 15; i < len && i < 271; i++) {
        if (data[i] >= 0x20 && data[i] < 0x7F) {
            int pos = strlen(sms.text);
            sms.text[pos] = data[i];
            sms.text[pos+1] = '\0';
        }
    }
    
    if (strlen(sms.text) > 5) {
        pthread_mutex_lock(&sms_mutex);
        
        if (sms_count < 100) {
            sms_log[sms_count++] = sms;
            
            printf("\n\033[33m[SMS CAPTURED]\033[0m #%d\n", sms_count);
            printf("  From:    %s\n", sms.sender[0] ? sms.sender : "Unknown");
            printf("  To:      %s\n", sms.recipient[0] ? sms.recipient : "Unknown");
            printf("  Text:    %s\n", sms.text);
            printf("  RSSI:    %d dBm\n", signal_db);
            printf("  Time:    %s", ctime(&sms.timestamp));
        }
        
        pthread_mutex_unlock(&sms_mutex);
    }
}

void *receive_thread(void *arg) {
    uint8_t buffer[SAMPLE_RATE * 2];
    
    while (running) {
        int n_read;
        rtlsdr_read_sync(dev, buffer, SAMPLE_RATE * 2, &n_read);
        
        // Calculate signal strength
        int sum = 0;
        for (int i = 0; i < n_read; i++) {
            int v = buffer[i] - 127;
            sum += v * v;
        }
        int signal_db = (int)(10 * log10(sum / n_read + 1)) - 90;
        
        // Look for SMS frames (simplified)
        // Real implementation would use proper GSM frame sync and LAPDm parsing
        for (int i = 0; i < n_read - 100; i++) {
            // Look for SDCCH frame pattern
            if (buffer[i] == 0x01 && buffer[i+1] == 0x09) {
                uint8_t frame[256];
                int len = (buffer[i+2] < 250) ? buffer[i+2] : 23;
                for (int j = 0; j < len && (i+j) < n_read; j++) {
                    frame[j] = buffer[i+j];
                }
                parse_sms_frame(frame, len, signal_db);
            }
        }
    }
    
    return NULL;
}

void print_summary(void) {
    printf("\n════════════════════════════════════════════════════════════\n");
    printf("                    SMS CAPTURE LOG                         \n");
    printf("════════════════════════════════════════════════════════════\n");
    printf("Total SMS captured: %d\n\n", sms_count);
    
    for (int i = 0; i < sms_count; i++) {
        printf("#%d [%s] From: %s\n", i+1, 
               sms_log[i].sender[0] ? sms_log[i].sender : "Unknown",
               sms_log[i].text);
    }
}

int main(int argc, char **argv) {
    uint32_t freq = 941800000;
    
    if (argc > 1) freq = (uint32_t)atof(argv[1]);
    
    printf("╔══════════════════════════════════════════════════════════╗\n");
    printf("║           SMS CONTROL CHANNEL SNIFFER                    ║\n");
    printf("║           GSM SDCCH - SMS Capture                        ║\n");
    printf("╚══════════════════════════════════════════════════════════╝\n\n");
    
    if (rtlsdr_open(&dev, 0) < 0) {
        fprintf(stderr, "Failed to open RTL-SDR\n");
        return 1;
    }
    
    rtlsdr_set_center_freq(dev, freq);
    rtlsdr_set_sample_rate(dev, SAMPLE_RATE);
    rtlsdr_set_tuner_gain_mode(dev, 1);
    rtlsdr_set_tuner_gain(dev, 400);
    
    printf("Frequency: %.3f MHz\n", freq / 1e6);
    printf("Listening for SMS on control channels...\n");
    printf("Note: Most modern networks encrypt SMS. Success rate varies.\n\n");
    
    rtlsdr_reset_buffer(dev);
    
    signal(SIGINT, (__sighandler_t)(uintptr_t)&running);
    
    pthread_t rx_thread;
    pthread_create(&rx_thread, NULL, receive_thread, NULL);
    
    printf("Press Ctrl+C to stop and show captured SMS\n\n");
    
    pthread_join(rx_thread, NULL);
    
    rtlsdr_close(dev);
    
    print_summary();
    
    return 0;
}
