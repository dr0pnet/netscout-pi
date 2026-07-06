/*
 * GSM Downlink Broadcast Recorder
 * Records BCCH (Broadcast Control Channel) messages
 * Compile: gcc -o downlink_recorder downlink_recorder.c -lrtlsdr -lm
 * Usage: sudo ./downlink_recorder -f 941.8e6 -o capture.dat
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <signal.h>
#include <getopt.h>
#include <rtl-sdr.h>

#define SAMPLE_RATE 2048000
#define BLOCK_SIZE (256 * 1024)

static volatile int running = 1;
static rtlsdr_dev_t *dev = NULL;
static FILE *output = NULL;

void signal_handler(int sig) {
    running = 0;
}

void print_sysinfo(uint8_t *data, int len) {
    // Parse GSM 04.08 System Information messages
    uint8_t msg_type = data[1] & 0x3F;
    
    const char *si_type = "Unknown";
    switch (msg_type) {
        case 0x19: si_type = "System Information Type 1"; break;
        case 0x1A: si_type = "System Information Type 2"; break;
        case 0x1B: si_type = "System Information Type 3"; break;
        case 0x1C: si_type = "System Information Type 4"; break;
        case 0x00: si_type = "System Information Type 5"; break;
        case 0x01: si_type = "System Information Type 6"; break;
    }
    
    // Extract LAC and CI from SI3/SI4
    int lac = 0, ci = 0;
    if (msg_type == 0x1B || msg_type == 0x1C) {
        lac = (data[8] << 8) | data[9];
        ci = (data[10] << 8) | data[11];
    }
    
    time_t now = time(NULL);
    char *timestr = ctime(&now);
    timestr[strlen(timestr)-1] = '\0';
    
    printf("[%s] %s", timestr, si_type);
    if (lac) printf(" | LAC: %d | CI: %d", lac, ci);
    printf("\n");
    
    // Print hex dump of first 32 bytes
    printf("  Data: ");
    for (int i = 0; i < 32 && i < len; i++) {
        printf("%02X ", data[i]);
    }
    printf("\n\n");
}

void process_buffer(uint8_t *buffer, int len) {
    // Look for BCCH frames
    for (int i = 0; i < len - 23; i++) {
        // GSM BCCH idle frame pattern
        if (buffer[i] == 0x00 && buffer[i+1] >= 0x19 && buffer[i+1] <= 0x1C) {
            uint8_t frame[23];
            memcpy(frame, buffer + i, 23);
            
            print_sysinfo(frame, 23);
            
            // Write to file with timestamp
            if (output) {
                time_t ts = time(NULL);
                fwrite(&ts, sizeof(ts), 1, output);
                fwrite(frame, 1, 23, output);
                fflush(output);
            }
        }
    }
}

int main(int argc, char **argv) {
    uint32_t freq = 941800000;
    const char *filename = "downlink.dat";
    int gain = 400;
    
    int opt;
    while ((opt = getopt(argc, argv, "f:o:g:h")) != -1) {
        switch (opt) {
            case 'f': freq = (uint32_t)atof(optarg); break;
            case 'o': filename = optarg; break;
            case 'g': gain = atoi(optarg) * 10; break;
            case 'h':
            default:
                printf("Usage: %s -f <freq> -o <file> -g <gain>\n", argv[0]);
                return 1;
        }
    }
    
    signal(SIGINT, signal_handler);
    
    printf("╔══════════════════════════════════════════════════════════╗\n");
    printf("║           DOWNLINK BROADCAST RECORDER                    ║\n");
    printf("║           BCCH System Information Capture               ║\n");
    printf("╚══════════════════════════════════════════════════════════╝\n\n");
    
    output = fopen(filename, "wb");
    if (!output) {
        perror("Failed to open output file");
        return 1;
    }
    
    if (rtlsdr_open(&dev, 0) < 0) {
        fprintf(stderr, "Failed to open RTL-SDR\n");
        fclose(output);
        return 1;
    }
    
    rtlsdr_set_center_freq(dev, freq);
    rtlsdr_set_sample_rate(dev, SAMPLE_RATE);
    rtlsdr_set_tuner_gain_mode(dev, 1);
    rtlsdr_set_tuner_gain(dev, gain);
    
    printf("Recording to: %s\n", filename);
    printf("Frequency: %.3f MHz\n", freq / 1e6);
    printf("Gain: %.1f dB\n\n", gain / 10.0);
    
    rtlsdr_reset_buffer(dev);
    
    uint8_t *buffer = malloc(BLOCK_SIZE);
    int total_blocks = 0;
    time_t start = time(NULL);
    
    printf("Recording... Press Ctrl+C to stop\n\n");
    
    while (running) {
        int n_read;
        rtlsdr_read_sync(dev, buffer, BLOCK_SIZE, &n_read);
        
        process_buffer(buffer, n_read);
        
        total_blocks++;
        
        // Status every 10 seconds
        time_t elapsed = time(NULL) - start;
        if (elapsed % 10 == 0) {
            printf("\r[%ld sec] Blocks: %d | Size: %.1f MB", 
                   elapsed, total_blocks, (total_blocks * BLOCK_SIZE) / 1e6);
            fflush(stdout);
        }
    }
    
    printf("\n\nStopped. Total recorded: %.1f MB\n", 
           (total_blocks * BLOCK_SIZE) / 1e6);
    
    free(buffer);
    fclose(output);
    rtlsdr_close(dev);
    
    return 0;
}