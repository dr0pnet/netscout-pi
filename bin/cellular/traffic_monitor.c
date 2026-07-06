/*
 * Cell Traffic Analyzer
 * Monitors control channel activity to estimate cell load
 * Compile: gcc -o traffic_monitor traffic_monitor.c -lrtlsdr -lm -lpthread
 * Usage: sudo ./traffic_monitor -f 941.8e6
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <math.h>
#include <unistd.h>
#include <pthread.h>
#include <rtl-sdr.h>

#define SAMPLE_RATE 2048000
#define HISTORY_SIZE 60  // 1 minute of history

typedef struct {
    time_t timestamp;
    int paging_count;
    int access_count;
    int assign_count;
    float total_power;
} TrafficSample;

static TrafficSample history[HISTORY_SIZE];
static int hist_pos = 0;
static volatile int running = 1;
static rtlsdr_dev_t *dev = NULL;

void clear_screen(void) {
    printf("\033[2J\033[H");
}

void print_header(uint32_t freq) {
    printf("╔══════════════════════════════════════════════════════════╗\n");
    printf("║           CELL TRAFFIC MONITOR                           ║\n");
    printf("║           Frequency: %.3f MHz                          ║\n", freq/1e6);
    printf("╚══════════════════════════════════════════════════════════╝\n\n");
}

void print_gauge(const char *label, int value, int max, const char *unit) {
    int bars = (value * 20) / max;
    if (bars > 20) bars = 20;
    
    printf("%-12s [", label);
    for (int i = 0; i < 20; i++) {
        if (i < bars) {
            if (i < 10) printf("\033[32m#\033[0m");
            else if (i < 17) printf("\033[33m#\033[0m");
            else printf("\033[31m#\033[0m");
        } else {
            printf(" ");
        }
    }
    printf("] %3d %s\n", value, unit);
}

void print_stats(TrafficSample *current, TrafficSample *prev) {
    printf("\033[3;1H"); // Move cursor
    
    printf("Current Activity (last 10 seconds):\n");
    print_gauge("Paging", current->paging_count, 50, "req/s");
    print_gauge("Access", current->access_count, 30, "req/s");
    print_gauge("Assign", current->assign_count, 20, "ch/s");
    
    printf("\nSignal Level: %.1f dB\n", current->total_power);
    
    // Trend calculation
    if (prev) {
        int trend = current->paging_count - prev->paging_count;
        printf("Trend: %s%d paging requests/sec\n", 
               trend > 0 ? "+" : "", trend);
        
        if (current->paging_count > 40) {
            printf("\033[31m[ALERT] High cell load detected!\033[0m\n");
        } else if (current->paging_count > 25) {
            printf("\033[33m[WARNING] Moderate cell load\033[0m\n");
        } else {
            printf("\033[32m[NORMAL] Low cell activity\033[0m\n");
        }
    }
    
    printf("\nHistory (last 60 seconds):\n");
    printf("Time  Paging Access Assign Load\n");
    printf("────  ────── ────── ────── ────\n");
    
    for (int i = 0; i < 10 && i < HISTORY_SIZE; i++) {
        int idx = (hist_pos - i - 1 + HISTORY_SIZE) % HISTORY_SIZE;
        if (history[idx].timestamp == 0) continue;
        
        struct tm *tm = localtime(&history[idx].timestamp);
        printf("%02d:%02d %6d %6d %6d ", 
               tm->tm_min, tm->tm_sec,
               history[idx].paging_count,
               history[idx].access_count,
               history[idx].assign_count);
        
        // Visual load indicator
        int load = history[idx].paging_count;
        if (load < 10) printf("\033[32mLOW \033[0m\n");
        else if (load < 30) printf("\033[33mMED \033[0m\n");
        else printf("\033[31mHIGH\033[0m\n");
    }
    
    fflush(stdout);
}

void *monitor_thread(void *arg) {
    uint32_t freq = *(uint32_t*)arg;
    uint8_t buffer[SAMPLE_RATE * 2];
    
    TrafficSample current = {0};
    time_t last_update = time(NULL);
    
    while (running) {
        int n_read;
        rtlsdr_read_sync(dev, buffer, SAMPLE_RATE * 2, &n_read);
        
        // Analyze signal
        long sum = 0;
        int paging = 0, access = 0, assign = 0;
        
        for (int i = 0; i < n_read - 10; i++) {
            int v = buffer[i] - 127;
            sum += v * v;
            
            // Pattern detection for different message types
            // PAGING: Look for PCH patterns
            if (buffer[i] == 0x21 && buffer[i+1] == 0x08) {
                paging++;
            }
            // ACCESS: RACH bursts
            else if (buffer[i] > 200 && buffer[i+1] < 50) {
                access++;
            }
            // ASSIGN: AGCH
            else if (buffer[i] == 0x3F && buffer[i+1] == 0x06) {
                assign++;
            }
        }
        
        current.total_power = 10 * log10(sum / n_read + 1) - 90;
        current.paging_count += paging / 10;
        current.access_count += access / 10;
        current.assign_count += assign / 10;
        
        // Update every 10 seconds
        time_t now = time(NULL);
        if (now - last_update >= 10) {
            current.timestamp = now;
            
            TrafficSample *prev = NULL;
            if (hist_pos > 0) prev = &history[(hist_pos - 1 + HISTORY_SIZE) % HISTORY_SIZE];
            
            history[hist_pos] = current;
            hist_pos = (hist_pos + 1) % HISTORY_SIZE;
            
            print_stats(&current, prev);
            
            // Reset counters
            memset(&current, 0, sizeof(current));
            last_update = now;
        }
    }
    
    return NULL;
}

int main(int argc, char **argv) {
    uint32_t freq = 941800000;
    
    if (argc > 1) freq = (uint32_t)atof(argv[1]);
    
    if (rtlsdr_open(&dev, 0) < 0) {
        fprintf(stderr, "Failed to open RTL-SDR\n");
        return 1;
    }
    
    rtlsdr_set_center_freq(dev, freq);
    rtlsdr_set_sample_rate(dev, SAMPLE_RATE);
    rtlsdr_set_tuner_gain_mode(dev, 1);
    rtlsdr_set_tuner_gain(dev, 400);
    
    clear_screen();
    print_header(freq);
    
    printf("Initializing...\n");
    rtlsdr_reset_buffer(dev);
    sleep(1);
    
    pthread_t mon_thread;
    pthread_create(&mon_thread, NULL, monitor_thread, &freq);
    
    printf("Monitoring cell traffic. Press Ctrl+C to exit.\n\n");
    
    while (running) sleep(1);
    
    pthread_join(mon_thread, NULL);
    rtlsdr_close(dev);
    
    return 0;
}
