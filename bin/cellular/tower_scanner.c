/*
 * GSM/UMTS/LTE Cell Tower Scanner
 * Scans cellular bands and logs tower information
 * Compile: gcc -o tower_scanner tower_scanner.c -lrtlsdr -lfftw3 -lm
 * Usage: sudo ./tower_scanner
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <math.h>
#include <rtl-sdr.h>
#include <fftw3.h>

#define SAMPLE_RATE 2048000
#define FFT_SIZE 2048

typedef struct {
    uint32_t freq_hz;
    int arfcn;
    int power_db;
    int mcc, mnc, lac, cid;
    char type[16];
    time_t detected;
} CellTower;

#define MAX_TOWERS 500
static CellTower towers[MAX_TOWERS];
static int tower_count = 0;

// GSM ARFCN to frequency
uint32_t arfcn_to_freq(int arfcn) {
    if (arfcn >= 0 && arfcn <= 124) {
        return 935000000 + (arfcn * 200000);
    } else if (arfcn >= 512 && arfcn <= 885) {
        return 1805200000 + ((arfcn - 512) * 200000);
    } else if (arfcn >= 955 && arfcn <= 1023) {
        return 935000000 + ((arfcn - 1024) * 200000);
    }
    return 0;
}

void print_banner(void) {
    printf("\033[2J\033[H");
    printf("╔══════════════════════════════════════════════════════════╗\n");
    printf("║           CELL TOWER DATABASE SCANNER                    ║\n");
    printf("║           RTL-SDR v5 - GSM/UMTS/LTE                     ║\n");
    printf("╚══════════════════════════════════════════════════════════╝\n\n");
}

void print_tower(CellTower *t) {
    printf("\033[32m[NEW TOWER]\033[0m #%d\n", tower_count);
    printf("  Frequency: %.3f MHz\n", t->freq_hz / 1e6);
    printf("  ARFCN:     %d\n", t->arfcn);
    printf("  Power:     %d dBm\n", t->power_db);
    printf("  Type:      %s\n", t->type);
    printf("  MCC/MNC:   %d/%d\n", t->mcc, t->mnc);
    printf("  LAC/CID:   %d/%d\n", t->lac, t->cid);
    printf("  Time:      %s", ctime(&t->detected));
    printf("────────────────────────────────────────────────────────────\n");
}

void scan_band(rtlsdr_dev_t *dev, uint32_t start, uint32_t end, const char *band_name) {
    printf("\n\033[1mScanning %s (%.0f-%.0f MHz)...\033[0m\n", 
           band_name, start/1e6, end/1e6);
    
    fftw_complex *fft_in = fftw_alloc_complex(FFT_SIZE);
    fftw_complex *fft_out = fftw_alloc_complex(FFT_SIZE);
    fftw_plan plan = fftw_plan_dft_1d(FFT_SIZE, fft_in, fft_out, FFTW_FORWARD, FFTW_ESTIMATE);
    
    uint8_t buffer[SAMPLE_RATE * 2];
    int step = SAMPLE_RATE / 2;
    
    for (uint32_t freq = start; freq < end && tower_count < MAX_TOWERS; freq += step) {
        rtlsdr_set_center_freq(dev, freq);
        rtlsdr_reset_buffer(dev);
        
        int n_read;
        rtlsdr_read_sync(dev, buffer, SAMPLE_RATE * 2, &n_read);
        
        // FFT analysis
        for (int i = 0; i < FFT_SIZE; i++) {
            float I = (buffer[i*2] - 127.5) / 128.0;
            float Q = (buffer[i*2+1] - 127.5) / 128.0;
            fft_in[i][0] = I;
            fft_in[i][1] = Q;
        }
        
        fftw_execute(plan);
        
        // Find peaks
        for (int i = 0; i < FFT_SIZE; i++) {
            double power = sqrt(fft_out[i][0] * fft_out[i][0] + 
                               fft_out[i][1] * fft_out[i][1]);
            double db = 20 * log10(power + 1e-10);
            
            if (db > -30) {
                int offset = ((i * SAMPLE_RATE) / FFT_SIZE) - (SAMPLE_RATE/2);
                uint32_t detected = freq + offset;
                
                // Check if GSM channel
                for (int arfcn = 0; arfcn <= 1023; arfcn++) {
                    if (abs((int)detected - (int)arfcn_to_freq(arfcn)) < 50000) {
                        // Check if already logged
                        int exists = 0;
                        for (int j = 0; j < tower_count; j++) {
                            if (abs((int)towers[j].freq_hz - (int)detected) < 100000) {
                                exists = 1;
                                break;
                            }
                        }
                        
                        if (!exists) {
                            CellTower *t = &towers[tower_count];
                            t->freq_hz = detected;
                            t->arfcn = arfcn;
                            t->power_db = (int)db;
                            strcpy(t->type, "GSM");
                            t->detected = time(NULL);
                            
                            print_tower(t);
                            tower_count++;
                        }
                        break;
                    }
                }
            }
        }
    }
    
    fftw_destroy_plan(plan);
    fftw_free(fft_in);
    fftw_free(fft_out);
}

void print_summary(void) {
    printf("\n════════════════════════════════════════════════════════════\n");
    printf("                    TOWER DATABASE                          \n");
    printf("════════════════════════════════════════════════════════════\n");
    printf("Total towers found: %d\n\n", tower_count);
    
    // Sort by frequency
    for (int i = 0; i < tower_count - 1; i++) {
        for (int j = i + 1; j < tower_count; j++) {
            if (towers[i].freq_hz > towers[j].freq_hz) {
                CellTower tmp = towers[i];
                towers[i] = towers[j];
                towers[j] = tmp;
            }
        }
    }
    
    printf("ARFCN | Freq (MHz) | Power  | Type | Band\n");
    printf("──────┼────────────┼────────┼──────┼──────────\n");
    
    for (int i = 0; i < tower_count; i++) {
        CellTower *t = &towers[i];
        const char *band = (t->freq_hz < 1000000000) ? "GSM900" : "DCS1800";
        
        printf("%5d | %10.3f | %4d dB| %-4s | %s\n",
               t->arfcn, t->freq_hz/1e6, t->power_db, t->type, band);
    }
}

int main(void) {
    rtlsdr_dev_t *dev;
    
    print_banner();
    
    if (rtlsdr_open(&dev, 0) < 0) {
        fprintf(stderr, "Failed to open RTL-SDR\n");
        return 1;
    }
    
    rtlsdr_set_sample_rate(dev, SAMPLE_RATE);
    rtlsdr_set_tuner_gain_mode(dev, 1);
    rtlsdr_set_tuner_gain(dev, 400);
    
    printf("Device: %s\n\n", rtlsdr_get_device_name(0));
    
    // Scan GSM900
    scan_band(dev, 935000000, 960000000, "GSM900 Downlink");
    
    // Scan DCS1800
    scan_band(dev, 1805000000, 1880000000, "DCS1800 Downlink");
    
    // Scan UMTS
    scan_band(dev, 2110000000, 2170000000, "UMTS Downlink");
    
    rtlsdr_close(dev);
    
    print_summary();
    
    return 0;
}
