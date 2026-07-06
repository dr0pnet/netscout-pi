#!/bin/bash
# cellular_rotate.sh - Rotating RTL-SDR Cellular Intelligence System

# Log directory priority: 1) Command line 2) Environment 3) Default
LOG_DIR="${1:-${LOG_DIR:-/home/pi/netscout-pi/state/cellular-logs}}"
ROTATION_TIME="${2:-300}"
FREQ="${3:-941.8e6}"
GAIN="${4:-40}"

# Programs
PROGS=("imsi_catcher" "tower_scanner" "sms_sniffer" "traffic_monitor" "downlink_recorder")
NAMES=("IMSI Catcher" "Tower Scanner" "SMS Sniffer" "Traffic Monitor" "Downlink Recorder")

# Create log directory
mkdir -p "$LOG_DIR" || {
    echo "Error: Cannot create $LOG_DIR"
    exit 1
}

# Verify writable
if [[ ! -w "$LOG_DIR" ]]; then
    echo "Error: $LOG_DIR is not writable"
    exit 1
fi

ABS_LOG_DIR=$(cd "$LOG_DIR" && pwd)
echo "Logging to: $ABS_LOG_DIR"

# Cleanup function
cleanup() {
    echo ""
    echo "[!] Stopping all processes..."
    killall -9 ${PROGS[@]} 2>/dev/null
    echo "Logs saved in: $ABS_LOG_DIR"
    exit 0
}

trap cleanup SIGINT SIGTERM

# Banner
clear
echo "============================================================"
echo "     RTL-SDR v5 Cellular Intelligence Rotator"
echo "     Rotating through 5 capture modes"
echo "============================================================"
echo ""
echo "Settings:"
echo "  Log directory: $ABS_LOG_DIR"
echo "  Rotation time: $ROTATION_TIME seconds"
echo "  Frequency: $FREQ"
echo "  Gain: ${GAIN}dB"
echo ""
echo "Usage: $0 [LOG_DIR] [ROTATION_TIME] [FREQ] [GAIN]"
echo "Example: $0 /mnt/usb/cellular_logs 600 951.4e6 50"
echo ""
echo "Press Ctrl+C to stop gracefully"
echo ""

# Function to run program with timeout
run_mode() {
    local idx=$1
    local prog=${PROGS[$idx]}
    local name=${NAMES[$idx]}
    local timestamp=$(date +%Y%m%d_%H%M%S)
    local logfile="$ABS_LOG_DIR/${prog}_${timestamp}.log"
    
    echo "[$(date '+%H:%M:%S')] Starting $name for $ROTATION_TIME seconds..."
    echo "         Log: $logfile"
    echo "----------------------------------------"
    
    # Kill any existing RTL-SDR processes
    killall -9 $prog 2>/dev/null
    sleep 1
    
    # Run program with appropriate arguments
    case $prog in
        "imsi_catcher")
            timeout $ROTATION_TIME ./$prog -f $FREQ -g $GAIN 2>&1 | tee "$logfile" &
            ;;
        "tower_scanner")
            timeout $ROTATION_TIME ./$prog 2>&1 | tee "$logfile" &
            ;;
        "sms_sniffer")
            timeout $ROTATION_TIME ./$prog -f $FREQ 2>&1 | tee "$logfile" &
            ;;
        "traffic_monitor")
            timeout $ROTATION_TIME ./$prog -f $FREQ 2>&1 | tee "$logfile" &
            ;;
        "downlink_recorder")
            local datafile="$ABS_LOG_DIR/bcch_${timestamp}.dat"
            timeout $ROTATION_TIME ./$prog -f $FREQ -g $GAIN -o "$datafile" 2>&1 | tee "$logfile" &
            ;;
    esac
    
    local PID=$!
    
    # Show countdown
    for ((i=ROTATION_TIME; i>0; i--)); do
        printf "\r[%02d:%02d] %s running... (PID: %d) " \
               $((i/60)) $((i%60)) "$name" $PID
        sleep 1
    done
    echo ""
    
    # Kill process
    kill $PID 2>/dev/null
    wait $PID 2>/dev/null
    
    # Get line count for summary
    local lines=$(wc -l < "$logfile" 2>/dev/null || echo "0")
    
    echo "[$(date '+%H:%M:%S')] * $name complete (${lines} lines)"
    echo "Log: $logfile"
    
    # Extract key findings
    case $prog in
        "imsi_catcher")
            local imsi_count=$(grep -c "IMSI:" "$logfile" 2>/dev/null || echo "0")
            echo "  Captured: $imsi_count IMSI numbers"
            ;;
        "tower_scanner")
            local tower_count=$(grep -c "NEW TOWER" "$logfile" 2>/dev/null || echo "0")
            echo "  Found: $tower_count towers"
            ;;
        "sms_sniffer")
            local sms_count=$(grep -c "SMS CAPTURED" "$logfile" 2>/dev/null || echo "0")
            echo "  Captured: $sms_count SMS messages"
            ;;
        "traffic_monitor")
            local avg_load=$(grep "req/s" "$logfile" | tail -1 | grep -oP '\d+' | head -1 || echo "0")
            echo "  Peak load: $avg_load requests/sec"
            ;;
        "downlink_recorder")
            local bcch_count=$(grep -c "System Information" "$logfile" 2>/dev/null || echo "0")
            echo "  Recorded: $bcch_count BCCH messages"
            ;;
    esac
    
    echo ""
    
    # Brief pause between modes
    sleep 2
}

# Main loop
cycle=1
while true; do
    echo "=== ROTATION CYCLE $cycle ==="
    echo "Log directory: $ABS_LOG_DIR"
    echo ""
    
    for i in 0 1 2 3 4; do
        run_mode $i
    done
    
    echo "=== Cycle $cycle complete. Logs in $ABS_LOG_DIR ==="
    echo ""
    
    # Summary of cycle
    echo "Cycle Summary:"
    ls -lh "$ABS_LOG_DIR"/*$(date +%Y%m%d)*.log 2>/dev/null | tail -5 | awk '{print "  " $9 " (" $5 ")"}'
    echo ""
    
    ((cycle++))
done