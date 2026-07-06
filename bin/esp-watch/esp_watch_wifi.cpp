// NetSc0ut ESP Watch v2 / Marauder Watch
// Passive-only 802.11 management-frame detector.
// Detects ESP-like identity clues plus Marauder-style behavior bursts:
// beacons/APs, probe requests/responses, probe floods, beacon spam,
// deauth/disassoc bursts, action/vendor frames, and ESP-NOW-style frames.

#include <pcap.h>
#include <algorithm>
#include <array>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <iomanip>
#include <iostream>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

using Clock = std::chrono::steady_clock;
using TimePoint = std::chrono::time_point<Clock>;

static volatile std::sig_atomic_t g_stop = 0;

static void handle_sigint(int) {
    g_stop = 1;
}

static uint16_t le16(const uint8_t *p) {
    return static_cast<uint16_t>(p[0] | (p[1] << 8));
}

static uint32_t le32(const uint8_t *p) {
    return static_cast<uint32_t>(p[0] | (p[1] << 8) | (p[2] << 16) | (p[3] << 24));
}

static std::string now_time() {
    std::time_t t = std::time(nullptr);
    std::tm tm{};
    localtime_r(&t, &tm);
    char buf[32];
    std::strftime(buf, sizeof(buf), "%H:%M:%S", &tm);
    return std::string(buf);
}

static std::string mac_to_str(const uint8_t *m) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (int i = 0; i < 6; ++i) {
        if (i) oss << ":";
        oss << std::setw(2) << static_cast<int>(m[i]);
    }
    return oss.str();
}

static std::string upper(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return std::toupper(c); });
    return s;
}

static std::string lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return std::tolower(c); });
    return s;
}

static bool contains_any_ci(const std::string &s, const std::vector<std::string> &needles) {
    std::string ls = lower(s);
    for (const auto &n : needles) {
        if (ls.find(lower(n)) != std::string::npos) return true;
    }
    return false;
}

static std::string safe_ssid(const std::string &ssid) {
    if (ssid.empty()) return "<hidden>";
    std::string out;
    for (unsigned char c : ssid) {
        if (c >= 32 && c <= 126) out.push_back(static_cast<char>(c));
        else out.push_back('.');
    }
    return out;
}

static bool is_local_admin_mac(const uint8_t *m) {
    return (m[0] & 0x02) != 0;
}

static bool is_broadcast_mac(const uint8_t *m) {
    for (int i = 0; i < 6; ++i) if (m[i] != 0xff) return false;
    return true;
}

static bool is_zero_mac(const uint8_t *m) {
    for (int i = 0; i < 6; ++i) if (m[i] != 0x00) return false;
    return true;
}

static std::set<std::string> esp_oui_prefixes = {
    "18:fe:34", "24:0a:c4", "24:6f:28", "2c:3a:e8", "30:ae:a4",
    "34:85:18", "3c:61:05", "40:22:d8", "58:bf:25", "5c:cf:7f",
    "7c:df:a1", "84:0d:8e", "8c:aa:b5", "94:b5:55", "a0:a3:b3",
    "a4:cf:12", "b4:e6:2d", "bc:dd:c2", "c4:4f:33", "cc:50:e3",
    "d8:bf:c0", "dc:4f:22", "ec:94:cb", "f4:cf:a2", "fc:f5:c4"
};

static bool has_esp_oui_mac(const uint8_t *m) {
    std::string mac = mac_to_str(m);
    return esp_oui_prefixes.count(mac.substr(0, 8)) > 0;
}

static bool has_esp_oui_str(const std::string &mac) {
    std::string lm = lower(mac);
    if (lm.size() < 8) return false;
    return esp_oui_prefixes.count(lm.substr(0, 8)) > 0;
}

static std::vector<std::string> esp_words = {
    "esp", "esp32", "esp8266", "espressif", "marauder", "wled", "tasmota", "esphome",
    "nodemcu", "lolin", "d1 mini", "cyd", "cheap yellow", "flipper", "evil", "portal"
};

struct RadiotapInfo {
    int header_len = 0;
    int signal_dbm = 9999;
    int frequency = 0;
    int channel = 0;
};

static int freq_to_channel(int freq) {
    if (freq == 2484) return 14;
    if (freq >= 2412 && freq <= 2472) return (freq - 2407) / 5;
    if (freq >= 5000 && freq <= 5900) return (freq - 5000) / 5;
    return 0;
}

static size_t align_offset(size_t offset, size_t align) {
    if (align <= 1) return offset;
    size_t rem = offset % align;
    if (!rem) return offset;
    return offset + (align - rem);
}

struct FieldInfo { size_t align; size_t size; };

static FieldInfo radiotap_field_info(int index) {
    switch (index) {
        case 0: return {8, 8};   // TSFT
        case 1: return {1, 1};   // Flags
        case 2: return {1, 1};   // Rate
        case 3: return {2, 4};   // Channel
        case 4: return {2, 2};   // FHSS
        case 5: return {1, 1};   // dBm antenna signal
        case 6: return {1, 1};   // dBm antenna noise
        case 7: return {2, 2};   // Lock quality
        case 8: return {2, 2};   // TX attenuation
        case 9: return {2, 2};   // dB TX attenuation
        case 10: return {1, 1};  // dBm TX power
        case 11: return {1, 1};  // Antenna
        case 12: return {1, 1};  // dB antenna signal
        case 13: return {1, 1};  // dB antenna noise
        case 14: return {2, 2};  // RX flags
        case 15: return {2, 2};  // TX flags
        case 16: return {1, 1};  // RTS retries
        case 17: return {1, 1};  // Data retries
        case 19: return {1, 3};  // MCS
        case 20: return {4, 8};  // AMPDU
        case 21: return {2, 12}; // VHT
        default: return {1, 0};
    }
}

static RadiotapInfo parse_radiotap(const uint8_t *pkt, int len) {
    RadiotapInfo rt;
    if (len < 8) return rt;

    uint16_t hlen = le16(pkt + 2);
    if (hlen < 8 || hlen > len) return rt;
    rt.header_len = hlen;

    std::vector<uint32_t> present_words;
    size_t pos = 4;
    while (pos + 4 <= static_cast<size_t>(hlen)) {
        uint32_t present = le32(pkt + pos);
        present_words.push_back(present);
        pos += 4;
        if ((present & 0x80000000u) == 0) break;
    }

    size_t field_pos = pos;
    for (size_t word_i = 0; word_i < present_words.size(); ++word_i) {
        uint32_t present = present_words[word_i];
        for (int bit = 0; bit < 32; ++bit) {
            if (bit == 31) continue; // extension bit
            if ((present & (1u << bit)) == 0) continue;
            int index = static_cast<int>(word_i * 32 + bit);
            FieldInfo fi = radiotap_field_info(index);
            if (fi.size == 0) continue;
            field_pos = align_offset(field_pos, fi.align);
            if (field_pos + fi.size > static_cast<size_t>(hlen)) return rt;

            if (index == 3 && fi.size >= 4) {
                rt.frequency = le16(pkt + field_pos);
                rt.channel = freq_to_channel(rt.frequency);
            } else if (index == 5 && fi.size >= 1) {
                rt.signal_dbm = static_cast<int8_t>(pkt[field_pos]);
            }
            field_pos += fi.size;
        }
    }
    return rt;
}

struct TagsInfo {
    std::string ssid;
    bool has_vendor_ie = false;
    bool has_esp_vendor_ie = false;
    std::vector<std::string> vendor_ouis;
};

static std::string oui_to_str(const uint8_t *p) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(p[0]) << ":"
        << std::setw(2) << static_cast<int>(p[1]) << ":"
        << std::setw(2) << static_cast<int>(p[2]);
    return oss.str();
}

static TagsInfo parse_tags(const uint8_t *p, int len) {
    TagsInfo info;
    int pos = 0;
    while (pos + 2 <= len) {
        uint8_t id = p[pos];
        uint8_t l = p[pos + 1];
        pos += 2;
        if (pos + l > len) break;
        const uint8_t *v = p + pos;

        if (id == 0) { // SSID
            info.ssid.assign(reinterpret_cast<const char *>(v), reinterpret_cast<const char *>(v + l));
        } else if (id == 221 && l >= 3) { // vendor-specific IE
            info.has_vendor_ie = true;
            std::string oui = oui_to_str(v);
            info.vendor_ouis.push_back(oui);
            if (esp_oui_prefixes.count(oui) > 0 || oui == "18:fe:34" || oui == "24:0a:c4") {
                info.has_esp_vendor_ie = true;
            }
        }
        pos += l;
    }
    return info;
}

struct Options {
    std::string iface;
    std::vector<int> channels;
    int hop_ms = 350;
    int dedupe_sec = 1;
    int window_sec = 5;
    int probe_src_threshold = 3;
    int probe_total_threshold = 8;
    int deauth_threshold = 2;
    int beacon_spam_threshold = 4;
    bool print_passive = true;
    bool print_all_probes = true;
    bool print_actions = true;
    bool marauder_watch = true;
};

static std::vector<int> parse_channels(const std::string &s) {
    std::vector<int> out;
    std::stringstream ss(s);
    std::string item;
    while (std::getline(ss, item, ',')) {
        try {
            int ch = std::stoi(item);
            if (ch > 0) out.push_back(ch);
        } catch (...) {}
    }
    if (out.empty()) out = {1,2,3,4,5,6,7,8,9,10,11,12,13};
    return out;
}

static void usage(const char *argv0) {
    std::cerr << "Usage:\n"
              << "  " << argv0 << " <iface> <channels> <hop_ms> <dedupe_sec> [options]\n"
              << "Example:\n"
              << "  sudo " << argv0 << " wlan1 1,2,3,4,5,6,7,8,9,10,11,12,13 350 1 --marauder-watch\n\n"
              << "Options:\n"
              << "  --window-sec N              sliding detection window, default 5\n"
              << "  --probe-src-threshold N     probes from same source in window, default 3\n"
              << "  --probe-total-threshold N   total probes in window, default 8\n"
              << "  --deauth-threshold N        deauth/disassoc burst threshold, default 2\n"
              << "  --beacon-spam-threshold N   unique SSIDs in window threshold, default 4\n"
              << "  --quiet-passive             do not print one-time passive AP/probe/action events\n";
}

static Options parse_args(int argc, char **argv) {
    if (argc < 2) {
        usage(argv[0]);
        std::exit(2);
    }
    Options opt;
    opt.iface = argv[1];
    opt.channels = (argc >= 3 && argv[2][0] != '-') ? parse_channels(argv[2]) : parse_channels("1,2,3,4,5,6,7,8,9,10,11,12,13");
    if (argc >= 4 && argv[3][0] != '-') opt.hop_ms = std::max(50, std::atoi(argv[3]));
    if (argc >= 5 && argv[4][0] != '-') opt.dedupe_sec = std::max(0, std::atoi(argv[4]));

    for (int i = 5; i < argc; ++i) {
        std::string a = argv[i];
        auto need_val = [&](int &target) {
            if (i + 1 >= argc) return;
            target = std::atoi(argv[++i]);
        };
        if (a == "--window-sec") need_val(opt.window_sec);
        else if (a == "--probe-src-threshold") need_val(opt.probe_src_threshold);
        else if (a == "--probe-total-threshold") need_val(opt.probe_total_threshold);
        else if (a == "--deauth-threshold") need_val(opt.deauth_threshold);
        else if (a == "--beacon-spam-threshold") need_val(opt.beacon_spam_threshold);
        else if (a == "--quiet-passive") opt.print_passive = false;
        else if (a == "--no-all-probes") opt.print_all_probes = false;
        else if (a == "--help" || a == "-h") { usage(argv[0]); std::exit(0); }
    }
    return opt;
}

static void set_channel(const std::string &iface, int ch) {
    std::string cmd = "iw dev " + iface + " set channel " + std::to_string(ch) + " HT20 >/dev/null 2>&1";
    std::system(cmd.c_str());
}

static void prune_deque(std::deque<TimePoint> &dq, TimePoint now, int window_sec) {
    auto cutoff = now - std::chrono::seconds(window_sec);
    while (!dq.empty() && dq.front() < cutoff) dq.pop_front();
}

class Detector {
public:
    explicit Detector(Options opt) : opt_(std::move(opt)) {}

    bool should_print(const std::string &key) {
        if (opt_.dedupe_sec <= 0) return true;
        TimePoint now = Clock::now();
        auto it = last_print_.find(key);
        if (it == last_print_.end() || now - it->second >= std::chrono::seconds(opt_.dedupe_sec)) {
            last_print_[key] = now;
            return true;
        }
        return false;
    }

    void print_event(const std::string &type, const std::string &msg, const std::string &dedupe_key = "") {
        std::string key = dedupe_key.empty() ? type + ":" + msg : dedupe_key;
        if (!should_print(key)) return;
        std::cout << "[" << now_time() << "] [" << type << "] " << msg << std::endl;
    }

    void on_frame(const uint8_t *frame, int frame_len, const RadiotapInfo &rt) {
        if (frame_len < 24) return;

        uint16_t fc = le16(frame);
        int type = (fc >> 2) & 0x3;
        int subtype = (fc >> 4) & 0xf;
        if (type != 0) return; // management only

        const uint8_t *addr1 = frame + 4;   // DA
        const uint8_t *addr2 = frame + 10;  // SA
        const uint8_t *addr3 = frame + 16;  // BSSID

        std::string da = mac_to_str(addr1);
        std::string sa = mac_to_str(addr2);
        std::string bssid = mac_to_str(addr3);
        bool esp_src = has_esp_oui_mac(addr2);
        bool local_src = is_local_admin_mac(addr2);
        bool bad_src = is_broadcast_mac(addr2) || is_zero_mac(addr2);
        if (bad_src) return;

        std::string rssi = rt.signal_dbm == 9999 ? "?" : std::to_string(rt.signal_dbm);
        int ch = rt.channel;

        TagsInfo tags;
        std::string ssid;
        if ((subtype == 8 || subtype == 5) && frame_len >= 36) { // beacon or probe response
            tags = parse_tags(frame + 36, frame_len - 36);
            ssid = safe_ssid(tags.ssid);
        } else if (subtype == 4 && frame_len >= 24) { // probe request
            tags = parse_tags(frame + 24, frame_len - 24);
            ssid = safe_ssid(tags.ssid);
        }

        bool esp_name = contains_any_ci(ssid, esp_words);
        bool esp_vendor_ie = tags.has_esp_vendor_ie;

        if (subtype == 8) handle_beacon(sa, bssid, ssid, rssi, ch, esp_src, esp_name, esp_vendor_ie, local_src);
        else if (subtype == 5) handle_probe_resp(sa, bssid, ssid, rssi, ch, esp_src, esp_name, esp_vendor_ie, local_src);
        else if (subtype == 4) handle_probe_req(sa, ssid, rssi, ch, esp_src, esp_name, esp_vendor_ie, local_src);
        else if (subtype == 12 || subtype == 10) handle_deauth_disassoc(subtype, sa, da, bssid, rssi, ch, esp_src, local_src);
        else if (subtype == 13) handle_action(frame, frame_len, sa, da, bssid, rssi, ch, esp_src, local_src);
    }

private:
    Options opt_;
    std::map<std::string, TimePoint> last_print_;
    std::set<std::string> seen_aps_;
    std::set<std::string> seen_probe_sources_;
    std::deque<TimePoint> probe_total_;
    std::map<std::string, std::deque<TimePoint>> probe_by_src_;
    std::deque<TimePoint> deauth_total_;
    std::deque<std::pair<TimePoint, std::string>> recent_ssids_;

    void add_recent_ssid(const std::string &ssid) {
        if (ssid == "<hidden>" || ssid == "<wildcard>" || ssid.empty()) return;
        TimePoint now = Clock::now();
        recent_ssids_.push_back({now, ssid});
        auto cutoff = now - std::chrono::seconds(opt_.window_sec);
        while (!recent_ssids_.empty() && recent_ssids_.front().first < cutoff) recent_ssids_.pop_front();

        std::set<std::string> unique;
        for (const auto &p : recent_ssids_) unique.insert(p.second);
        if (static_cast<int>(unique.size()) >= opt_.beacon_spam_threshold) {
            std::ostringstream oss;
            oss << "unique_ssids=" << unique.size()
                << " window=" << opt_.window_sec << "s confidence=High"
                << " reason=\"many unique SSIDs/beacons seen in short window; possible beacon spam or test traffic\"";
            print_event("BEACON-SPAM / SSID-BURST", oss.str(), "beacon_spam_global");
        }
    }

    void handle_beacon(const std::string &sa, const std::string &bssid, const std::string &ssid, const std::string &rssi,
                       int ch, bool esp_src, bool esp_name, bool esp_vendor_ie, bool local_src) {
        add_recent_ssid(ssid);

        std::string key = bssid + ":" + ssid;
        bool first = seen_aps_.insert(key).second;

        if (esp_src || esp_name || esp_vendor_ie) {
            std::ostringstream oss;
            oss << "mac=" << sa << " bssid=" << bssid << " ssid=\"" << ssid << "\" rssi=" << rssi
                << "dBm ch=" << ch << " confidence=" << ((esp_name || esp_vendor_ie) ? "High" : "Medium")
                << " local_mac=" << (local_src ? "yes" : "no")
                << " reason=\"";
            bool first_reason = true;
            if (esp_name) { oss << "SSID/name looks ESP/Marauder-related"; first_reason = false; }
            if (esp_src) { oss << (first_reason ? "" : "; ") << "Espressif-like source OUI"; first_reason = false; }
            if (esp_vendor_ie) { oss << (first_reason ? "" : "; ") << "Espressif vendor IE"; }
            oss << "\"";
            print_event("ESP-LIKE AP/BEACON", oss.str(), "esp_beacon:" + key);
        } else if (opt_.print_passive && first) {
            std::ostringstream oss;
            oss << "mac=" << sa << " bssid=" << bssid << " ssid=\"" << ssid << "\" rssi=" << rssi
                << "dBm ch=" << ch << " local_mac=" << (local_src ? "yes" : "no")
                << " reason=\"passive AP/beacon seen\"";
            print_event("PASSIVE AP", oss.str(), "ap:" + key);
        }
    }

    void handle_probe_resp(const std::string &sa, const std::string &bssid, const std::string &ssid, const std::string &rssi,
                           int ch, bool esp_src, bool esp_name, bool esp_vendor_ie, bool local_src) {
        if (esp_src || esp_name || esp_vendor_ie || opt_.print_passive) {
            std::ostringstream oss;
            oss << "mac=" << sa << " bssid=" << bssid << " ssid=\"" << ssid << "\" rssi=" << rssi
                << "dBm ch=" << ch << " confidence=" << ((esp_src || esp_name || esp_vendor_ie) ? "Medium" : "Low")
                << " local_mac=" << (local_src ? "yes" : "no")
                << " reason=\"probe response";
            if (esp_src) oss << "; Espressif-like OUI";
            if (esp_name) oss << "; ESP-like name";
            if (esp_vendor_ie) oss << "; Espressif vendor IE";
            oss << "\"";
            print_event((esp_src || esp_name || esp_vendor_ie) ? "ESP-LIKE PROBE-RESP" : "PROBE-RESP", oss.str(), "probe_resp:" + sa + ":" + ssid);
        }
    }

    void handle_probe_req(const std::string &sa, const std::string &ssid, const std::string &rssi,
                          int ch, bool esp_src, bool esp_name, bool esp_vendor_ie, bool local_src) {
        TimePoint now = Clock::now();
        probe_total_.push_back(now);
        prune_deque(probe_total_, now, opt_.window_sec);
        auto &dq = probe_by_src_[sa];
        dq.push_back(now);
        prune_deque(dq, now, opt_.window_sec);

        if (static_cast<int>(probe_total_.size()) >= opt_.probe_total_threshold) {
            std::ostringstream oss;
            oss << "frames=" << probe_total_.size() << " window=" << opt_.window_sec << "s ch=" << ch
                << " confidence=High reason=\"high probe request rate; possible probe flood/test traffic\"";
            print_event("PROBE-FLOOD", oss.str(), "probe_flood_total");
        }

        if (static_cast<int>(dq.size()) >= opt_.probe_src_threshold) {
            std::ostringstream oss;
            oss << "src=" << sa << " frames=" << dq.size() << " window=" << opt_.window_sec << "s ssid=\"" << ssid
                << "\" rssi=" << rssi << "dBm ch=" << ch << " local_mac=" << (local_src ? "yes" : "no")
                << " confidence=High reason=\"repeated probe requests from same source\"";
            print_event("PROBE-BURST SRC", oss.str(), "probe_burst_src:" + sa);
        }

        if (esp_src || esp_name || esp_vendor_ie) {
            std::ostringstream oss;
            oss << "src=" << sa << " ssid=\"" << ssid << "\" rssi=" << rssi << "dBm ch=" << ch
                << " confidence=" << ((esp_src || esp_name) ? "Medium" : "Low")
                << " local_mac=" << (local_src ? "yes" : "no")
                << " reason=\"probe request";
            if (esp_src) oss << "; Espressif-like OUI";
            if (esp_name) oss << "; ESP-like SSID probe";
            if (esp_vendor_ie) oss << "; Espressif vendor IE";
            oss << "\"";
            print_event("ESP-LIKE PROBE", oss.str(), "esp_probe:" + sa + ":" + ssid);
        } else if (opt_.print_all_probes || opt_.print_passive) {
            bool first = seen_probe_sources_.insert(sa).second;
            if (first || opt_.print_all_probes) {
                std::ostringstream oss;
                oss << "src=" << sa << " ssid=\"" << ssid << "\" rssi=" << rssi << "dBm ch=" << ch
                    << " local_mac=" << (local_src ? "yes" : "no")
                    << " reason=\"probe request seen\"";
                print_event("PROBE-REQ", oss.str(), "probe_req:" + sa + ":" + ssid);
            }
        }
    }

    void handle_deauth_disassoc(int subtype, const std::string &sa, const std::string &da, const std::string &bssid,
                                const std::string &rssi, int ch, bool esp_src, bool local_src) {
        TimePoint now = Clock::now();
        deauth_total_.push_back(now);
        prune_deque(deauth_total_, now, opt_.window_sec);

        std::string label = subtype == 12 ? "DEAUTH" : "DISASSOC";
        std::ostringstream oss;
        oss << "src=" << sa << " dst=" << da << " bssid=" << bssid << " rssi=" << rssi << "dBm ch=" << ch
            << " local_mac=" << (local_src ? "yes" : "no")
            << " confidence=" << (static_cast<int>(deauth_total_.size()) >= opt_.deauth_threshold ? "High" : "Medium")
            << " reason=\"" << label << " management frame seen";
        if (esp_src) oss << "; Espressif-like source OUI";
        oss << "\"";
        print_event(label, oss.str(), "deauth_frame:" + sa + ":" + da + ":" + label);

        if (static_cast<int>(deauth_total_.size()) >= opt_.deauth_threshold) {
            std::ostringstream burst;
            burst << "frames=" << deauth_total_.size() << " window=" << opt_.window_sec << "s ch=" << ch
                  << " confidence=High reason=\"deauth/disassoc burst; possible disconnect attack/test traffic\"";
            print_event("DEAUTH/DISASSOC BURST", burst.str(), "deauth_burst");
        }
    }

    void handle_action(const uint8_t *frame, int frame_len, const std::string &sa, const std::string &da,
                       const std::string &bssid, const std::string &rssi, int ch, bool esp_src, bool local_src) {
        bool vendor_action = false;
        bool esp_vendor = false;
        std::string oui = "";

        if (frame_len >= 24 + 5) {
            uint8_t category = frame[24];
            if (category == 127 || category == 0x7f) { // vendor-specific action
                vendor_action = true;
                if (frame_len >= 24 + 1 + 3) {
                    oui = oui_to_str(frame + 25);
                    if (esp_oui_prefixes.count(oui) > 0 || oui == "18:fe:34" || oui == "24:0a:c4") esp_vendor = true;
                }
            }
        }

        if (opt_.print_actions || vendor_action || esp_src || esp_vendor) {
            std::ostringstream oss;
            oss << "src=" << sa << " dst=" << da << " bssid=" << bssid << " rssi=" << rssi << "dBm ch=" << ch
                << " vendor_action=" << (vendor_action ? "yes" : "no")
                << " vendor_oui=" << (oui.empty() ? "-" : oui)
                << " local_mac=" << (local_src ? "yes" : "no")
                << " confidence=" << ((esp_vendor || esp_src) ? "High" : (vendor_action ? "Medium" : "Low"))
                << " reason=\"action frame seen";
            if (vendor_action) oss << "; vendor-specific action frame";
            if (esp_vendor) oss << "; Espressif OUI in action frame; possible ESP-NOW";
            if (esp_src) oss << "; Espressif-like source OUI";
            oss << "\"";

            std::string type = esp_vendor ? "ESP-NOW / ESP VENDOR ACTION" : (vendor_action ? "VENDOR ACTION" : "ACTION FRAME");
            print_event(type, oss.str(), "action:" + sa + ":" + da + ":" + oui);
        }
    }
};

int main(int argc, char **argv) {
    std::signal(SIGINT, handle_sigint);
    std::signal(SIGTERM, handle_sigint);

    Options opt = parse_args(argc, argv);

    std::cout << "NetSc0ut ESP Watch v2 / Marauder Watch" << std::endl;
    std::cout << "Passive-only. Listening for ESP-like devices, passive Wi-Fi signals, probe floods, beacon spam, deauth/disassoc, and action/vendor frames." << std::endl;
    std::cout << "Interface: " << opt.iface << " Channels: ";
    for (size_t i = 0; i < opt.channels.size(); ++i) {
        if (i) std::cout << ",";
        std::cout << opt.channels[i];
    }
    std::cout << " Hop: " << opt.hop_ms << "ms Dedupe: " << opt.dedupe_sec << "s" << std::endl;
    std::cout << "Thresholds: probe_src=" << opt.probe_src_threshold
              << " probe_total=" << opt.probe_total_threshold
              << " deauth=" << opt.deauth_threshold
              << " beacon_spam=" << opt.beacon_spam_threshold
              << " window=" << opt.window_sec << "s" << std::endl;
    std::cout.flush();

    char errbuf[PCAP_ERRBUF_SIZE] = {0};
    pcap_t *handle = pcap_open_live(opt.iface.c_str(), 4096, 1, 100, errbuf);
    if (!handle) {
        std::cerr << "ERROR: pcap_open_live failed on " << opt.iface << ": " << errbuf << std::endl;
        return 1;
    }

    int dlt = pcap_datalink(handle);
    if (dlt != DLT_IEEE802_11_RADIO) {
        std::cerr << "WARNING: datalink is " << dlt << ", expected radiotap DLT_IEEE802_11_RADIO (127). Parsing may fail." << std::endl;
    }

    // Capture only 802.11 management frames. This keeps the tool light.
    struct bpf_program fp{};
    const char *filter = "type mgt";
    if (pcap_compile(handle, &fp, filter, 1, PCAP_NETMASK_UNKNOWN) == 0) {
        pcap_setfilter(handle, &fp);
        pcap_freecode(&fp);
    } else {
        std::cerr << "WARNING: failed to apply BPF filter: " << pcap_geterr(handle) << std::endl;
    }

    Detector detector(opt);
    size_t ch_index = 0;
    if (!opt.channels.empty()) set_channel(opt.iface, opt.channels[ch_index]);
    TimePoint last_hop = Clock::now();

    while (!g_stop) {
        if (opt.channels.size() > 1 && Clock::now() - last_hop >= std::chrono::milliseconds(opt.hop_ms)) {
            ch_index = (ch_index + 1) % opt.channels.size();
            set_channel(opt.iface, opt.channels[ch_index]);
            last_hop = Clock::now();
        }

        struct pcap_pkthdr *hdr = nullptr;
        const uint8_t *pkt = nullptr;
        int rc = pcap_next_ex(handle, &hdr, &pkt);
        if (rc == 0) continue;       // timeout
        if (rc == -1) {
            std::cerr << "ERROR: pcap_next_ex: " << pcap_geterr(handle) << std::endl;
            break;
        }
        if (rc == -2) break;
        if (!hdr || !pkt || hdr->caplen < 16) continue;

        RadiotapInfo rt = parse_radiotap(pkt, static_cast<int>(hdr->caplen));
        if (rt.header_len <= 0 || rt.header_len >= static_cast<int>(hdr->caplen)) continue;
        const uint8_t *frame = pkt + rt.header_len;
        int frame_len = static_cast<int>(hdr->caplen) - rt.header_len;
        detector.on_frame(frame, frame_len, rt);
    }

    pcap_close(handle);
    std::cout << "[" << now_time() << "] ESP Watch stopped." << std::endl;
    return 0;
}
