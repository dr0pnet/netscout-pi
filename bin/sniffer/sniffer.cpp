#include <pcap.h>
#include <csignal>
#include <ctime>
#include <fstream>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <set>
#include <map>
#include <unistd.h>
#include <sys/stat.h>

static volatile bool running = true;
static pcap_t* handle = nullptr;
static pcap_dumper_t* pcap_out = nullptr;
static std::ofstream json_out;

struct RadiotapHeader {
    uint8_t version;
    uint8_t pad;
    uint16_t len;
};

std::string now_iso() {
    std::time_t t = std::time(nullptr);
    std::tm* tm = std::localtime(&t);

    std::ostringstream ss;
    ss << std::put_time(tm, "%Y-%m-%dT%H:%M:%S");
    return ss.str();
}

std::string mac_to_str(const u_char* m) {
    char buf[18];
    snprintf(
        buf,
        sizeof(buf),
        "%02X:%02X:%02X:%02X:%02X:%02X",
        m[0], m[1], m[2], m[3], m[4], m[5]
    );
    return std::string(buf);
}

std::string json_escape(const std::string& s) {
    std::ostringstream o;

    for (char c : s) {
        if (c == '"') o << "\\\"";
        else if (c == '\\') o << "\\\\";
        else if (c == '\n') o << "\\n";
        else if (c == '\r') o << "\\r";
        else if (c == '\t') o << "\\t";
        else o << c;
    }

    return o.str();
}

void write_json(
    const std::string& type,
    const std::map<std::string, std::string>& fields
) {
    json_out << "{";
    json_out << "\"time\":\"" << now_iso() << "\",";
    json_out << "\"type\":\"" << type << "\"";

    for (const auto& kv : fields) {
        json_out << ",\"" << kv.first << "\":\"" << json_escape(kv.second) << "\"";
    }

    json_out << "}" << std::endl;
}

std::string parse_ssid(const u_char* body, int body_len) {
    int pos = 0;

    while (pos + 2 <= body_len) {
        uint8_t tag = body[pos];
        uint8_t len = body[pos + 1];

        if (pos + 2 + len > body_len) break;

        if (tag == 0) {
            if (len == 0) return "<hidden>";

            std::string ssid(
                reinterpret_cast<const char*>(body + pos + 2),
                len
            );

            return ssid;
        }

        pos += 2 + len;
    }

    return "";
}

void signal_handler(int sig) {
    running = false;

    if (handle) {
        pcap_breakloop(handle);
    }
}

void packet_handler(u_char*, const struct pcap_pkthdr* header, const u_char* packet) {
    if (!packet || header->caplen < 32) return;

    if (pcap_out) {
        pcap_dump((u_char*)pcap_out, header, packet);
    }

    const RadiotapHeader* rt = reinterpret_cast<const RadiotapHeader*>(packet);
    int rt_len = rt->len;

    if (rt_len <= 0 || rt_len >= (int)header->caplen) return;

    const u_char* frame = packet + rt_len;
    int frame_len = header->caplen - rt_len;

    if (frame_len < 24) return;

    uint16_t fc = frame[0] | (frame[1] << 8);

    int type = (fc >> 2) & 0x3;
    int subtype = (fc >> 4) & 0xF;

    std::string dst = mac_to_str(frame + 4);
    std::string src = mac_to_str(frame + 10);
    std::string bssid = mac_to_str(frame + 16);

    if (type == 0 && subtype == 8) {
        if (frame_len < 36) return;

        const u_char* tags = frame + 36;
        int tags_len = frame_len - 36;

        std::string ssid = parse_ssid(tags, tags_len);

        write_json("beacon", {
            {"ssid", ssid},
            {"bssid", bssid},
            {"src", src},
            {"dst", dst}
        });

        std::cout << "[BEACON] SSID: " << ssid
                  << " | BSSID: " << bssid << std::endl;
    }
    else if (type == 0 && subtype == 4) {
        if (frame_len < 24) return;

        const u_char* tags = frame + 24;
        int tags_len = frame_len - 24;

        std::string ssid = parse_ssid(tags, tags_len);

        write_json("probe_request", {
            {"client", src},
            {"ssid", ssid},
            {"dst", dst}
        });

        std::cout << "[PROBE] Client: " << src
                  << " | Looking for: " << ssid << std::endl;
    }
    else if (type == 0 && subtype == 12) {
        write_json("deauth_detected", {
            {"src", src},
            {"dst", dst},
            {"bssid", bssid}
        });

        std::cout << "[DEAUTH DETECTED] "
                  << src << " -> " << dst << std::endl;
    }
    else if (type == 2) {
        write_json("data_frame", {
            {"src", src},
            {"dst", dst},
            {"bssid", bssid}
        });

        std::cout << "[DATA] "
                  << src << " -> " << dst << std::endl;
    }
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        std::cerr << "Usage: sniffer <interface> <state_dir>" << std::endl;
        return 1;
    }

    std::string iface = argv[1];
    std::string state_dir = argv[2];

    mkdir(state_dir.c_str(), 0755);

    std::string stamp = now_iso();
    for (char& c : stamp) {
        if (c == ':' || c == '-') c = '_';
        if (c == 'T') c = '_';
    }

    std::string json_path = state_dir + "/sniffer_" + stamp + ".jsonl";
    std::string pcap_path = state_dir + "/sniffer_" + stamp + ".pcap";

    signal(SIGTERM, signal_handler);
    signal(SIGINT, signal_handler);

    char errbuf[PCAP_ERRBUF_SIZE];

    handle = pcap_open_live(
        iface.c_str(),
        BUFSIZ,
        1,
        1000,
        errbuf
    );

    if (!handle) {
        std::cerr << "pcap_open_live failed: " << errbuf << std::endl;
        return 1;
    }

    json_out.open(json_path);

    if (!json_out.is_open()) {
        std::cerr << "Failed to open JSON log: " << json_path << std::endl;
        pcap_close(handle);
        return 1;
    }

    pcap_out = pcap_dump_open(handle, pcap_path.c_str());

    if (!pcap_out) {
        std::cerr << "Failed to open PCAP file: " << pcap_path << std::endl;
    }

    write_json("session_start", {
        {"interface", iface},
        {"json_path", json_path},
        {"pcap_path", pcap_path}
    });

    std::cout << "[NetScout Sniffer] Started on " << iface << std::endl;
    std::cout << "[JSON] " << json_path << std::endl;
    std::cout << "[PCAP] " << pcap_path << std::endl;

    while (running) {
        pcap_dispatch(handle, 10, packet_handler, nullptr);
    }

    write_json("session_stop", {
        {"interface", iface},
        {"json_path", json_path},
        {"pcap_path", pcap_path}
    });

    if (pcap_out) {
        pcap_dump_close(pcap_out);
    }

    json_out.close();
    pcap_close(handle);

    std::cout << "[NetScout Sniffer] Stopped and saved." << std::endl;

    return 0;
}
