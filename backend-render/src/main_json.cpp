// main_json.cpp — Web-friendly DPI engine that outputs JSON
// Usage: ./dpi_json <input.pcap> <output.pcap>
// Outputs a single JSON object to stdout with full analysis results.

#include <iostream>
#include <fstream>
#include <unordered_map>
#include <vector>
#include <iomanip>
#include <unordered_set>
#include <algorithm>
#include <sstream>
#include <ctime>

#include "pcap_reader.h"
#include "packet_parser.h"
#include "sni_extractor.h"
#include "types.h"

using namespace PacketAnalyzer;
using namespace DPI;

struct Flow {
    FiveTuple tuple;
    AppType app_type = AppType::UNKNOWN;
    std::string sni;
    uint64_t packets = 0;
    uint64_t bytes = 0;
    bool blocked = false;
    std::string src_ip;
    std::string dst_ip;
    uint16_t src_port = 0;
    uint16_t dst_port = 0;
    std::string protocol;
};

class BlockingRules {
public:
    std::unordered_set<uint32_t> blocked_ips;
    std::unordered_set<AppType> blocked_apps;
    std::vector<std::string> blocked_domains;

    void blockApp(AppType app) { blocked_apps.insert(app); }

    bool isBlocked(uint32_t src_ip, AppType app, const std::string& sni) {
        if (blocked_ips.count(src_ip)) return true;
        if (app != AppType::UNKNOWN && blocked_apps.count(app)) return true;
        for (const auto& d : blocked_domains)
            if (sni.find(d) != std::string::npos) return true;
        return false;
    }
};

// Escape string for JSON output
std::string jsonEscape(const std::string& s) {
    std::string out;
    for (char c : s) {
        if (c == '"')  out += "\\\"";
        else if (c == '\\') out += "\\\\";
        else if (c == '\n') out += "\\n";
        else if (c == '\r') out += "\\r";
        else out += c;
    }
    return out;
}

uint32_t parseIPStr(const std::string& ip) {
    uint32_t result = 0; int octet = 0, shift = 0;
    for (char c : ip) {
        if (c == '.') { result |= (octet << shift); shift += 8; octet = 0; }
        else if (c >= '0' && c <= '9') octet = octet * 10 + (c - '0');
    }
    return result | (octet << shift);
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        std::cout << "{\"error\":\"Usage: dpi_json <input.pcap> <output.pcap>\"}\n";
        return 1;
    }

    std::string input_file  = argv[1];
    std::string output_file = argv[2];

    // Optional block rules: --block-app YOUTUBE --block-app FACEBOOK etc.
    BlockingRules rules;
    for (int i = 3; i < argc - 1; i++) {
        if (std::string(argv[i]) == "--block-app") {
            std::string app_name = argv[i+1];
            for (int j = 0; j < static_cast<int>(AppType::APP_COUNT); j++) {
                AppType t = static_cast<AppType>(j);
                if (appTypeToString(t) == app_name) { rules.blockApp(t); break; }
            }
        }
    }

    PcapReader reader;
    if (!reader.open(input_file)) {
        std::cout << "{\"error\":\"Cannot open input file: " << jsonEscape(input_file) << "\"}\n";
        return 1;
    }

    std::ofstream output(output_file, std::ios::binary);
    if (!output.is_open()) {
        std::cout << "{\"error\":\"Cannot open output file\"}\n";
        return 1;
    }

    const auto& header = reader.getGlobalHeader();
    output.write(reinterpret_cast<const char*>(&header), sizeof(header));

    std::unordered_map<FiveTuple, Flow, FiveTupleHash> flows;
    uint64_t total_packets = 0, forwarded = 0, dropped = 0;
    uint64_t tcp_count = 0, udp_count = 0;
    std::unordered_map<AppType, uint64_t> app_stats;

    // Packet-level details (first 200 for display)
    struct PacketInfo {
        int num;
        std::string timestamp;
        std::string src_ip, dst_ip;
        uint16_t src_port, dst_port;
        std::string protocol;
        std::string app;
        std::string sni;
        uint32_t size;
        bool blocked;
        std::string flags;
    };
    std::vector<PacketInfo> packet_list;

    RawPacket raw;
    ParsedPacket parsed;

    while (reader.readNextPacket(raw)) {
        total_packets++;
        if (!PacketParser::parse(raw, parsed)) continue;
        if (!parsed.has_ip || (!parsed.has_tcp && !parsed.has_udp)) continue;

        FiveTuple tuple;
        tuple.src_ip   = parseIPStr(parsed.src_ip);
        tuple.dst_ip   = parseIPStr(parsed.dest_ip);
        tuple.src_port = parsed.src_port;
        tuple.dst_port = parsed.dest_port;
        tuple.protocol = parsed.protocol;

        Flow& flow = flows[tuple];
        if (flow.packets == 0) {
            flow.tuple    = tuple;
            flow.src_ip   = parsed.src_ip;
            flow.dst_ip   = parsed.dest_ip;
            flow.src_port = parsed.src_port;
            flow.dst_port = parsed.dest_port;
            flow.protocol = PacketParser::protocolToString(parsed.protocol);
        }
        flow.packets++;
        flow.bytes += raw.data.size();

        if (parsed.has_tcp) tcp_count++;
        else                udp_count++;

        // SNI extraction for HTTPS
        if ((flow.app_type == AppType::UNKNOWN || flow.app_type == AppType::HTTPS)
            && flow.sni.empty() && parsed.has_tcp && parsed.dest_port == 443) {
            size_t po = 14;
            uint8_t ip_ihl = raw.data[14] & 0x0F;
            po += ip_ihl * 4;
            if (po + 12 < raw.data.size()) {
                uint8_t tcp_off = (raw.data[po + 12] >> 4) & 0x0F;
                po += tcp_off * 4;
                if (po < raw.data.size()) {
                    size_t pl = raw.data.size() - po;
                    if (pl > 5) {
                        auto sni = SNIExtractor::extract(raw.data.data() + po, pl);
                        if (sni) { flow.sni = *sni; flow.app_type = sniToAppType(*sni); }
                    }
                }
            }
        }

        // HTTP Host
        if ((flow.app_type == AppType::UNKNOWN || flow.app_type == AppType::HTTP)
            && flow.sni.empty() && parsed.has_tcp && parsed.dest_port == 80) {
            size_t po = 14;
            uint8_t ip_ihl = raw.data[14] & 0x0F;
            po += ip_ihl * 4;
            if (po + 12 < raw.data.size()) {
                uint8_t tcp_off = (raw.data[po + 12] >> 4) & 0x0F;
                po += tcp_off * 4;
                if (po < raw.data.size()) {
                    size_t pl = raw.data.size() - po;
                    auto host = HTTPHostExtractor::extract(raw.data.data() + po, pl);
                    if (host) { flow.sni = *host; flow.app_type = sniToAppType(*host); }
                }
            }
        }

        // Port-based fallback
        if (flow.app_type == AppType::UNKNOWN) {
            if (parsed.dest_port == 443 || parsed.src_port == 443) flow.app_type = AppType::HTTPS;
            else if (parsed.dest_port == 80 || parsed.src_port == 80) flow.app_type = AppType::HTTP;
            else if (parsed.dest_port == 53 || parsed.src_port == 53) flow.app_type = AppType::DNS;
        }

        // Rule check
        if (!flow.blocked)
            flow.blocked = rules.isBlocked(tuple.src_ip, flow.app_type, flow.sni);

        app_stats[flow.app_type]++;

        // Write to output or drop
        if (flow.blocked) {
            dropped++;
        } else {
            forwarded++;
            PcapPacketHeader pkt_hdr;
            pkt_hdr.ts_sec  = raw.header.ts_sec;
            pkt_hdr.ts_usec = raw.header.ts_usec;
            pkt_hdr.incl_len = raw.data.size();
            pkt_hdr.orig_len = raw.data.size();
            output.write(reinterpret_cast<const char*>(&pkt_hdr), sizeof(pkt_hdr));
            output.write(reinterpret_cast<const char*>(raw.data.data()), raw.data.size());
        }

        // Collect first 500 packets for display
        if (packet_list.size() < 500) {
            PacketInfo pi;
            pi.num      = total_packets;
            pi.src_ip   = parsed.src_ip;
            pi.dst_ip   = parsed.dest_ip;
            pi.src_port = parsed.src_port;
            pi.dst_port = parsed.dest_port;
            pi.protocol = PacketParser::protocolToString(parsed.protocol);
            pi.app      = appTypeToString(flow.app_type);
            pi.sni      = flow.sni;
            pi.size     = raw.data.size();
            pi.blocked  = flow.blocked;
            if (parsed.has_tcp)
                pi.flags = PacketParser::tcpFlagsToString(parsed.tcp_flags);
            // Timestamp
            std::time_t t = raw.header.ts_sec;
            char buf[32];
            std::strftime(buf, sizeof(buf), "%H:%M:%S", std::localtime(&t));
            pi.timestamp = std::string(buf) + "." +
                           std::to_string(raw.header.ts_usec / 1000);
            packet_list.push_back(pi);
        }
    }

    reader.close();
    output.close();

    // Sort app_stats descending
    std::vector<std::pair<AppType, uint64_t>> sorted_apps(app_stats.begin(), app_stats.end());
    std::sort(sorted_apps.begin(), sorted_apps.end(),
              [](const auto& a, const auto& b){ return a.second > b.second; });

    // Collect unique domains
    std::vector<std::pair<std::string,std::string>> domains;
    std::unordered_map<std::string,bool> seen;
    for (const auto& [t, f] : flows) {
        if (!f.sni.empty() && !seen[f.sni]) {
            seen[f.sni] = true;
            domains.push_back({f.sni, appTypeToString(f.app_type)});
        }
    }

    // Collect top flows by bytes
    std::vector<Flow> flow_list;
    for (const auto& [t, f] : flows) flow_list.push_back(f);
    std::sort(flow_list.begin(), flow_list.end(),
              [](const Flow& a, const Flow& b){ return a.bytes > b.bytes; });

    // ---- Build JSON output ----
    std::ostringstream j;
    j << "{\n";

    // Summary
    j << "  \"summary\": {\n";
    j << "    \"total_packets\": " << total_packets << ",\n";
    j << "    \"forwarded\": " << forwarded << ",\n";
    j << "    \"dropped\": " << dropped << ",\n";
    j << "    \"total_flows\": " << flows.size() << ",\n";
    j << "    \"tcp_packets\": " << tcp_count << ",\n";
    j << "    \"udp_packets\": " << udp_count << "\n";
    j << "  },\n";

    // App distribution
    j << "  \"app_distribution\": [\n";
    for (size_t i = 0; i < sorted_apps.size(); i++) {
        const auto& [app, cnt] = sorted_apps[i];
        double pct = total_packets > 0 ? 100.0 * cnt / total_packets : 0;
        j << "    {\"app\": \"" << appTypeToString(app) << "\","
          << " \"count\": " << cnt << ","
          << " \"percent\": " << std::fixed << std::setprecision(1) << pct << "}";
        if (i + 1 < sorted_apps.size()) j << ",";
        j << "\n";
    }
    j << "  ],\n";

    // Detected domains
    j << "  \"detected_domains\": [\n";
    for (size_t i = 0; i < domains.size(); i++) {
        j << "    {\"domain\": \"" << jsonEscape(domains[i].first) << "\","
          << " \"app\": \"" << domains[i].second << "\"}";
        if (i + 1 < domains.size()) j << ",";
        j << "\n";
    }
    j << "  ],\n";

    // Top flows
    j << "  \"top_flows\": [\n";
    size_t flow_limit = std::min(flow_list.size(), (size_t)50);
    for (size_t i = 0; i < flow_limit; i++) {
        const Flow& f = flow_list[i];
        j << "    {\"src\": \"" << jsonEscape(f.src_ip) << ":" << f.src_port << "\","
          << " \"dst\": \"" << jsonEscape(f.dst_ip) << ":" << f.dst_port << "\","
          << " \"proto\": \"" << f.protocol << "\","
          << " \"app\": \"" << appTypeToString(f.app_type) << "\","
          << " \"sni\": \"" << jsonEscape(f.sni) << "\","
          << " \"packets\": " << f.packets << ","
          << " \"bytes\": " << f.bytes << ","
          << " \"blocked\": " << (f.blocked ? "true" : "false") << "}";
        if (i + 1 < flow_limit) j << ",";
        j << "\n";
    }
    j << "  ],\n";

    // Packet list
    j << "  \"packets\": [\n";
    for (size_t i = 0; i < packet_list.size(); i++) {
        const auto& p = packet_list[i];
        j << "    {\"num\": " << p.num
          << ", \"time\": \"" << jsonEscape(p.timestamp) << "\""
          << ", \"src\": \"" << jsonEscape(p.src_ip) << ":" << p.src_port << "\""
          << ", \"dst\": \"" << jsonEscape(p.dst_ip) << ":" << p.dst_port << "\""
          << ", \"proto\": \"" << p.protocol << "\""
          << ", \"app\": \"" << p.app << "\""
          << ", \"sni\": \"" << jsonEscape(p.sni) << "\""
          << ", \"size\": " << p.size
          << ", \"blocked\": " << (p.blocked ? "true" : "false")
          << ", \"flags\": \"" << p.flags << "\"}";
        if (i + 1 < packet_list.size()) j << ",";
        j << "\n";
    }
    j << "  ]\n";
    j << "}\n";

    std::cout << j.str();
    return 0;
}
