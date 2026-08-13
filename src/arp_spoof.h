#pragma once

#include "common.h"

#pragma pack(push, 1)
struct EthArpPacket final {
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

struct Session {
    Ip sender_ip_;
    Ip target_ip_;
    Mac sender_mac_;
    Mac target_mac_;
};

struct ThreadArgs {
    pcap_t* pcap;
    Mac attacker_mac;
    std::vector<Session> sessions;
};

bool get_Address(const char* interface, Mac *mac_out, Ip *ip_out);
Mac get_SenderMac(pcap_t* pcap, Mac attacker_mac, Ip attacker_ip, Ip sender_ip);
void send_arp_infect(pcap_t* pcap, Mac attacker_mac, Mac sender_mac, Ip sender_ip, Ip target_ip);
void* infection_thread_func(void* arg);
void relay_packet(pcap_t* pcap, const u_char* packet, int length, const Session& session, Mac attacker_mac);