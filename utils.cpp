#include "utils.h"

void process_packets(const char* output_filename, std::queue<Packet>& packet_queue,
 std::mutex& locker, std::condition_variable& cv) 
{
    pcap_t* output_pcap;
    pcap_dumper_t* dumper;
    pcap_pkthdr packet;

    output_pcap = pcap_open_dead(DLT_EN10MB, 65536);
    dumper = pcap_dump_open(output_pcap, output_filename);

    while (true)
    {
        std::unique_lock<std::mutex> lock(locker);
        cv.wait(lock,[&packet_queue]()
        {
            return !packet_queue.empty();
        });

        Packet packet = packet_queue.front();
        packet_queue.pop();
        lock.unlock();

        pcap_dump((u_char*)dumper, &packet.header, packet.data.data());

        cv.notify_all();
    }

    pcap_dump_close(dumper);
    pcap_close(output_pcap);
    
}

void packet_manager(const char* input_filename)
{
    pcap_t* handle;
    char errbuf[PCAP_ERRBUF_SIZE];

    handle = pcap_open_offline(input_filename, errbuf);

    if (handle == NULL)
    {
        std::cerr << "Error while reading .pcap file" << errbuf << "\n";
    }

    struct pcap_pkthdr* header;
    const u_char* data;

    while (pcap_next_ex(handle, &header, &data) >= 0)
    {
        Packet packet;

        packet.header = *header;
        packet.data.assign(data, data + header->caplen);
        struct ether_header *eth_header = (struct ether_header *)data;
        
        if (ntohs(eth_header->ether_type) == ETHERTYPE_IP)
        {
            struct ip *ip_header = (struct ip*) (data + sizeof(struct ether_header));
            uint32_t dst_ip = ntohl(ip_header->ip_dst.s_addr);

            if (ip_header->ip_p == IPPROTO_TCP)
            {
                struct tcphdr * tcp_header = (struct tcphdr*) (data + sizeof(struct ether_header) + ip_header->ip_hl * 4);
                uint16_t dst_port = ntohs(tcp_header->th_dport);

                if (dst_ip >= 0x0B000003 && dst_ip <= 0x0B0000C8)
                {
                    std::unique_lock<std::mutex> lock(m1);
                    q1.push(packet);
                    lock.unlock();
                    cv1.notify_all();
                }
                else if (dst_ip >= 0x0C000003 && dst_ip <= 0x0C0000C8 && dst_port == 8080)
                {
                    std::unique_lock<std::mutex> lock(m2);
                    q2.push(packet);
                    lock.unlock();
                    cv2.notify_all();
                } 
                else
                {
                    std::unique_lock<std::mutex> lock(m3);
                    q3.push(packet);
                    lock.unlock();
                    cv3.notify_all();
                }

            }
            else if (ip_header->ip_p == IPPROTO_UDP)
            {
                struct udphdr *udp_header = (struct udphdr*) (data + sizeof(struct ether_header) + ip_header->ip_hl * 4);
                uint16_t dst_port = ntohs(udp_header->uh_dport);

                if (dst_ip >= 0x0B000003 && dst_ip <= 0x0B0000C8)
                {
                    std::unique_lock<std::mutex> lock(m1);
                    q1.push(packet);
                    lock.unlock();
                    cv1.notify_all();
                }
                else if (dst_ip >= 0x0C000003 && dst_ip <= 0x0C0000C8 && dst_port == 8080)
                {
                    std::unique_lock<std::mutex> lock(m2);
                    q2.push(packet);
                    lock.unlock();
                    cv2.notify_all();
                } 
                else
                {
                    std::unique_lock<std::mutex> lock(m3);
                    q3.push(packet);
                    lock.unlock();
                    cv3.notify_all();
                }
            }
        }
        
    }

    pcap_close(handle);
}