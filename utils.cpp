#include "utils.h"
#include <time.h>
#include <algorithm>
#include <atomic>

std::queue<Packet> q1, q2, q3;
std::mutex m1, m2, m3;
std::condition_variable cv1, cv2, cv3;
std::atomic<bool> processing_done(false);

void process_packets_for_handler1(const char* output_filename, std::queue<Packet>& packet_queue,
 std::mutex& locker, std::condition_variable& cv) 
{
    pcap_t* output_pcap = pcap_open_dead(DLT_EN10MB, 65536);
    pcap_dumper_t* dumper = pcap_dump_open(output_pcap, output_filename);
    int packet_counter = 0;
    

    while (true)
    {
        std::cout << "\nPacket in process in q1...\n";
        std::cout << "Packet added to queue in thread " << std::this_thread::get_id() << "\n";

        std::unique_lock<std::mutex> lock(locker);
        cv.wait(lock,[&packet_queue]()
        {
            return !packet_queue.empty() || processing_done;
        });

        if (packet_queue.empty() && processing_done)
        {
            break;  
        }

        Packet packet = packet_queue.front();
        packet_queue.pop();
        lock.unlock();

        struct ip* ip_header = (struct ip*) (packet.data.data() + sizeof(struct ether_header));
        struct tcphdr* tcp_header = (struct tcphdr*) (packet.data.data() + sizeof(struct ether_header) + ip_header->ip_hl * 4);
        uint16_t dst_port = ntohs(tcp_header->th_dport);
        
        if (dst_port == 7070)
        {
            std::cout << "Обработчик 1: Пакет под номером "<< packet_counter << "игнорируется\n";
            continue;
        }

        pcap_dump((u_char*)dumper, &packet.header, packet.data.data());
        packet_counter++;
        cv.notify_all();
    }

    pcap_dump_close(dumper);
    pcap_close(output_pcap);
    
}

void process_packets_for_handler2(const char* output_filename, std::queue<Packet>& packet_queue,
 std::mutex& locker, std::condition_variable& cv) 
{
    pcap_t* output_pcap = pcap_open_dead(DLT_EN10MB, 65536);
    pcap_dumper_t* dumper = pcap_dump_open(output_pcap, output_filename);    

    while (true)
    {
        std::cout << "\nPacket in process in q2...\n";
        std::cout << "Packet added to queue in thread " << std::this_thread::get_id() << "\n";

        std::unique_lock<std::mutex> lock(locker);
        cv.wait(lock,[&packet_queue]()
        {
            return !packet_queue.empty() || processing_done;
        });

        if (packet_queue.empty() && processing_done)
        {
            break;  
        }

        Packet packet = packet_queue.front();
        packet_queue.pop();
        lock.unlock();

        struct ip* ip_header = (struct ip*) (packet.data.data() + sizeof(struct ether_header));
        auto l4_data_start = packet.data.begin() + sizeof(struct ether_header) + ip_header->ip_hl * 4;
        auto l4_data_end = packet.data.end();
        
        auto x_pos = std::find(l4_data_start, l4_data_end, 'x');

        if (x_pos != l4_data_end)
        {
            packet.data.erase(x_pos + 1, l4_data_end);
        }

        pcap_dump((u_char*)dumper, &packet.header, packet.data.data());
        cv.notify_all();
    }

    pcap_dump_close(dumper);
    pcap_close(output_pcap);
    
}

void process_packets_for_handler3(const char* output_filename, std::queue<Packet>& packet_queue,
 std::mutex& locker, std::condition_variable& cv) 
{
    pcap_t* output_pcap = pcap_open_dead(DLT_EN10MB, 65536);
    pcap_dumper_t* dumper = pcap_dump_open(output_pcap, output_filename);
    

    while (true)
    {
        std::cout << "\nPacket in process in q3...\n";
        std::cout << "Packet added to queue in thread " << std::this_thread::get_id() << "\n";

        std::unique_lock<std::mutex> lock(locker);
        cv.wait(lock,[&packet_queue]()
        {
            return !packet_queue.empty() || processing_done;
        });

        if (packet_queue.empty() && processing_done)
        {
            break;  
        }

        Packet packet = packet_queue.front();
        packet_queue.pop();
        lock.unlock();

        struct ip* ip_header = (struct ip*) (packet.data.data() + sizeof(struct ether_header));
        
        if (ip_header->ip_p == IPPROTO_TCP)
        {
            std::this_thread::sleep_for(std::chrono::seconds(2));
            time_t curr_time = time(nullptr);

            if (curr_time % 2 == 0)
            {
                pcap_dump((u_char*)dumper, &packet.header, packet.data.data());
            }
        }
        else if (ip_header->ip_p == IPPROTO_UDP)
        {
            struct udphdr *udp_header = (struct udphdr*) (packet.data.data()+ sizeof(struct ether_header) + ip_header->ip_hl * 4);
            uint16_t dst_port = ntohs(udp_header->uh_dport);
            uint16_t src_port = ntohs(udp_header->uh_sport);

            if (src_port == dst_port)
            {
                std:: cout << "Обработчик 3: найдено совпадение port = " << src_port << "\n";
                pcap_dump((u_char*)dumper, &packet.header, packet.data.data());
            }

        }
        cv.notify_all();
    }

    pcap_dump_close(dumper);
    pcap_close(output_pcap);
    
}

void packet_manager(const char* input_filename)
{
    pcap_t* handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    int score = 0;

    handle = pcap_open_offline(input_filename, errbuf);

    if (handle == NULL)
    {
        std::cerr << "Error while reading .pcap file" << errbuf << "\n";
    }

    struct pcap_pkthdr* header;
    const u_char* data;

    while (pcap_next_ex(handle, &header, &data) >= 0)
    {
        score++;
        std::cout << "\nPacket in process...\n";
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
                    cv1.notify_one();
                }
                else if (dst_ip >= 0x0C000003 && dst_ip <= 0x0C0000C8 && dst_port == 8080)
                {
                    std::unique_lock<std::mutex> lock(m2);
                    q2.push(packet);
                    lock.unlock();
                    cv2.notify_one();
                } 
                else
                {
                    std::unique_lock<std::mutex> lock(m3);
                    q3.push(packet);
                    lock.unlock();
                    cv3.notify_one();
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
        std::cout <<"\n Processing end...\n";
        
    }

    processing_done = true;
    cv1.notify_all();
    cv2.notify_all();
    cv3.notify_all();

    std::cout << score << "\n";

    pcap_close(handle);

}