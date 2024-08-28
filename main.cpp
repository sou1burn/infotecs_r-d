#include "utils.h"


int main(int argc, char* argv[])
{
    if (argc != 2)
    {
        std::cerr << "Usage: " << argv[0] << " input pcap file\n";
        return 1;
    }
    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_if_t* alldevs;

    
    if (pcap_findalldevs(&alldevs, error_buffer) == -1)
    {
        std::cerr << "Error while finding device" << error_buffer << "\n";
        return 1;
    }
    std::cout << "Devices found:" << "\n";

    for (pcap_if_t *d = alldevs; d; d= d->next)
    {
        std::cout << d->name << "\n";
    }

    pcap_freealldevs(alldevs);

    std::thread handler1(process_packets_for_handler1, "result_1.pcap", std::ref(q1), std::ref(m1), std::ref(cv1));
    std::thread handler2(process_packets_for_handler2, "result_2.pcap", std::ref(q2), std::ref(m2), std::ref(cv2));
    std::thread handler3(process_packets_for_handler3, "result_3.pcap", std::ref(q3), std::ref(m3), std::ref(cv3));
    
    packet_manager(argv[1]);

    handler1.join();
    handler2.join();
    handler3.join();

    return 0;
}