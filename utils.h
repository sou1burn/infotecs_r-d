#ifndef utils_h
#define utils_h

#include <iostream>
#include <exception>
#include <thread>
#include <pcap.h>
#include <mutex>
#include <condition_variable>
#include <queue>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <vector>

struct Packet
{
    pcap_pkthdr header;
    std::vector<u_char> data;
};

extern std::queue<Packet> q1, q2, q3;
extern std::mutex m1, m2, m3;
extern std::condition_variable cv1, cv2, cv3;

void process_packets_for_handler1(const char* output_filename, std::queue<Packet>& packet_queue,
 std::mutex& locker, std::condition_variable& cv);

void process_packets_for_handler2(const char* output_filename, std::queue<Packet>& packet_queue,
 std::mutex& locker, std::condition_variable& cv);

void process_packets_for_handler3(const char* output_filename, std::queue<Packet>& packet_queue,
 std::mutex& locker, std::condition_variable& cv);

void packet_manager(const char* input_filename);



#endif