#include <stdio.h>
#include <getopt.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pcap/pcap.h>
#include <get_num.h>
#include <help_ip.h>

struct option long_option[] = 
    {{"net_interface", required_argument, NULL, 'i'},
     {"interval", required_argument, NULL, 't'}};

char errbuf[PCAP_ERRBUF_SIZE];

size_t set_buf_arp(char *buf, mac_t src_mac, ip_t src_ip, ip_t dst_ip) {
    ethernet_frame_t ethernet;
    memset(ethernet.ethernet_dhost, 0xFF, ETHERNET_ADDR_LEN);
    memcpy(ethernet.ethernet_shost, src_mac.addr, ETHERNET_ADDR_LEN);
    ethernet.ethernet_type = htons(0x0806);

    arp_frame_t arp;
    arp.arp_hardware_type = htons(0x01);
    arp.arp_protocol = htons(0x0800);
    arp.arp_hardware_address_length = 0x06;
    arp.arp_protocol_address_length = 0x04;
    arp.arp_opcode = htons(0x01);
    memcpy(arp.arp_src_hardware_address, src_mac.addr, ETHERNET_ADDR_LEN);
    ip_t tmp = htonl(src_ip);
    memcpy(arp.arp_src_ip_address, &tmp, IP_ADDR_LEN);
    memset(arp.arp_dst_hardware_address, 0xFF, ETHERNET_ADDR_LEN);
    tmp = htonl(dst_ip);
    memcpy(arp.arp_dst_ip_address, &tmp, IP_ADDR_LEN);

    memcpy(buf, &ethernet, sizeof(ethernet));
    memcpy(&buf[sizeof(ethernet)], &arp, sizeof(arp));
    return 60;
}

int main(int argc, char* argv[]) {
    char buff[PACKET_MAX_LENGTH];
    int c;
    char *net_interface = "wlp3s0";
    mac_t  src_mac;
    ip_t   src_ip;
    mask_t mask = 10;
    int    delay_s = 10;

    while ((c = getopt_long(argc, argv, "i:t:h", long_option, NULL)) != -1) {
        switch (c) {
        case -1:
        case 0:
            break;
        case 'i':
            net_interface = optarg;
            break;
        case 't':
            delay_s = get_int(optarg, GN_NONNEG, "delay");
            break;
        case 'h':
            printf("Usage %s [OPTIONS]\n", argv[0]);
            printf("    -i net_interface\n");
            printf("    -t delay\n");
            printf("    -h help\n");
            return 0;
        case ':':
        case '?':
            fprintf(stderr, "Try %s -h for more information \n", argv[0]);
            return -1;
        default:
            fprintf(stderr, "%s: Invalid option -%c\n", argv[0], c);
            fprintf(stderr, "Try %s -h for more information\n", argv[0]);
            return -1;
        }
    }

    if (!is_valid(net_interface)) {
        fprintf(stderr, "Interface %s doesn't exist\n", net_interface);
        return -1;
    }

    src_ip = get_ip_if(net_interface);
    src_mac = get_mac_if(net_interface);
    mask = get_mask_if(net_interface);

    pcap_t *handle = pcap_open_live(net_interface, PACKET_MAX_LENGTH, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open interface %s\n", net_interface);
        return -1;
    }

    ip_t gateway = get_gateway(src_ip, mask);
    for(;;) {
        for (unsigned int i = 0, dst_ip = get_next_ip(gateway, i);
             dst_ip <= get_broadcast(gateway, mask);
             dst_ip = get_next_ip(gateway, ++i)) {
            size_t len = set_buf_arp(buff, src_mac, src_ip, dst_ip);
            pcap_sendpacket(handle, (const unsigned char*)&buff, len);
            memset(buff, '\0', PACKET_MAX_LENGTH);
        }
        sleep(delay_s);
    }

    return 0;
}
