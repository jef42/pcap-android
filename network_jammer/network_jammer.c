#include <stdio.h>
#include <getopt.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pcap/pcap.h>
#include <get_num.h>
#include <help_ip.h>

struct option long_option[] = 
    {{"net_interface", required_argument, NULL, 'i'},
     {"src_mac", required_argument, NULL, 's'},
     {"src_ip", required_argument, NULL, 'p'}};

char errbuf[PCAP_ERRBUF_SIZE];

size_t set_buf_icmp(char *buff, mac_t src_mac, ip_t src_ip) {
    ethernet_frame_t ethernet;
    memset(ethernet.ethernet_dhost, 0xFF, ETHERNET_ADDR_LEN);
    memcpy(ethernet.ethernet_shost, &src_mac, ETHERNET_ADDR_LEN);
    ethernet.ethernet_type = htons(0x0800);

    ip_frame_t ip;
    ip.ip_vhl = 0x45;
    ip.ip_tos = 0x0;
    ip.ip_len = htons(0x1c);
    ip.ip_id = htons(0x1000);
    ip.ip_off = htons(0x00);
    ip.ip_ttl = 0x64;
    ip.ip_p = 0x1;
    ip.ip_sum = htons(0x0000);
    ip_t tmp = htonl(src_ip);
    memcpy(ip.ip_src, &tmp, IP_ADDR_LEN);
    memset(ip.ip_dst, 0xFF, IP_ADDR_LEN);
    ip.ip_sum = calc_ip_frame_checksum(&ip);

    icmp_frame_t icmp;
    icmp.icmp_type = 0x08;
    icmp.icmp_code = 0x00;
    icmp.icmp_checksum = htons(0x0);
    icmp.icmp_rest_header = htonl(0x0);
    icmp.icmp_checksum = calc_icmp_frame_checksum(&ip, &icmp);

    memcpy(buff, &ethernet, sizeof(ethernet));
    memcpy(&buff[sizeof(ethernet)], &ip, sizeof(ip));
    memcpy(&buff[sizeof(ethernet) + sizeof(ip)], &icmp, sizeof(icmp));
    return sizeof(ethernet) + sizeof(ip) + sizeof(icmp);
}

int main(int argc, char* argv[]) {
    char buff[PACKET_MAX_LENGTH];
    int c;
    char *net_interface = "wlp3s0";
    mac_t src_mac;
    ip_t src_ip;
    
    while ((c = getopt_long(argc, argv, "i:s:p:h", long_option, NULL)) != -1) {
        switch(c) {
            case -1:
            case 0:
                break;
            case 'i':
                net_interface = optarg;
                src_mac = get_mac_if(net_interface);
                src_ip = get_ip_if(net_interface);
                break;
            case 's':
                src_mac = get_mac(optarg);
                break;
            case 'p':
                src_ip = get_ip(optarg);
                break;
            case 'h':
                printf("Usage %s [OPTIONS]\n", argv[0]);
                printf("    -i net_interface(set before -s and -p)\n");
                printf("    -s src_mac\n");
                printf("    -p src_ip\n");
                printf("    -h help\n");
                return 0;
            case ':':
            case '?':
                fprintf(stderr, "Try %s -h for more information\n", argv[0]);
                return -1;
            default:
                fprintf(stderr, "%s: Invalid option --%c\n", argv[0], c);
                fprintf(stderr, "Try %s -h for more information\n", argv[0]);
                return -1;
        }
    }

    if (!is_valid(net_interface)) {
        fprintf(stderr, "Interface %s doesn't exist\n", net_interface);
        return -1;
    }

    pcap_t *handle = pcap_open_live(net_interface, PACKET_MAX_LENGTH, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open interface %s\n", net_interface);
        return -1;
    }

    for (;;) {
        size_t len = set_buf_icmp(buff, src_mac, src_ip);
        pcap_sendpacket(handle, (const unsigned char*)&buff, len);
        memset(buff, '\0', PACKET_MAX_LENGTH);
    }
}