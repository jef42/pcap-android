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
     {"dst_mac", required_argument, NULL, 'm'},
     {"dst_ip", required_argument, NULL, 'p'},
     {"type", required_argument, NULL, 't'},
     {"interval", required_argument, NULL, 'd'}};

char errbuf[PCAP_ERRBUF_SIZE];

void set_ethernet_ip_frames(ethernet_frame_t *ethernet,
                            ip_frame_t *ip,
                            mac_t src_mac, mac_t dst_mac,
                            ip_t src_ip, ip_t dst_ip,
                            unsigned short length,
                            unsigned char p) {
    memcpy(ethernet->ethernet_dhost, &dst_mac, ETHERNET_ADDR_LEN);
    memcpy(ethernet->ethernet_shost, &src_mac, ETHERNET_ADDR_LEN);
    ethernet->ethernet_type = htons(0x0800);

    ip->ip_vhl = 0x45;
    ip->ip_tos = 0x0;
    ip->ip_len = htons(length);
    ip->ip_id = htons(0x1000);
    ip->ip_off = htons(0x00);
    ip->ip_ttl = 0x64;
    ip->ip_p = p;
    ip->ip_sum = htons(0x0000);
    ip_t tmp = htonl(src_ip);
    memcpy(ip->ip_src, &tmp, IP_ADDR_LEN);
    tmp = htonl(dst_ip);
    memcpy(ip->ip_dst, &tmp, IP_ADDR_LEN);

    ip->ip_sum = calc_ip_frame_checksum(ip);
}

size_t set_buf_tcp(char *buff, mac_t src_mac, mac_t dst_mac, 
                   ip_t src_ip, ip_t dst_ip, unsigned short i) {
    ethernet_frame_t ethernet;
    ip_frame_t ip;
    set_ethernet_ip_frames(&ethernet, &ip, src_mac, dst_mac, src_ip, dst_ip, 0x28, 0x06);

    tcp_frame_t tcp;
    tcp.tcp_sport = htons(0x4923);
    tcp.tcp_dport = htons(i);
    tcp.tcp_seq = htonl(0x3323);
    tcp.tcp_ack = htonl(0x0);
    tcp.tcp_offx2 = 0x50;
    tcp.tcp_flags = 0x02;
    tcp.tcp_win = htons(0x7020);
    tcp.tcp_sum = htons(0x00);
    tcp.tcp_urp = htons(0x00);
    tcp.tcp_sum = calc_tcp_frame_checksum(&ip, &tcp);

    memcpy(buff, &ethernet, sizeof(ethernet));
    memcpy(&buff[sizeof(ethernet)], &ip, sizeof(ip));
    memcpy(&buff[sizeof(ethernet) + sizeof(ip)], &tcp, sizeof(tcp));
    return sizeof(ethernet) + sizeof(ip) + sizeof(tcp);
}

size_t set_buf_udp(char *buff, mac_t src_mac, mac_t dst_mac,
                   ip_t src_ip, ip_t dst_ip, unsigned short i) {
    ethernet_frame_t ethernet;
    ip_frame_t ip;
    set_ethernet_ip_frames(&ethernet, &ip, src_mac, dst_mac, src_ip, dst_ip, 0x1c, 0x11);

    udp_frame_t udp;
    udp.udp_sport = htons(0x4923);
    udp.udp_dport = htons(i);
    udp.udp_length = htons(0x08);
    udp.udp_checksum = htons(0x00);
    udp.udp_checksum = calc_udp_frame_checksum(&ip, &udp);

    memcpy(buff, &ethernet, sizeof(ethernet));
    memcpy(&buff[sizeof(ethernet)], &ip, sizeof(ip));
    memcpy(&buff[sizeof(ethernet) + sizeof(ip)], &udp, sizeof(udp));
    return sizeof(ethernet) + sizeof(ip) + sizeof(udp);
}

int main(int argc, char *argv[]) {
    char buff[PACKET_MAX_LENGTH];
    int c;
    char *net_interface = "wlp3s0";
    mac_t src_mac;
    mac_t dst_mac;
    ip_t  src_ip;
    ip_t  dst_ip;
    int type;
    int delay_s;

    while((c = getopt_long(argc, argv, "i:m:p:t:d:h", long_option, NULL)) != -1) {
        switch(c) {
        case -1:
        case 0:
            break;
        case 'i':
            net_interface = optarg;
            break;
        case 'm':
            memcpy(dst_mac.addr, get_mac(optarg).addr, ETHERNET_ADDR_LEN);
            break;
        case 'p':
            dst_ip = get_ip(optarg);
            break;
        case 't':
            type = get_int(optarg, GN_NONNEG, "type");
            break;
        case 'd':
            delay_s = get_int(optarg, GN_NONNEG, "delay");
            break;
        case 'h':
            printf("Usage %s [OPTIONS]\n", argv[0]);
            printf("    -i net_interface\n");
            printf("    -m dst_mac\n");
            printf("    -p dst_ip\n");
            printf("    -t type (1 tcp, 2 udp)\n");
            printf("    -d delay\n");
            printf("    -h help\n");
            return 0;
        case ':':
        case '?':
            fprintf(stderr, "Try %s -h for more information\n", argv[0]);
            return -1;
        default:
            fprintf(stderr, "%s: Invalid option --%c\n", argv[0], c);
            fprintf(stderr, "Try %s -h for more inforation\n", argv[0]);
            return -1;
        }
    }

    if (!is_valid(net_interface)) {
        fprintf(stderr, "Interface %s doesn't exist\n", net_interface);
        return -1;
    }

    src_ip = get_ip_if(net_interface);
    src_mac = get_mac_if(net_interface);

    pcap_t *handle = pcap_open_live(net_interface, 65536, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open interface %s\n", net_interface);
        return -1;
    }

    for (;;) {
        for (unsigned short i = 1; i != 0; ++i) {
            size_t len = 0;
            if (type == 1) { //TCP
                len = set_buf_tcp(buff, src_mac, dst_mac, src_ip, dst_ip, i);
            } else {
                if (type == 2) { //UDP
                    len = set_buf_udp(buff, src_mac, dst_mac, src_ip, dst_ip, i);
                }
                else {
                    fprintf(stderr, "Wrong type %d try %s -h\n", type, argv[0]);
                    return -1;
                }
            }
            pcap_sendpacket(handle, (const unsigned char*)&buff, len);
            memset(buff, '\0', PACKET_MAX_LENGTH);
        }
        sleep(delay_s);
    }

    return 0;
}
