#include "help_ip.h"
#include <stdlib.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <ifaddrs.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <net/if.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

char is_valid(const char *net_if) {
    struct stat st;
    char tmp[100];
    memset(tmp, '\0', 100);
    memcpy(tmp, "/sys/class/net/", 15);
    memcpy(&tmp[15], net_if, strlen(net_if));
    if (stat(tmp, &st) == -1) {
        fprintf(stderr, "Error: %s\n", strerror(errno));
        return 0;
    }
    if (S_ISDIR(st.st_mode)) {
        return 1;
    }
    return 0;
}

ip_t decode_ip(const unsigned char *packet) {
    ip_t res = 0;
    return 0 | packet[0] << 24 | packet[1] << 16 |
               packet[2] << 8 | packet[3];
}

mac_t decode_mac(const char *mac) {
    mac_t res;
    memcpy(res.addr, mac, ETHERNET_ADDR_LEN);
    return res;
}

static
void parse_bytes(const char *str, char sep, unsigned char *bytes, int maxBytes, int base) {
    for (int i = 0; i < maxBytes; i++) {
        bytes[i] = strtoul(str, NULL, base);
        str = strchr(str, sep);
        if (str == NULL || *str == '\0') {
            break;
        }
        str++;
    }
}

ip_t get_ip_if(const char *net_if) {
    ip_t res = 0;
    struct ifreq ifr;
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    memset(&ifr, '\0', sizeof(struct ifreq));
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, net_if, IFNAMSIZ-1);

    if (ioctl(fd, SIOCGIFADDR, &ifr) != 0) {
        fprintf(stderr, "Error %s\n", strerror(errno));
        return res;
    }

    close(fd);
    res = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr;
    res = ntohl(res);
    return res;
}

mac_t get_mac_if(const char *net_if) {
    mac_t res;
    struct ifreq ifr;
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    memset(&ifr, '\0', sizeof(struct ifreq));
    memset(&res, '\0', sizeof(mac_t));
    ifr.ifr_addr.sa_family = AF_INET;

    strncpy(ifr.ifr_name, net_if, IFNAMSIZ-1);
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) != 0) {
        fprintf(stderr, "Error %s\n", strerror(errno));
        return res;
    }

    close(fd);
    memcpy(res.addr, ifr.ifr_hwaddr.sa_data, ETHERNET_ADDR_LEN);
    return res;
}

unsigned int get_mask_if(const char *net_if) {
    unsigned int res = 0;
    struct ifreq ifr;
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    memset(&ifr, '\0', sizeof(struct ifreq));
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, net_if, IFNAMSIZ-1);

    if (ioctl(fd, SIOCGIFNETMASK, &ifr) != 0) {
        fprintf(stderr, "Error %s\n", strerror(errno));
        return res;
    }

    close(fd);
    unsigned int tmp = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr;
    while (tmp != 0) {
        ++res;
        tmp = tmp >> 1;
    }
    return res;
}

static
unsigned short checksum(void *p, int count) {
    unsigned int sum = 0;
    unsigned short *addr = (unsigned short*)p;

    while (count > 1) {
        sum += *addr++;
        count -= 2;
    }

    if (count > 0)
        sum += *(unsigned char *)addr;

    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);
    return ~sum;
}

typedef struct {
    unsigned char pseudo_src_ip[IP_ADDR_LEN];
    unsigned char pseudo_dst_ip[IP_ADDR_LEN];
    unsigned char pseudo_reserved;
    unsigned char protocol;
    unsigned short pseudo_length;
} pseudo_frame_t;

unsigned short calc_ip_frame_checksum(ip_frame_t *ip) {
    return checksum(&(*ip), sizeof(*ip));
}

unsigned short calc_icmp_frame_checksum(ip_frame_t *ip, icmp_frame_t *icmp) {
    return checksum(&(*icmp), ntohs(ip->ip_len) - (IP_HL(ip) * 4));
}

unsigned short calc_tcp_frame_checksum(ip_frame_t *ip, tcp_frame_t *tcp) {
    pseudo_frame_t pseudo;
    char tmp[1500];
    memset(&pseudo, '\0', sizeof(pseudo));
    memset(tmp, '\0', 1500);

    memcpy(pseudo.pseudo_src_ip, ip->ip_src, IP_ADDR_LEN);
    memcpy(pseudo.pseudo_dst_ip, ip->ip_dst, IP_ADDR_LEN);
    pseudo.pseudo_reserved = 0x0;
    pseudo.protocol = ip->ip_p;
    pseudo.pseudo_length = htons(ntohs(ip->ip_len) - (IP_HL(ip) * 4));

    memcpy(tmp, &pseudo, sizeof(pseudo));
    memcpy(&tmp[sizeof(pseudo)], tcp, sizeof(*tcp));
    return checksum(&tmp, ntohs(ip->ip_len) - (IP_HL(ip) * 4) + sizeof(pseudo));
}

unsigned short calc_udp_frame_checksum(ip_frame_t *ip, udp_frame_t *udp) {
    pseudo_frame_t pseudo;
    char tmp[1500];
    memset(&pseudo, '\0', sizeof(pseudo));
    memset(tmp, '\0', 1500);

    memcpy(pseudo.pseudo_src_ip, ip->ip_src, IP_ADDR_LEN);
    memcpy(pseudo.pseudo_dst_ip, ip->ip_dst, IP_ADDR_LEN);
    pseudo.pseudo_reserved = 0x0;
    pseudo.protocol = ip->ip_p;
    pseudo.pseudo_length = htons(ntohs(ip->ip_len) - (IP_HL(ip) * 4));

    memcpy(tmp, &pseudo, sizeof(pseudo));
    memcpy(&tmp[sizeof(pseudo)], udp, sizeof(*udp));
    return checksum(&tmp, ntohs(udp->udp_length) + sizeof(pseudo));
}

ip_t get_ip(const char *arg) {
    unsigned char tmp[4];
    parse_bytes(arg, '.', tmp, 4, 10);
    return ((int)tmp[0]) << 24 |
            ((int)tmp[1]) << 16 |
            ((int)tmp[2]) << 8  |
            ((int)tmp[3]);
}

mac_t get_mac(const char *arg) {
    mac_t res;
    parse_bytes(arg, '-', res.addr, 6, 16);
    return res;
}

ip_t get_gateway(ip_t ip, mask_t mask) {
    return ip & (~0 << (32 - mask));
}

ip_t get_broadcast(ip_t ip, mask_t mask) {
    return ip | (((unsigned int)~0) >> mask);
}

ip_t get_next_ip(ip_t ip, unsigned int i) {
    return ip + i;
}
