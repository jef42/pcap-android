#ifndef HELP_IP
#define HELP_IP

#define PACKET_MAX_LENGTH 65536
#define ETHERNET_ADDR_LEN 6
#define IP_ADDR_LEN       4
#define IP_HL(ip) (((ip)->ip_vhl) & 0x0f)

typedef struct {
    unsigned char addr[ETHERNET_ADDR_LEN];
} mac_t;

typedef unsigned int ip_t;
typedef unsigned int mask_t;

typedef struct {
    unsigned char ethernet_dhost[ETHERNET_ADDR_LEN];
    unsigned char ethernet_shost[ETHERNET_ADDR_LEN];
    unsigned short ethernet_type;
} ethernet_frame_t;

typedef struct {
    unsigned short arp_hardware_type;
    unsigned short arp_protocol;
    unsigned char arp_hardware_address_length;
    unsigned char arp_protocol_address_length;
    unsigned short arp_opcode;
    unsigned char arp_src_hardware_address[ETHERNET_ADDR_LEN];
    unsigned char arp_src_ip_address[IP_ADDR_LEN];
    unsigned char arp_dst_hardware_address[ETHERNET_ADDR_LEN];
    unsigned char arp_dst_ip_address[IP_ADDR_LEN];
} arp_frame_t;

typedef struct {
    unsigned char ip_vhl;
    unsigned char ip_tos;
    unsigned short ip_len;
    unsigned short ip_id;
    unsigned short ip_off;
    unsigned char ip_ttl;
    unsigned char ip_p;
    unsigned short ip_sum;
    unsigned char ip_src[IP_ADDR_LEN];
    unsigned char ip_dst[IP_ADDR_LEN];
} ip_frame_t;

typedef struct {
    unsigned char icmp_type;
    unsigned char icmp_code;
    unsigned short icmp_checksum;
    unsigned int icmp_rest_header;
} icmp_frame_t;

typedef struct {
    unsigned short tcp_sport;
    unsigned short tcp_dport;
    unsigned int tcp_seq;
    unsigned int tcp_ack;
    unsigned char tcp_offx2;
    unsigned char tcp_flags;
    unsigned short tcp_win;
    unsigned short tcp_sum;
    unsigned short tcp_urp;
} tcp_frame_t;

typedef struct {
    unsigned short udp_sport;
    unsigned short udp_dport;
    unsigned short udp_length;
    unsigned short udp_checksum;
} udp_frame_t;

char is_valid(const char *net_if);

ip_t decode_ip(const unsigned char *packet);
mac_t decode_mac(const char *mac);

ip_t get_ip_if(const char *net_if);
mac_t get_mac_if(const char *net_if);
unsigned int get_mask_if(const char *net_if);

unsigned short calc_ip_frame_checksum(ip_frame_t *ip);
unsigned short calc_icmp_frame_checksum(ip_frame_t *ip, icmp_frame_t *icmp);
unsigned short calc_tcp_frame_checksum(ip_frame_t *ip, tcp_frame_t *tcp);
unsigned short calc_udp_frame_checksum(ip_frame_t *ip, udp_frame_t *udp);

ip_t get_ip(const char *arg);
mac_t get_mac(const char *arg);

ip_t get_gateway(ip_t ip, mask_t mask);
ip_t get_broadcast(ip_t ip, mask_t mask);
ip_t get_next_ip(ip_t ip, unsigned int i);

#endif
