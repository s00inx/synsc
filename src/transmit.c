#define _GNU_SOURCE

#include <sys/socket.h>
#include <stdint.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>

#include "scanner.h"

// calculate Internet Checksum (RFC 1071 accurate)
uint16_t checksum(uint16_t *addr, int ct) {
    uint64_t sum = 0;
    while (ct > 1) {
        sum += *addr++;
        ct -= 2;
    }

    if (ct > 0) {
        sum += *(uint8_t *)addr;
    }

    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    return (uint16_t)~sum; 
}

// get local ip in Network Byte Order
uint32_t get_local_ip(void) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return 0;

    struct sockaddr_in lo;
    memset(&lo, 0, sizeof(lo));
    lo.sin_family = AF_INET;
    lo.sin_addr.s_addr = inet_addr("8.8.8.8"); // google DNS:53
    // lo.sin_addr.s_addr = inet_addr("192.168.100.2");
    lo.sin_port = htons(53);

    if (connect(sock, (struct sockaddr *)&lo, sizeof(lo)) < 0) {
        close(sock);
        return 0;
    }

    struct sockaddr_in local_addr;
    socklen_t addr_len = sizeof(local_addr);
    
    if (getsockname(sock, (struct sockaddr *)&local_addr, &addr_len) < 0) {
        close(sock);
        return 0;
    }

    close(sock);
    return local_addr.sin_addr.s_addr; 
}

// pseudo header for calculating tcp checksum
typedef struct pseudohdr {
    uint32_t saddr;
    uint32_t daddr;
    uint8_t zero;
    uint8_t proto; // 6 for tcp
    uint16_t tcp_length; // tcp header + tcp payload
} __attribute__((packed)) pseudohdr;

// set ip header to ptr on [buf] (0) / -> [daddr]
int set_iphdr(char *hbuf, uint32_t daddr) {
    struct iphdr *iph = (struct iphdr *)hbuf;

    iph->version = 4;
    iph->ihl = 5;
    iph->tos = 0; // default packet
    iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr)); // 20 + 20 = 40 bytes 

    iph->frag_off = htons(IP_DF);
    iph->ttl = 128;
    iph->protocol = 6;
    iph->check = 0;

    iph->saddr = get_local_ip();
    iph->daddr = daddr;

    iph->check = checksum((uint16_t *)iph, sizeof(struct iphdr));
    return 0;
}

// set tcp header to [buf] with ip header to (buf + iphdr) pos
int set_tcphdr(char *hbuf, uint16_t dport) {
    struct iphdr *iph = (struct iphdr *)hbuf;
    struct tcphdr *tcph = (struct tcphdr *)(hbuf + sizeof(struct iphdr));

    tcph->source = htons(SRC_PORT);
    tcph->dest = htons(dport);

    tcph->seq = htonl(167273);
    tcph->ack_seq = 0;
    tcph->doff = 5; // 20 bytes 
    tcph->syn = 1;
    tcph->window = htons((1 << 16) - 1);
    tcph->check = 0;
    tcph->urg_ptr = 0;

    pseudohdr psh = {0};
    psh.saddr = iph->saddr;
    psh.daddr = iph->daddr;
    psh.proto = IPPROTO_TCP;
    psh.tcp_length = htons(sizeof(struct tcphdr));

    char tx_buf[sizeof(pseudohdr) + sizeof(struct tcphdr)];
    memcpy(tx_buf, &psh, sizeof(pseudohdr));
    memcpy(tx_buf + sizeof(pseudohdr), tcph, sizeof(struct tcphdr));

    tcph->check = checksum((uint16_t *)tx_buf, sizeof(tx_buf));
    return 0;
}

// build a syn packet with ip/tcp headers and empty payload to [pbuf]
int buildp(char *pbuf, uint32_t daddr, int dport) {
    if (set_iphdr(pbuf, daddr) < 0) {
        return -1;
    };

    if (set_tcphdr(pbuf, dport) < 0) {
        return -1;
    };

    return 0;
}

// send packet in [pbuf] with length [packet_len] via [tx_fd]
int send_packet(int tx_fd, char *pbuf, int packet_len) {
    struct sockaddr_in dst;
    struct iphdr *iph = (struct iphdr *)pbuf;
    dst.sin_family = AF_INET;
    dst.sin_addr.s_addr = iph->daddr;

    int sent = sendto(tx_fd, pbuf, packet_len, 0, (struct sockaddr *)&dst, sizeof(dst));
    if (sent < 0) {
        perror("packet send failed");
        return -1;
    }

    return 0;
}

int init_tx(void) {
    int tx_fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (tx_fd < 0) {
        perror("can't init transmit socket");
        return -1;
    }

    int optv = 1;
    setsockopt(tx_fd, IPPROTO_IP, IP_HDRINCL, &optv, sizeof(optv));

    return tx_fd;
}

int get_plen(void) {
    return sizeof(struct iphdr) + sizeof(struct tcphdr);
}

// convert ip addr string to uint32_t inet view
uint32_t ipchar2raw(char *daddr) {
    uint32_t raw_daddr;
    if (inet_pton(AF_INET, daddr, &raw_daddr) <= 0) {
        perror("invalid destination ip address");
        return -1;
    }

    return raw_daddr;
}