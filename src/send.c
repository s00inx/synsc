#define _GNU_SOURCE

#include <sys/socket.h>
#include <stdint.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>

#define SPORT 5132

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

// get local ip in (!) Network Byte Order
uint32_t get_local_ip() {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return 0;

    struct sockaddr_in lo;
    memset(&lo, 0, sizeof(lo));
    lo.sin_family = AF_INET;
    lo.sin_addr.s_addr = inet_addr("8.8.8.8"); // google DNS:53
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

    tcph->source = htons(SPORT);
    tcph->dest = htons(dport);

    tcph->seq = htonl(167273);
    tcph->ack_seq = 0;
    tcph->doff = 5; // 20 bytes 
    tcph->syn = 1;
    tcph->window = htons((1 << 16) - 1);
    tcph->check = 0;
    tcph->urg_ptr = 0;

    pseudohdr psh;
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

int send_packet(int tx_fd, char *pbuf, int packet_len) {
    struct sockaddr_in dst;
    struct iphdr *iph = (struct iphdr *)pbuf;
    dst.sin_family = AF_INET;
    dst.sin_addr.s_addr = iph->daddr;

    int sent = sendto(tx_fd, pbuf, packet_len, 0, (struct sockaddr *)&dst, sizeof(dst));
    if (sent < 0) {
        perror("packet send failed");
        return -1;
    } else {
        printf("sent %d bytes\n", sent);
    }

    return 0;
}

typedef enum {
    PORT_OPEN,
    PORT_CLOSED,
    PORT_FILTERED,
} pstatus_t;

int recv_packet(int rx_fd, uint32_t target_addr, int myport) {
    char rx_buf[1 << 16];
    struct sockaddr_in from;
    socklen_t fromlen = sizeof(from);
    
    int recvd = recvfrom(rx_fd, rx_buf, sizeof(rx_buf), 0, (struct sockaddr *)&from, &fromlen);
    if (recvd < 0) {
        perror("no data to recv");
        return -2;
    }

    struct iphdr *iph = (struct iphdr *)rx_buf;
    struct tcphdr *tcph = (struct tcphdr *)(rx_buf + (iph->ihl * 4));

    if (iph->saddr == target_addr && ntohs(tcph->dest) == myport) {
        if (tcph->syn && tcph->ack) {
            return PORT_OPEN;
        }
        if (tcph->rst) {
            return PORT_CLOSED;
        }
    }

    return -2;
}

int main() {
    // transmit socket / -> server 
    int tx_fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    // recv socket / <- server 
    int rx_fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);

    int optv = 1;
    setsockopt(tx_fd, IPPROTO_IP, IP_HDRINCL, &optv, sizeof(optv));

    int pc_len = sizeof(struct iphdr) + sizeof(struct tcphdr);
    char *packet = (char *)calloc(1, pc_len);

    char *daddr = "185.188.181.17"; uint32_t raw_daddr;
    if (inet_pton(AF_INET, daddr, &raw_daddr) <= 0) {
        perror("invalid destination ip address");
        return -1;
    }

    if (buildp(packet, raw_daddr, 80) < 0) {
        perror("can't build packet to transmit");
        return -1;
    }

    send_packet(tx_fd, packet, pc_len);
    while (1) {
        int status = recv_packet(rx_fd, raw_daddr, SPORT);
        
        if (status == PORT_OPEN) {
            printf("Port is OPEN!\n");
            break;
        } else if (status == PORT_CLOSED) {
            printf("Port is CLOSED!\n");
            break;
        }
    }

    free(packet); close(tx_fd); close(rx_fd);

    return 0;
}