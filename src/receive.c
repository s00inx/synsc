#define _GNU_SOURCE

#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#include <stdio.h>

#include "scanner.h"

int init_rx(void) {
    int rx_fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (rx_fd < 0) {
        perror("can't init receive socket");
        return -1;
    }

    return rx_fd;
}

int recv_packet(int rx_fd, uint32_t target_addr, int myport) {
    char rx_buf[1 << 16];
    struct sockaddr_in from;
    socklen_t fromlen = sizeof(from);
    
    int recvd = recvfrom(rx_fd, rx_buf, sizeof(rx_buf), 0, (struct sockaddr *)&from, &fromlen);
    if (recvd < 0) {
        perror("no data to recv");
        return PORT_INVAL;
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

    return PORT_SKIP;
}