#define _GNU_SOURCE

#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>

#include "scanner.h"

// init receiving socket
int init_rx(void) {
    int rx_fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (rx_fd < 0) {
        perror("can't init receive socket");
        return -1;
    }

    int flags = fcntl(rx_fd, F_GETFL, 0);
    if (flags == -1) {
        return -1; 
    }

    if (fcntl(rx_fd, F_SETFL, flags | O_NONBLOCK) == -1) {
        return -1;
    }

    return rx_fd;
}

// make PORT close/open verdict for recvd from [rx_buf] packets
int filter_packet(char *rx_buf, int rxbuflen, int rx_fd, uint32_t target_addr, int s_port, uint16_t *resp_port) {
    int recvd = recv(rx_fd, rx_buf, rxbuflen, 0);
    if (recvd < 0) {
        // eagain and ewouldblock is common behaviour 
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return PORT_SKIP;
        }
        return PORT_INVAL;
    }

    if (recvd < (int)(sizeof(struct iphdr) + sizeof(struct tcphdr))) {
        return PORT_SKIP;
    }

    struct iphdr *iph = (struct iphdr *)rx_buf;

    int iphdrl = iph->ihl * 4;
    struct tcphdr *tcph = (struct tcphdr *)(rx_buf + iphdrl);
    
    if (iph->saddr == target_addr && ntohs(tcph->dest) == s_port) {
        // which port is respont (!!)
        *resp_port = ntohs(tcph->source);
        if (tcph->syn && tcph->ack) {
            return PORT_OPEN;
        }
        if (tcph->rst) {
            return PORT_CLOSED;
        }
    }

    return PORT_SKIP;
}