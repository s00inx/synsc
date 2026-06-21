#pragma once

#define SRC_PORT 5132
#include <stdint.h>

typedef enum {
    PORT_INVAL,
    PORT_SKIP,
    PORT_OPEN,
    PORT_CLOSED,
    PORT_FILTERED,
} pstatus_t;

int recv_packet(int rx_fd, uint32_t target_addr, int myport);
int init_rx(void);
int init_tx(void);
int get_plen();
uint32_t ipchar2raw(char *daddr);
int buildp(char *pbuf, uint32_t daddr, int dport);
int send_packet(int tx_fd, char *pbuf, int packet_len);
