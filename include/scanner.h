#pragma once

#include <stdint.h>
#include <time.h>

#define SRC_PORT 5132
// count of ports to scan (0 - PORT_COUNT); for test i scan first 100 ports, but default val is 65536
#define PORT_COUNT 65536
// max sliding window size (500 active packets)
#define MAX_WINDOW 50
// timeout for conn
#define TIMEOUT_MS 1000

// enums for port lifecycle (sent -> wait for resp -> done)
typedef enum {
    PORT_SENT,
    PORT_WAIT,
    PORT_DONE
} port_state_t;

// port verdict 
typedef enum {
    PORT_INVAL,
    PORT_SKIP,
    PORT_OPEN,
    PORT_CLOSED,
    PORT_FILTERED,
} port_status_t;

// all metadata about port 
typedef struct port_info_t {
    port_state_t    state;
    port_status_t   verdict;
    struct timespec sent_time;
} port_info_t;


int scan(uint32_t raw_daddr, char* daddr);

int filter_packet(char *rx_buf, int rxbuflen, int rx_fd, uint32_t target_addr, int s_port, uint16_t *resp_port);
int init_rx(void);
int init_tx(void);
int get_plen();
uint32_t ipchar2raw(char *daddr);
int buildp(char *pbuf, uint32_t daddr, int dport);
int send_packet(int tx_fd, char *pbuf, int packet_len);
