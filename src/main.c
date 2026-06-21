#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "scanner.h"

int main(void) {
    int tx_fd = init_tx(); int rx_fd = init_rx();    

    int packet_len = get_plen();
    char *packet = (char *)calloc(1, packet_len);

    uint32_t raw_daddr = ipchar2raw((char *)"185.188.181.17");

    if (buildp(packet, raw_daddr, 5132) < 0) {
        perror("can't build packet to transmit");
        return -1;
    }

    send_packet(tx_fd, packet, packet_len);
    while (1) {
        int status = recv_packet(rx_fd, raw_daddr, SRC_PORT);
        
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