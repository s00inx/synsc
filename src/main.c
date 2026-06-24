#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "scanner.h"

int main(void) {
    int tx_fd = init_tx(); int rx_fd = init_rx();    
    uint32_t raw_daddr = ipchar2raw((char *)"185.188.181.17");

    run_scan(raw_daddr, rx_fd, tx_fd);
    
    close(tx_fd); close(rx_fd);
    return 0;
}